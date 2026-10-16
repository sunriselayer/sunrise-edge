//! Explicit offline mint/burn custody commands (DR-0253); no peer supplies
//! trust pins. Mirrors `asset_split_merge_commands`'s shape for the
//! separate kind-4 mint/burn family. `mint` and `burn` share one trust and
//! one wire kind but differ enough in argument shape (amount/recipient
//! versus a second owned consumed coin) that each keeps its own explicit
//! command body rather than a shared generic callback.

use super::{
    approvals::{self, ApprovalRecord},
    asset_mint_burn::{
        AssetBurnRequest, AssetMintBurnRequest, AssetMintBurnTrust, AssetMintRequest,
    },
    asset_mint_burn_wire,
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
use sunrise_edge_client::{PublicationContext, RequestId, VerifiedGenesisRoot};

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

fn load_trust(parsed: &ParsedArgs, config: &CustodyConfig) -> Result<AssetMintBurnTrust, CliError> {
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
    AssetMintBurnTrust::new(config.clone(), root)
}

fn owned_object(parsed: &ParsedArgs, flag: &'static str) -> Result<Vec<u8>, CliError> {
    Ok(read_private_file(
        Path::new(parsed.require(flag)?),
        0o600,
        0o700,
        sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    )?)
}

fn read_mint_request(parsed: &ParsedArgs) -> Result<AssetMintRequest, CliError> {
    Ok(AssetMintRequest {
        cap_bytes: owned_object(parsed, "--cap-file")?,
        fee_bytes: owned_object(parsed, "--fee-source-file")?,
        amount: parse_u64("--amount", parsed.require("--amount")?)?,
        recipient: decode_hex_32("--recipient", parsed.require("--recipient")?)?,
        nonce: parse_u64("--nonce", parsed.require("--nonce")?)?,
        request_id: RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)?,
        max_fee: parse_u64("--max-fee", parsed.require("--max-fee")?)?,
        gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
    })
}

fn read_burn_request(parsed: &ParsedArgs) -> Result<AssetBurnRequest, CliError> {
    Ok(AssetBurnRequest {
        cap_bytes: owned_object(parsed, "--cap-file")?,
        coin_bytes: owned_object(parsed, "--coin-file")?,
        fee_bytes: owned_object(parsed, "--fee-source-file")?,
        nonce: parse_u64("--nonce", parsed.require("--nonce")?)?,
        request_id: RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)?,
        max_fee: parse_u64("--max-fee", parsed.require("--max-fee")?)?,
        gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
    })
}

fn decode_mint_request(parsed: &ParsedArgs) -> Result<AssetMintRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        asset_mint_burn_wire::MAX_REQUEST_BYTES,
    )?;
    match asset_mint_burn_wire::decode(&bytes).map_err(CustodyError::Wire)? {
        AssetMintBurnRequest::Mint(mint) => Ok(*mint),
        AssetMintBurnRequest::Burn(_) => Err(invalid("expected an exported mint request")),
    }
}

fn decode_burn_request(parsed: &ParsedArgs) -> Result<AssetBurnRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        asset_mint_burn_wire::MAX_REQUEST_BYTES,
    )?;
    match asset_mint_burn_wire::decode(&bytes).map_err(CustodyError::Wire)? {
        AssetMintBurnRequest::Burn(burn) => Ok(*burn),
        AssetMintBurnRequest::Mint(_) => Err(invalid("expected an exported burn request")),
    }
}

pub(super) fn prepare_mint<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for name in [
        "--cap-file",
        "--fee-source-file",
        "--amount",
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
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let request: AssetMintRequest = read_mint_request(&parsed)?;
    let prepared = trust.prepare_mint(&request)?;
    print!("{}", prepared.review);
    let bytes: Vec<u8> =
        asset_mint_burn_wire::encode(&AssetMintBurnRequest::Mint(Box::new(request)))
            .map_err(CustodyError::Wire)?;
    super::write_review_preimage(output, &bytes)?;
    println!("mint_request_exported=true");
    Ok(())
}

pub(super) fn prepare_burn<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for name in [
        "--cap-file",
        "--coin-file",
        "--fee-source-file",
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
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let request: AssetBurnRequest = read_burn_request(&parsed)?;
    let prepared = trust.prepare_burn(&request)?;
    print!("{}", prepared.review);
    let bytes: Vec<u8> =
        asset_mint_burn_wire::encode(&AssetMintBurnRequest::Burn(Box::new(request)))
            .map_err(CustodyError::Wire)?;
    super::write_review_preimage(output, &bytes)?;
    println!("burn_request_exported=true");
    Ok(())
}

fn approve_prepared(
    config: &CustodyConfig,
    approvals_dir: &Path,
    request_id: RequestId,
    review: &str,
    confirmation: &str,
    frame: &[u8],
    not_after: u64,
) -> Result<(), CliError> {
    if super::revoke::is_revoked(approvals_dir, &request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    print!("{review}");
    println!("Type exactly to approve:\n{confirmation}");
    if super::approve::read_bounded_confirmation_line(1024)? != confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }
    let record = ApprovalRecord {
        publisher: config.publisher(),
        not_after_unix_seconds: not_after,
        frame: frame.to_vec(),
    };
    approvals::write_approval(approvals_dir, &request_id, &record)?;
    Ok(())
}

pub(super) fn approve_mint<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let request: AssetMintRequest = decode_mint_request(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let prepared = trust.prepare_mint(&request)?;
    let expires: u64 = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    // Computed exactly once: this is the one `not_after` value both the
    // typed confirmation line and the written `ApprovalRecord` use.
    let not_after: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs()
        .checked_add(expires)
        .ok_or(CustodyError::ExpiryOverflow)?;
    let confirmation: String = format!(
        "APPROVE-MINT sender={} supply_before={} amount={} supply_after={} recipient={} fee_balance={} max_fee={} nonce={} request_id={} not_after={not_after}",
        config.publisher(),
        prepared.supply_before,
        request.amount,
        prepared.supply_after,
        crate::hex::encode_hex(&request.recipient),
        prepared.fee_balance,
        request.max_fee,
        request.nonce,
        request.request_id,
    );
    approve_prepared(
        &config,
        approvals,
        request.request_id,
        &prepared.review,
        &confirmation,
        prepared.prepared.signable_frame(),
        not_after,
    )?;
    println!(
        "approved_mint=true\nrequest_id={}\nnot_after={not_after}",
        request.request_id
    );
    Ok(())
}

pub(super) fn approve_burn<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let request: AssetBurnRequest = decode_burn_request(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let prepared = trust.prepare_burn(&request)?;
    let expires: u64 = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    // Computed exactly once: this is the one `not_after` value both the
    // typed confirmation line and the written `ApprovalRecord` use.
    let not_after: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs()
        .checked_add(expires)
        .ok_or(CustodyError::ExpiryOverflow)?;
    let confirmation: String = format!(
        "APPROVE-BURN sender={} supply_before={} burn_amount={} supply_after={} fee_balance={} max_fee={} nonce={} request_id={} not_after={not_after}",
        config.publisher(),
        prepared.supply_before,
        prepared.burn_amount,
        prepared.supply_after,
        prepared.fee_balance,
        request.max_fee,
        request.nonce,
        request.request_id,
    );
    approve_prepared(
        &config,
        approvals,
        request.request_id,
        &prepared.review,
        &confirmation,
        prepared.prepared.signable_frame(),
        not_after,
    )?;
    println!(
        "approved_burn=true\nrequest_id={}\nnot_after={not_after}",
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
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let signer = super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let summary = super::server::run_mint_burn(
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

fn custody_signer(parsed: &ParsedArgs) -> Result<(String, u32, [u8; 32]), CliError> {
    let crate::signer::SignerSelection::Custody {
        socket,
        custody_uid,
        expected_public_key,
    } = crate::signer::parse_signer_selection(parsed)?
    else {
        return Err(invalid(
            "sign-mint/sign-burn requires the explicitly pinned custody signer",
        ));
    };
    Ok((socket, custody_uid, expected_public_key))
}

pub(super) fn sign_mint<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([scalar(REQUEST), scalar(OUT)]);
    specs.extend(crate::signer::signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let (socket, custody_uid, expected_public_key) = custody_signer(&parsed)?;
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(invalid("mint sender differs from pinned custody key"));
    }
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let request: AssetMintRequest = decode_mint_request(&parsed)?;
    let prepared = trust.prepare_mint(&request)?;
    let target = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let frame: Vec<u8> =
        asset_mint_burn_wire::encode(&AssetMintBurnRequest::Mint(Box::new(request.clone())))
            .map_err(CustodyError::Wire)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(CustodyError::Runtime)?;
    let signature: [u8; 64] =
        runtime.block_on(super::client::request_signature_async(&target, &frame))?;
    let signed = prepared.prepared.finalize(signature.to_vec())?;
    let bytes: Vec<u8> = sunrise_edge_client::encode_signed_paid_intent(&signed).map_err(fail)?;
    super::write_review_preimage(output, &bytes)?;
    println!(
        "signed_mint_exported=true\nrequest_id={}",
        request.request_id
    );
    Ok(())
}

pub(super) fn sign_burn<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([scalar(REQUEST), scalar(OUT)]);
    specs.extend(crate::signer::signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let (socket, custody_uid, expected_public_key) = custody_signer(&parsed)?;
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(invalid("burn sender differs from pinned custody key"));
    }
    let trust: AssetMintBurnTrust = load_trust(&parsed, &config)?;
    let request: AssetBurnRequest = decode_burn_request(&parsed)?;
    let prepared = trust.prepare_burn(&request)?;
    let target = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let frame: Vec<u8> =
        asset_mint_burn_wire::encode(&AssetMintBurnRequest::Burn(Box::new(request.clone())))
            .map_err(CustodyError::Wire)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(CustodyError::Runtime)?;
    let signature: [u8; 64] =
        runtime.block_on(super::client::request_signature_async(&target, &frame))?;
    let signed = prepared.prepared.finalize(signature.to_vec())?;
    let bytes: Vec<u8> = sunrise_edge_client::encode_signed_paid_intent(&signed).map_err(fail)?;
    super::write_review_preimage(output, &bytes)?;
    println!(
        "signed_burn_exported=true\nrequest_id={}",
        request.request_id
    );
    Ok(())
}
