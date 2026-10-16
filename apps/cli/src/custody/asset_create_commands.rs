//! Explicit offline create-asset custody commands (DR-0255); no peer
//! supplies trust pins. Mirrors `asset_mint_burn_commands`'s shape for the
//! separate kind-5 create-asset family.

use super::{
    approvals::{self, ApprovalRecord},
    asset_create::{AssetCreateRequest, AssetCreateTrust},
    asset_create_wire,
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

fn load_trust(parsed: &ParsedArgs, config: &CustodyConfig) -> Result<AssetCreateTrust, CliError> {
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
    AssetCreateTrust::new(config.clone(), root)
}

fn owned_object(parsed: &ParsedArgs, flag: &'static str) -> Result<Vec<u8>, CliError> {
    Ok(read_private_file(
        Path::new(parsed.require(flag)?),
        0o600,
        0o700,
        sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    )?)
}

fn read_create_request(parsed: &ParsedArgs) -> Result<AssetCreateRequest, CliError> {
    Ok(AssetCreateRequest {
        seed: decode_hex_32("--seed", parsed.require("--seed")?)?,
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

fn decode_create_request(parsed: &ParsedArgs) -> Result<AssetCreateRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        asset_create_wire::MAX_REQUEST_BYTES,
    )?;
    Ok(asset_create_wire::decode(&bytes).map_err(CustodyError::Wire)?)
}

pub(super) fn prepare_create<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for name in [
        "--seed",
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
    let trust: AssetCreateTrust = load_trust(&parsed, &config)?;
    let request: AssetCreateRequest = read_create_request(&parsed)?;
    let prepared = trust.prepare_create(&request)?;
    print!("{}", prepared.review);
    let bytes: Vec<u8> = asset_create_wire::encode(&request).map_err(CustodyError::Wire)?;
    super::write_review_preimage(output, &bytes)?;
    println!("create_request_exported=true");
    Ok(())
}

pub(super) fn approve_create<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetCreateTrust = load_trust(&parsed, &config)?;
    let request: AssetCreateRequest = decode_create_request(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let prepared = trust.prepare_create(&request)?;
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
        "APPROVE-CREATE sender={} seed={} new_instance_creator={} new_instance_seed={} new_instance_revision={} new_instance_record_digest={} fee_balance={} max_fee={} nonce={} request_id={} not_after={not_after}",
        config.publisher(),
        crate::hex::encode_hex(&request.seed),
        crate::hex::encode_hex(&prepared.new_instance.creator),
        crate::hex::encode_hex(&prepared.new_instance.seed),
        prepared.new_instance.revision,
        prepared.new_instance.record_digest,
        prepared.fee_balance,
        request.max_fee,
        request.nonce,
        request.request_id,
    );
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    print!("{}", prepared.review);
    println!("Type exactly to approve:\n{confirmation}");
    if super::approve::read_bounded_confirmation_line(1024)? != confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }
    let record = ApprovalRecord {
        publisher: config.publisher(),
        not_after_unix_seconds: not_after,
        frame: prepared.prepared.signable_frame().to_vec(),
    };
    approvals::write_approval(approvals, &request.request_id, &record)?;
    println!(
        "approved_create=true\nrequest_id={}\nnot_after={not_after}",
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
    let trust: AssetCreateTrust = load_trust(&parsed, &config)?;
    let signer = super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let summary = super::server::run_create(
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
            "sign-create requires the explicitly pinned custody signer",
        ));
    };
    Ok((socket, custody_uid, expected_public_key))
}

pub(super) fn sign_create<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([scalar(REQUEST), scalar(OUT)]);
    specs.extend(crate::signer::signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let (socket, custody_uid, expected_public_key) = custody_signer(&parsed)?;
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(invalid("create sender differs from pinned custody key"));
    }
    let trust: AssetCreateTrust = load_trust(&parsed, &config)?;
    let request: AssetCreateRequest = decode_create_request(&parsed)?;
    let prepared = trust.prepare_create(&request)?;
    let target = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let frame: Vec<u8> = asset_create_wire::encode(&request).map_err(CustodyError::Wire)?;
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
        "signed_create_exported=true\nrequest_id={}",
        request.request_id
    );
    Ok(())
}
