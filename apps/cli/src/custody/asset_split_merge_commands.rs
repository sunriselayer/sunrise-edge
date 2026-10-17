//! Explicit offline split/merge custody commands (DR-0249); no peer supplies
//! trust pins. Mirrors `asset_commands`'s transfer-only shape, for the
//! separate kind-3 split/merge family. `split` and `merge` share one trust
//! and one wire kind but differ enough in argument shape (amount/recipient
//! versus a second owned input) that each keeps its own explicit command
//! body rather than a shared generic callback.

use super::{
    approvals::{self, ApprovalRecord},
    asset_application_pin::application_pin_selection,
    asset_split_merge::{
        AssetMergeRequest, AssetSplitMergeRequest, AssetSplitMergeTrust, AssetSplitRequest,
    },
    asset_split_merge_wire,
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
use sunrise_edge_client::{ObjectId, PublicationContext, RequestId, VerifiedGenesisRoot};

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
    vec![
        scalar(CONFIG),
        scalar(GENESIS),
        scalar(GENESIS_DIGEST),
        scalar("--asset"),
        scalar("--instance-ref"),
    ]
}

fn load_trust(
    parsed: &ParsedArgs,
    config: &CustodyConfig,
) -> Result<AssetSplitMergeTrust, CliError> {
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
    let application: Option<(ObjectId, Vec<u8>)> = application_pin_selection(parsed)?;
    AssetSplitMergeTrust::new(config.clone(), root, application)
}

fn owned_object(parsed: &ParsedArgs, flag: &'static str) -> Result<Vec<u8>, CliError> {
    Ok(read_private_file(
        Path::new(parsed.require(flag)?),
        0o600,
        0o700,
        sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    )?)
}

fn read_split_request(parsed: &ParsedArgs) -> Result<AssetSplitRequest, CliError> {
    Ok(AssetSplitRequest {
        coin_bytes: owned_object(parsed, "--coin-file")?,
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

fn read_merge_request(parsed: &ParsedArgs) -> Result<AssetMergeRequest, CliError> {
    Ok(AssetMergeRequest {
        into_bytes: owned_object(parsed, "--into-file")?,
        from_bytes: owned_object(parsed, "--from-file")?,
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

fn decode_split_request(parsed: &ParsedArgs) -> Result<AssetSplitRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        asset_split_merge_wire::MAX_REQUEST_BYTES,
    )?;
    match asset_split_merge_wire::decode(&bytes).map_err(CustodyError::Wire)? {
        AssetSplitMergeRequest::Split(split) => Ok(*split),
        AssetSplitMergeRequest::Merge(_) => Err(invalid("expected an exported split request")),
    }
}

fn decode_merge_request(parsed: &ParsedArgs) -> Result<AssetMergeRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        asset_split_merge_wire::MAX_REQUEST_BYTES,
    )?;
    match asset_split_merge_wire::decode(&bytes).map_err(CustodyError::Wire)? {
        AssetSplitMergeRequest::Merge(merge) => Ok(*merge),
        AssetSplitMergeRequest::Split(_) => Err(invalid("expected an exported merge request")),
    }
}

pub(super) fn prepare_split<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for name in [
        "--coin-file",
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
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let request: AssetSplitRequest = read_split_request(&parsed)?;
    let prepared = trust.prepare_split(&request)?;
    print!("{}", prepared.review);
    let bytes: Vec<u8> =
        asset_split_merge_wire::encode(&AssetSplitMergeRequest::Split(Box::new(request)))
            .map_err(CustodyError::Wire)?;
    super::write_review_preimage(output, &bytes)?;
    println!("split_request_exported=true");
    Ok(())
}

pub(super) fn prepare_merge<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for name in [
        "--into-file",
        "--from-file",
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
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let request: AssetMergeRequest = read_merge_request(&parsed)?;
    let prepared = trust.prepare_merge(&request)?;
    print!("{}", prepared.review);
    let bytes: Vec<u8> =
        asset_split_merge_wire::encode(&AssetSplitMergeRequest::Merge(Box::new(request)))
            .map_err(CustodyError::Wire)?;
    super::write_review_preimage(output, &bytes)?;
    println!("merge_request_exported=true");
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

pub(super) fn approve_split<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let request: AssetSplitRequest = decode_split_request(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let prepared = trust.prepare_split(&request)?;
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
    let recipient_is_self: bool = request.recipient == *config.publisher().as_bytes();
    let confirmation: String = format!(
        "APPROVE-SPLIT sender={} held={} amount={} recipient={} recipient_is_self={} fee_balance={} max_fee={} nonce={} request_id={} not_after={not_after}",
        config.publisher(),
        prepared.held,
        request.amount,
        crate::hex::encode_hex(&request.recipient),
        recipient_is_self,
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
        "approved_split=true\nrequest_id={}\nnot_after={not_after}",
        request.request_id
    );
    Ok(())
}

pub(super) fn approve_merge<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let request: AssetMergeRequest = decode_merge_request(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let prepared = trust.prepare_merge(&request)?;
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
        "APPROVE-MERGE sender={} into_amount={} from_amount={} checked_total={} fee_balance={} max_fee={} nonce={} request_id={} not_after={not_after}",
        config.publisher(),
        prepared.into_amount,
        prepared.from_amount,
        prepared.checked_total,
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
        "approved_merge=true\nrequest_id={}\nnot_after={not_after}",
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
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let signer = super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let summary = super::server::run_split_merge(
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
            "sign-split/sign-merge requires the explicitly pinned custody signer",
        ));
    };
    Ok((socket, custody_uid, expected_public_key))
}

pub(super) fn sign_split<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([scalar(REQUEST), scalar(OUT)]);
    specs.extend(crate::signer::signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let (socket, custody_uid, expected_public_key) = custody_signer(&parsed)?;
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(invalid("split sender differs from pinned custody key"));
    }
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let request: AssetSplitRequest = decode_split_request(&parsed)?;
    let prepared = trust.prepare_split(&request)?;
    let target = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let frame: Vec<u8> =
        asset_split_merge_wire::encode(&AssetSplitMergeRequest::Split(Box::new(request.clone())))
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
        "signed_split_exported=true\nrequest_id={}",
        request.request_id
    );
    Ok(())
}

pub(super) fn sign_merge<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([scalar(REQUEST), scalar(OUT)]);
    specs.extend(crate::signer::signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let (socket, custody_uid, expected_public_key) = custody_signer(&parsed)?;
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(invalid("merge sender differs from pinned custody key"));
    }
    let trust: AssetSplitMergeTrust = load_trust(&parsed, &config)?;
    let request: AssetMergeRequest = decode_merge_request(&parsed)?;
    let prepared = trust.prepare_merge(&request)?;
    let target = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let frame: Vec<u8> =
        asset_split_merge_wire::encode(&AssetSplitMergeRequest::Merge(Box::new(request.clone())))
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
        "signed_merge_exported=true\nrequest_id={}",
        request.request_id
    );
    Ok(())
}

#[cfg(test)]
mod application_pin_flag_tests {
    use super::super::fsperm::test_support::{TempDir, write_mode_file};
    use super::*;

    #[test]
    fn role_specs_load_the_bounded_local_application_pin() {
        let directory: TempDir = TempDir::new(0o700);
        let pin_path = directory.child("application-instance");
        let pin_bytes: Vec<u8> = vec![1, 2, 3];
        write_mode_file(&pin_path, 0o600, &pin_bytes);
        let asset: String = "aa".repeat(32);
        let parsed: ParsedArgs = parse_flags(
            [
                "--asset",
                &asset,
                "--instance-ref",
                pin_path.to_str().unwrap(),
            ]
            .into_iter()
            .map(OsString::from),
            &trust_specs(),
        )
        .unwrap();
        assert_eq!(
            application_pin_selection(&parsed).unwrap(),
            Some((ObjectId::new([0xaa; 32]), pin_bytes)),
        );
    }

    #[test]
    fn role_specs_without_a_pin_preserve_genesis_selection() {
        let parsed: ParsedArgs = parse_flags(Vec::<OsString>::new(), &trust_specs()).unwrap();
        assert_eq!(application_pin_selection(&parsed).unwrap(), None);
    }
}
