//! `transfer`: the devnet Standard Asset v1 whole-coin transfer command.
//!
//! This command is the only place in `apps/cli` that knows anything about
//! the devnet's preinstalled Standard Asset v1 transfer module: its fixed
//! `transfer` entrypoint name and its use of
//! `standard_assets::StandardAssetTransferArgsV1` as the sole argument
//! frame. `clients/rust` stays application-agnostic (see
//! `docs/architecture/product-surfaces.md` §44); this file only uses the
//! small, generic canonical-struct, access-manifest, and Standard Asset v1
//! surface `clients/rust` re-exports.
//!
//! It queries authoritative context first and, before any nonce/object
//! query or signing, requires the trusted `/v1/context` result to exactly
//! match a locally configured [`sunrise_edge_client::ExpectedProtocolContext`]
//! (DR-0085 / `TODO.md` CLI-First Node Production Gate S1a). This is a
//! mandatory pre-signing check, independent of transport trust: a successful
//! connection never by itself proves the remote server speaks this client's
//! intended chain/protocol.
//!
//! Once the context is verified, this command queries the signer's next
//! nonce (checking its epoch agrees with the verified context's before
//! proceeding) and both current-inline coin references, decoding each as a
//! `standard_assets::StandardAssetCoinV1`. Both coins must be owned by the
//! local signer's own address, must share one `AssetId`, must be distinct
//! objects, and the signed `--fee-asset-id` must equal that shared
//! `AssetId` (the protocol forces the fee asset to equal the transferred
//! asset for this entrypoint — see DR-0107, F5). These are defense-in-depth
//! checks alongside the server's committed typed-entrypoint and owner-
//! transition policy. It then builds the transferred/fee/treasury `Write`
//! accesses, builds and signs the transaction through `clients/rust`, and
//! submits it with an explicit non-zero request id. Waiting for a receipt
//! is optional and, when requested, bounded by caller-supplied, finite poll
//! parameters.
//!
//! There is no `--amount` or destination-account concept: this is a
//! whole-object transfer of `--source-coin` to `--recipient`, never a
//! partial balance movement (`split`/`merge` are separate commands; mint and
//! arbitrary Create remain deferred).

use std::ffi::OsString;
use std::num::NonZeroU32;
use std::time::Duration;

use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Amount, AssetId, AtomicityDomainId, ChainId,
    Client, Digest32, ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExecutionEffects,
    ExecutionStatus, ExpectedProtocolContext, FeePayment, HashAlgorithmId, HashSuiteId,
    LocalSigner, NodeResponseStatus, ObjectEffect, ObjectId, ObjectRef, Owner, PreparedTransaction,
    ProtocolVersion, ReceiptPollBounds, RequestId, SignatureSchemeId, StandardAssetCoinV1,
    StandardAssetTransferArgsV1, SubmitTransactionRequest, TransactionRequest, Transport,
    decode_object, decode_standard_asset_coin_v1, encode_standard_asset_transfer_args_v1,
};

use crate::args::{ParsedArgs, parse_flags, scalar, switch};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::net::{connect, tls_flag_specs};
use crate::output::{bounded_hex_field, sanitize_line};
use crate::parse::{parse_u16, parse_u32, parse_u64};
use crate::seed::load_dev_seed;
use crate::signer::{SignerSelection, parse_signer_selection, signer_flag_specs};

const ENDPOINT: &str = "--endpoint";
const MODULE_ID: &str = "--module-id";
const MODULE_VERSION: &str = "--module-version";
const MODULE_DIGEST_ALGORITHM: &str = "--module-digest-algorithm";
const MODULE_DIGEST: &str = "--module-digest";
const SOURCE_COIN: &str = "--source-coin";
const RECIPIENT: &str = "--recipient";
const FEE_COIN: &str = "--fee-coin";
const GAS_LIMIT: &str = "--gas-limit";
const FEE_ASSET_ID: &str = "--fee-asset-id";
const MAX_FEE: &str = "--max-fee";
const FEE_TREASURY_OBJECT: &str = "--fee-treasury-object";
const REQUEST_ID: &str = "--request-id";
const EXPECTED_CHAIN_ID: &str = "--expected-chain-id";
const EXPECTED_PROTOCOL_VERSION: &str = "--expected-protocol-version";
const EXPECTED_EPOCH: &str = "--expected-epoch";
const EXPECTED_HASH_SUITE_ID: &str = "--expected-hash-suite-id";
const EXPECTED_DOMAIN: &str = "--expected-domain";
const WAIT: &str = "--wait";
const WAIT_MAX_ATTEMPTS: &str = "--wait-max-attempts";
const WAIT_INITIAL_BACKOFF_MS: &str = "--wait-initial-backoff-ms";
const WAIT_MAX_BACKOFF_MS: &str = "--wait-max-backoff-ms";
const WAIT_MAX_ELAPSED_MS: &str = "--wait-max-elapsed-ms";

/// The devnet Standard Asset v1 module's `transfer` entrypoint name.
const TRANSFER_ENTRYPOINT: &str = "transfer";

/// Fully parsed, strongly typed `transfer` inputs.
struct TransferInputs {
    module_ref: ObjectRef,
    source_coin_id: ObjectId,
    fee_coin_id: ObjectId,
    recipient: Address,
    fee_asset_id: AssetId,
    max_fee: Amount,
    fee_treasury_object_id: ObjectId,
    gas_limit: u64,
    request_id: RequestId,
    expected_context: ExpectedProtocolContext,
    wait_bounds: Option<ReceiptPollBounds>,
}

/// Runs the `transfer` subcommand.
///
/// Signer selection ([`crate::signer::parse_signer_selection`]) happens before
/// this function constructs a network [`Client`]. The live Standard Asset v1
/// transfer has no Ledger clear-signing policy yet, so a Ledger selection is
/// rejected locally before any device or network dispatch.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = transfer_flag_specs();
    specs.extend(tls_flag_specs());
    specs.extend(signer_flag_specs());
    let parsed = parse_flags(args, &specs)?;

    let endpoint = parsed.require(ENDPOINT)?;
    let inputs = parse_inputs(&parsed)?;

    match parse_signer_selection(&parsed)? {
        SignerSelection::Local { seed_file } => {
            let seed = load_dev_seed(std::path::Path::new(&seed_file))?;
            let signer = LocalSigner::from_seed(seed);
            let sender = signer.address();
            let client = connect(endpoint, &parsed)?;
            execute(&client, sender, inputs, |prepared| {
                prepared
                    .sign_and_finalize_with(&signer)
                    .map_err(CliError::from)
            })
        }
        SignerSelection::Ledger {
            hid_path: _,
            account: _,
            expected_firmware_version: _,
        } => Err(CliError::LedgerStandardAssetTransferUnsupported),
    }
}

fn transfer_flag_specs() -> Vec<crate::args::FlagSpec> {
    vec![
        scalar(ENDPOINT),
        scalar(MODULE_ID),
        scalar(MODULE_VERSION),
        scalar(MODULE_DIGEST_ALGORITHM),
        scalar(MODULE_DIGEST),
        scalar(SOURCE_COIN),
        scalar(RECIPIENT),
        scalar(FEE_COIN),
        scalar(GAS_LIMIT),
        scalar(FEE_ASSET_ID),
        scalar(MAX_FEE),
        scalar(FEE_TREASURY_OBJECT),
        scalar(REQUEST_ID),
        scalar(EXPECTED_CHAIN_ID),
        scalar(EXPECTED_PROTOCOL_VERSION),
        scalar(EXPECTED_EPOCH),
        scalar(EXPECTED_HASH_SUITE_ID),
        scalar(EXPECTED_DOMAIN),
        switch(WAIT),
        scalar(WAIT_MAX_ATTEMPTS),
        scalar(WAIT_INITIAL_BACKOFF_MS),
        scalar(WAIT_MAX_BACKOFF_MS),
        scalar(WAIT_MAX_ELAPSED_MS),
    ]
}

fn parse_inputs(parsed: &ParsedArgs) -> Result<TransferInputs, CliError> {
    let module_ref = parse_module_ref(parsed)?;
    let source_coin_id = ObjectId::new(decode_hex_32(SOURCE_COIN, parsed.require(SOURCE_COIN)?)?);
    let fee_coin_id = ObjectId::new(decode_hex_32(FEE_COIN, parsed.require(FEE_COIN)?)?);
    if source_coin_id == fee_coin_id {
        return Err(CliError::SameSourceCoinAndFeeCoin);
    }
    let recipient = Address::new(decode_hex_32(RECIPIENT, parsed.require(RECIPIENT)?)?);
    let fee_asset_id = AssetId::new(decode_hex_32(FEE_ASSET_ID, parsed.require(FEE_ASSET_ID)?)?);
    let max_fee = parse_u64(MAX_FEE, parsed.require(MAX_FEE)?)?;
    if max_fee == 0 {
        return Err(CliError::ZeroMaxFee);
    }
    let fee_treasury_object_id = ObjectId::new(decode_hex_32(
        FEE_TREASURY_OBJECT,
        parsed.require(FEE_TREASURY_OBJECT)?,
    )?);
    if fee_treasury_object_id == source_coin_id || fee_treasury_object_id == fee_coin_id {
        return Err(CliError::FeeTreasuryConflictsWithTransfer);
    }
    let gas_limit = parse_u64(GAS_LIMIT, parsed.require(GAS_LIMIT)?)?;
    if gas_limit == 0 {
        return Err(CliError::ZeroGasLimit);
    }
    let request_id = RequestId::new(decode_hex_32(REQUEST_ID, parsed.require(REQUEST_ID)?)?)?;
    let expected_context = parse_expected_context(parsed)?;
    let wait_bounds = parse_wait_bounds(parsed)?;

    Ok(TransferInputs {
        module_ref,
        source_coin_id,
        fee_coin_id,
        recipient,
        fee_asset_id,
        max_fee: Amount::new(max_fee),
        fee_treasury_object_id,
        gas_limit,
        request_id,
        expected_context,
        wait_bounds,
    })
}

/// Parses the required `--expected-*` flags into a locally trusted
/// [`ExpectedProtocolContext`] (DR-0085), rejecting a missing, zero, or
/// malformed value before any network dispatch. The transaction-auth
/// profile id, signature scheme, and address binding expectations come
/// from this client's own implemented constants, not from a flag — there is
/// only one implemented combination — but they are still compared against
/// the remote result by [`ExpectedProtocolContext::verify`].
pub(crate) fn parse_expected_context(
    parsed: &ParsedArgs,
) -> Result<ExpectedProtocolContext, CliError> {
    let chain_id = ChainId::new(parsed.require(EXPECTED_CHAIN_ID)?)?;
    let protocol_version = ProtocolVersion::new(parse_u32(
        EXPECTED_PROTOCOL_VERSION,
        parsed.require(EXPECTED_PROTOCOL_VERSION)?,
    )?);
    let epoch = Epoch::new(parse_u64(EXPECTED_EPOCH, parsed.require(EXPECTED_EPOCH)?)?);
    let hash_suite_id = HashSuiteId::new(parse_u16(
        EXPECTED_HASH_SUITE_ID,
        parsed.require(EXPECTED_HASH_SUITE_ID)?,
    )?);
    let domain_bytes = decode_hex_32(EXPECTED_DOMAIN, parsed.require(EXPECTED_DOMAIN)?)?;
    let domain = AtomicityDomainId::new(domain_bytes)?;

    Ok(ExpectedProtocolContext::new(
        chain_id,
        protocol_version,
        epoch,
        hash_suite_id,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        domain,
    )?)
}

fn execute<T, F>(
    client: &Client<T>,
    sender: Address,
    inputs: TransferInputs,
    sign: F,
) -> Result<(), CliError>
where
    T: Transport,
    F: FnOnce(PreparedTransaction) -> Result<Vec<u8>, CliError>,
{
    let context = client.query_verified_context(&inputs.expected_context)?;

    let nonce_result = client.query_next_nonce(sender)?;
    if nonce_result.epoch() != context.epoch() {
        return Err(CliError::EpochMismatch {
            context_epoch: context.epoch().get(),
            nonce_epoch: nonce_result.epoch().get(),
        });
    }

    let (source_ref, source_coin) =
        require_owned_current_coin(client, SOURCE_COIN, inputs.source_coin_id, sender)?;
    let (fee_ref, fee_coin) =
        require_owned_current_coin(client, FEE_COIN, inputs.fee_coin_id, sender)?;
    if source_coin.asset_id() != fee_coin.asset_id() {
        return Err(CliError::CoinAssetMismatch);
    }
    if inputs.fee_asset_id != source_coin.asset_id() {
        return Err(CliError::FeeAssetMismatch);
    }
    let treasury_ref =
        require_current_inline(client, FEE_TREASURY_OBJECT, inputs.fee_treasury_object_id)?;

    let mut access_manifest = AccessManifest::new();
    access_manifest.push(AccessEntry {
        object_ref: source_ref,
        mode: AccessMode::Write,
    });
    access_manifest.push(AccessEntry {
        object_ref: fee_ref.clone(),
        mode: AccessMode::Write,
    });
    access_manifest.push(AccessEntry {
        object_ref: treasury_ref,
        mode: AccessMode::Write,
    });

    let fee_payment = FeePayment {
        asset_id: inputs.fee_asset_id,
        max_fee: inputs.max_fee,
        fee_object: fee_ref,
    };

    let args = encode_standard_asset_transfer_args_v1(&StandardAssetTransferArgsV1::new(
        inputs.recipient,
    ))?;

    let request = TransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        nonce: nonce_result.next_nonce(),
        access_manifest,
        module_ref: inputs.module_ref,
        entrypoint: TRANSFER_ENTRYPOINT.to_string(),
        args,
        gas_limit: inputs.gas_limit,
        fee_payment: Some(fee_payment),
    };
    let prepared = PreparedTransaction::prepare_submission(
        inputs.request_id,
        sender,
        SignatureSchemeId::Ed25519,
        request,
    )?;
    let signed_bytes = sign(prepared)?;

    let submit_result = client.submit_transaction(SubmitTransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        request_id: inputs.request_id,
        signed_transaction_bytes: signed_bytes,
    })?;

    if submit_result.responses().is_empty() {
        return Err(CliError::EmptySubmitResponse);
    }

    println!("request_id={}", submit_result.request_id());
    println!("responses={}", submit_result.responses().len());
    // Print every response's diagnostics before failing, but never let a
    // later `Ok` path (including `--wait`) run once any response was
    // rejected or its decoded execution failed: the first such outcome wins.
    let mut outcome: Result<(), CliError> = Ok(());
    for (index, response) in submit_result.responses().iter().enumerate() {
        let status = match response.status() {
            NodeResponseStatus::Accepted => "accepted",
            NodeResponseStatus::Rejected => "rejected",
        };
        println!("response[{index}].status={status}");
        if outcome.is_ok() && response.status() == NodeResponseStatus::Rejected {
            outcome = Err(CliError::TransactionRejected { index });
        }
        let failure_reason = response
            .payload()
            .and_then(|payload| print_payload(index, payload));
        if let Some(reason) = failure_reason
            && outcome.is_ok()
        {
            outcome = Err(CliError::TransactionExecutionFailed { index, reason });
        }
    }
    outcome?;

    if let Some(bounds) = inputs.wait_bounds {
        let receipt = client.wait_for_receipt(inputs.request_id, &bounds)?;
        print_receipt(&receipt);
    }

    Ok(())
}

pub(crate) fn parse_module_ref(parsed: &ParsedArgs) -> Result<ObjectRef, CliError> {
    let id = ObjectId::new(decode_hex_32(MODULE_ID, parsed.require(MODULE_ID)?)?);
    let version = parse_u64(MODULE_VERSION, parsed.require(MODULE_VERSION)?)?;
    let algorithm_id = parse_u16(
        MODULE_DIGEST_ALGORITHM,
        parsed.require(MODULE_DIGEST_ALGORITHM)?,
    )?;
    let algorithm = HashAlgorithmId::try_from(algorithm_id)
        .map_err(|_| CliError::InvalidHashAlgorithm(algorithm_id))?;
    let digest_bytes = decode_hex_32(MODULE_DIGEST, parsed.require(MODULE_DIGEST)?)?;
    Ok(ObjectRef {
        id,
        version,
        digest: Digest32::new(algorithm, digest_bytes),
    })
}

pub(crate) fn parse_wait_bounds(
    parsed: &ParsedArgs,
) -> Result<Option<ReceiptPollBounds>, CliError> {
    let wait_flags = [
        WAIT_MAX_ATTEMPTS,
        WAIT_INITIAL_BACKOFF_MS,
        WAIT_MAX_BACKOFF_MS,
        WAIT_MAX_ELAPSED_MS,
    ];
    if !parsed.is_present(WAIT) {
        for flag in wait_flags {
            if parsed.is_present(flag) {
                return Err(CliError::WaitBoundWithoutWait(flag));
            }
        }
        return Ok(None);
    }

    for flag in wait_flags {
        if !parsed.is_present(flag) {
            return Err(CliError::WaitBoundRequired(flag));
        }
    }
    let max_attempts = parse_u32(WAIT_MAX_ATTEMPTS, parsed.require(WAIT_MAX_ATTEMPTS)?)?;
    let max_attempts =
        NonZeroU32::new(max_attempts).ok_or(CliError::WaitBoundRequired(WAIT_MAX_ATTEMPTS))?;
    let initial_backoff = Duration::from_millis(parse_u64(
        WAIT_INITIAL_BACKOFF_MS,
        parsed.require(WAIT_INITIAL_BACKOFF_MS)?,
    )?);
    let max_backoff = Duration::from_millis(parse_u64(
        WAIT_MAX_BACKOFF_MS,
        parsed.require(WAIT_MAX_BACKOFF_MS)?,
    )?);
    let max_elapsed = Duration::from_millis(parse_u64(
        WAIT_MAX_ELAPSED_MS,
        parsed.require(WAIT_MAX_ELAPSED_MS)?,
    )?);
    Ok(Some(ReceiptPollBounds {
        max_attempts,
        initial_backoff,
        max_backoff,
        max_elapsed,
    }))
}

/// Queries `object_id`, requires it to be `CurrentInline`, decodes its exact
/// canonical body as a `StandardAssetCoinV1` through `clients/rust`'s
/// generic public surface, and requires the decoded `Owner::Address` to
/// equal `expected_owner` before returning its `ObjectRef` and decoded coin.
///
/// This is a client-side, defense-in-depth check: the server's own typed-
/// entrypoint verification and default sender-ownership rule independently
/// and authoritatively reject an invalid transaction. Checking here too only
/// saves a round trip and gives an actionable local error; it never weakens
/// or substitutes for that server-side check.
pub(crate) fn require_owned_current_coin<T>(
    client: &Client<T>,
    flag: &'static str,
    object_id: ObjectId,
    expected_owner: Address,
) -> Result<(ObjectRef, StandardAssetCoinV1), CliError>
where
    T: Transport,
{
    let result = client.query_object(object_id)?;
    let (object_version, digest, canonical_object_bytes) = match &result {
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => (*object_version, *digest, canonical_object_bytes),
        other => {
            return Err(CliError::ObjectNotCurrentlyInline {
                flag,
                object_id: object_id.to_string(),
                status: object_query_status_label(other),
            });
        }
    };

    let object = decode_object(canonical_object_bytes).map_err(|source| {
        CliError::ObjectBodyDecodeFailed {
            flag,
            object_id: object_id.to_string(),
            source,
        }
    })?;

    match &object.owner {
        Owner::Address(owner_address) if *owner_address == expected_owner => {}
        owner => {
            return Err(CliError::ObjectOwnerMismatch {
                flag,
                object_id: object_id.to_string(),
                expected_owner: expected_owner.to_string(),
                owner: owner_label(owner),
            });
        }
    }

    let coin = decode_standard_asset_coin_v1(&object.data).map_err(|source| {
        CliError::CoinBodyDecodeFailed {
            flag,
            object_id: object_id.to_string(),
            source,
        }
    })?;

    Ok((
        ObjectRef {
            id: object_id,
            version: object_version.get(),
            digest,
        },
        coin,
    ))
}

/// Queries `object_id` and requires it to be `CurrentInline`, returning its
/// exact `ObjectRef` without decoding or checking ownership.
///
/// Used only for the fee treasury: unlike the source/fee coins, the
/// treasury's owner is trusted node composition, not a caller-controlled
/// address, so there is nothing local for this client to compare it against.
pub(crate) fn require_current_inline<T>(
    client: &Client<T>,
    flag: &'static str,
    object_id: ObjectId,
) -> Result<ObjectRef, CliError>
where
    T: Transport,
{
    let result = client.query_object(object_id)?;
    match &result {
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            ..
        } => Ok(ObjectRef {
            id: object_id,
            version: object_version.get(),
            digest: *digest,
        }),
        other => Err(CliError::ObjectNotCurrentlyInline {
            flag,
            object_id: object_id.to_string(),
            status: object_query_status_label(other),
        }),
    }
}

fn owner_label(owner: &Owner) -> String {
    match owner {
        Owner::Address(address) => format!("address:{address}"),
        Owner::Shared => "shared".to_string(),
        Owner::Immutable => "immutable".to_string(),
        Owner::System => "system".to_string(),
    }
}

fn object_query_status_label(result: &sunrise_edge_client::HttpObjectQueryResult) -> &'static str {
    match result {
        sunrise_edge_client::HttpObjectQueryResult::Absent { .. } => "absent",
        sunrise_edge_client::HttpObjectQueryResult::Tombstoned { .. } => "tombstoned",
        sunrise_edge_client::HttpObjectQueryResult::HistoricalCurrentInline { .. } => {
            "historical_current_inline_unverified"
        }
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline { .. } => "current_inline",
        sunrise_edge_client::HttpObjectQueryResult::CurrentBlobReference { .. } => {
            "current_blob_reference"
        }
    }
}

/// Prints `payload`'s diagnostics and returns the sanitized execution
/// failure reason, if its decoded effects declared `ExecutionStatus::Failure`.
pub(crate) fn print_payload(index: usize, payload: &[u8]) -> Option<String> {
    match sunrise_edge_client::decode_execution_effects(payload) {
        Ok(effects) => print_effects(index, &effects),
        Err(_) => {
            let (hex, truncated) = bounded_hex_field(payload);
            println!("response[{index}].payload_len={}", payload.len());
            println!("response[{index}].payload_truncated={truncated}");
            println!("response[{index}].payload_hex={hex}");
            None
        }
    }
}

/// Prints `effects`'s diagnostics and returns the sanitized execution
/// failure reason, if any.
fn print_effects(index: usize, effects: &ExecutionEffects) -> Option<String> {
    println!("response[{index}].tx_hash={}", effects.tx_hash);
    println!("response[{index}].gas_used={}", effects.gas_used);
    let failure_reason = match &effects.status {
        ExecutionStatus::Success => {
            println!("response[{index}].execution_status=success");
            None
        }
        ExecutionStatus::Failure { reason } => {
            println!("response[{index}].execution_status=failure");
            let sanitized_reason = sanitize_line(reason);
            println!("response[{index}].execution_failure_reason={sanitized_reason}");
            Some(sanitized_reason)
        }
    };
    println!(
        "response[{index}].object_effects={}",
        effects.object_effects.len()
    );
    for (effect_index, effect) in effects.object_effects.iter().enumerate() {
        print_object_effect(index, effect_index, effect);
    }
    println!("response[{index}].events={}", effects.events.len());
    for (event_index, event) in effects.events.iter().enumerate() {
        let (type_tag_hex, type_tag_truncated) = bounded_hex_field(&event.type_tag);
        let (data_hex, data_truncated) = bounded_hex_field(&event.data);
        println!("response[{index}].event[{event_index}].type_tag_hex={type_tag_hex}");
        println!("response[{index}].event[{event_index}].type_tag_truncated={type_tag_truncated}");
        println!(
            "response[{index}].event[{event_index}].data_len={}",
            event.data.len()
        );
        println!("response[{index}].event[{event_index}].data_truncated={data_truncated}");
        println!("response[{index}].event[{event_index}].data_hex={data_hex}");
    }
    failure_reason
}

fn print_object_effect(response_index: usize, effect_index: usize, effect: &ObjectEffect) {
    let prefix = format!("response[{response_index}].object_effect[{effect_index}]");
    match effect {
        ObjectEffect::Created(object) => {
            println!("{prefix}.kind=created");
            println!("{prefix}.object_id={}", object.id);
            println!("{prefix}.object_version={}", object.version);
            let (hex, truncated) = bounded_hex_field(&object.data);
            println!("{prefix}.data_len={}", object.data.len());
            println!("{prefix}.data_truncated={truncated}");
            println!("{prefix}.data_hex={hex}");
        }
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        } => {
            println!("{prefix}.kind=mutated");
            println!("{prefix}.object_id={}", new_object.id);
            println!("{prefix}.previous_version={previous_version}");
            println!("{prefix}.object_version={}", new_object.version);
            let (hex, truncated) = bounded_hex_field(&new_object.data);
            println!("{prefix}.data_len={}", new_object.data.len());
            println!("{prefix}.data_truncated={truncated}");
            println!("{prefix}.data_hex={hex}");
        }
        ObjectEffect::Deleted { id, version } => {
            println!("{prefix}.kind=deleted");
            println!("{prefix}.object_id={id}");
            println!("{prefix}.object_version={version}");
        }
    }
}

pub(crate) fn print_receipt(receipt: &sunrise_edge_client::HttpReceiptQueryResult) {
    match receipt {
        sunrise_edge_client::HttpReceiptQueryResult::Absent { request_id } => {
            println!("receipt_status=absent");
            println!("receipt_request_id={request_id}");
        }
        sunrise_edge_client::HttpReceiptQueryResult::Present {
            request_id,
            event_digest,
            dedup_record_bytes,
        } => {
            println!("receipt_status=present");
            println!("receipt_request_id={request_id}");
            println!(
                "receipt_event_digest_algorithm={}",
                event_digest.algorithm().as_u16()
            );
            println!("receipt_event_digest={event_digest}");
            let (hex, truncated) = bounded_hex_field(dedup_record_bytes);
            println!(
                "receipt_dedup_record_bytes_len={}",
                dedup_record_bytes.len()
            );
            println!("receipt_dedup_record_bytes_truncated={truncated}");
            println!("receipt_dedup_record_bytes={hex}");
        }
    }
}

/// Submits one already-signed request and applies the CLI's fail-closed
/// response handling shared by whole transfer, split, and merge.
pub(crate) fn submit_and_report<T: Transport>(
    client: &Client<T>,
    context: &sunrise_edge_client::HttpContextQueryResult,
    request_id: RequestId,
    signed_transaction_bytes: Vec<u8>,
    wait_bounds: Option<ReceiptPollBounds>,
) -> Result<(), CliError> {
    let submit_result = client.submit_transaction(SubmitTransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        request_id,
        signed_transaction_bytes,
    })?;

    if submit_result.responses().is_empty() {
        return Err(CliError::EmptySubmitResponse);
    }
    println!("request_id={}", submit_result.request_id());
    println!("responses={}", submit_result.responses().len());
    let mut outcome: Result<(), CliError> = Ok(());
    for (index, response) in submit_result.responses().iter().enumerate() {
        let status = match response.status() {
            NodeResponseStatus::Accepted => "accepted",
            NodeResponseStatus::Rejected => "rejected",
        };
        println!("response[{index}].status={status}");
        if outcome.is_ok() && response.status() == NodeResponseStatus::Rejected {
            outcome = Err(CliError::TransactionRejected { index });
        }
        let failure_reason = response
            .payload()
            .and_then(|payload| print_payload(index, payload));
        if let Some(reason) = failure_reason
            && outcome.is_ok()
        {
            outcome = Err(CliError::TransactionExecutionFailed { index, reason });
        }
    }
    outcome?;
    if let Some(bounds) = wait_bounds {
        let receipt = client.wait_for_receipt(request_id, &bounds)?;
        print_receipt(&receipt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, node_result_ok, query_ok};
    use hashing::{BuiltinHashFunction, HashFunction};
    use protocol_types::HashPurpose;
    use sunrise_edge_client::{
        AtomicityDomainId, ChainId, ClientError, Epoch, HashSuiteId, HttpContextQueryResult,
        HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult, NodeResponse,
        ProtocolContextMismatch, ProtocolVersion, StandardAssetCoinV1,
        encode_standard_asset_coin_v1,
    };

    fn sample_signer() -> LocalSigner {
        LocalSigner::from_seed([0x77; 32])
    }

    /// The local-signer `sign` closure every `execute` test below passes.
    fn sign_locally(
        signer: &LocalSigner,
    ) -> impl FnOnce(PreparedTransaction) -> Result<Vec<u8>, CliError> {
        let signer = signer.clone();
        move |prepared| {
            prepared
                .sign_and_finalize_with(&signer)
                .map_err(CliError::from)
        }
    }

    fn sample_expected_context() -> ExpectedProtocolContext {
        ExpectedProtocolContext::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(5),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
        )
        .unwrap()
    }

    const ASSET: AssetId = AssetId::new([0x50; 32]);

    fn sample_inputs() -> TransferInputs {
        TransferInputs {
            module_ref: ObjectRef {
                id: ObjectId::new([0x01; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
            },
            source_coin_id: ObjectId::new([0x10; 32]),
            fee_coin_id: ObjectId::new([0x20; 32]),
            recipient: Address::new([0x88; 32]),
            fee_asset_id: ASSET,
            max_fee: Amount::new(10),
            fee_treasury_object_id: ObjectId::new([0x40; 32]),
            gas_limit: 1_000,
            request_id: RequestId::new([0x30; 32]).unwrap(),
            expected_context: sample_expected_context(),
            wait_bounds: None,
        }
    }

    fn sample_context() -> HttpContextQueryResult {
        HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(5),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap()
    }

    fn coin_object_bytes(asset_id: AssetId, amount: u64) -> Vec<u8> {
        encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(asset_id, amount).unwrap()).unwrap()
    }

    fn current_inline_with_owner(
        object_id: ObjectId,
        version: u64,
        owner: Owner,
        data: Vec<u8>,
    ) -> HttpObjectQueryResult {
        let creating_chain_id: ChainId = ChainId::new("transfer-test-chain").unwrap();
        let creating_protocol_version: ProtocolVersion = ProtocolVersion::new(4);
        let object = objects::Object {
            id: object_id,
            version,
            owner,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x09; 32]),
            schema_version: 1,
            data,
        };
        let canonical_object_bytes: Vec<u8> = objects::encode_object(&object).unwrap();
        let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
            .hash(
                HashPurpose::Object,
                creating_protocol_version,
                &creating_chain_id,
                &canonical_object_bytes,
            )
            .unwrap();
        HttpObjectQueryResult::CurrentInline {
            object_id,
            head_revision: runtime::ObjectHeadRevision::new(1).unwrap(),
            object_version: runtime::DurableObjectVersion::new(version).unwrap(),
            digest,
            creating_chain_id,
            creating_protocol_version,
            canonical_object_bytes,
        }
    }

    fn current_coin_owned_by(
        object_id: ObjectId,
        version: u64,
        owner: Address,
        asset_id: AssetId,
        amount: u64,
    ) -> HttpObjectQueryResult {
        current_inline_with_owner(
            object_id,
            version,
            Owner::Address(owner),
            coin_object_bytes(asset_id, amount),
        )
    }

    #[test]
    fn execute_succeeds_and_submits_after_the_expected_round_trip() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), ASSET, 500);
        let treasury = current_inline_with_owner(
            inputs.fee_treasury_object_id,
            1,
            Owner::Address(Address::new([0x99; 32])),
            coin_object_bytes(ASSET, 1),
        );
        let accepted =
            NodeResponse::new(inputs.request_id, NodeResponseStatus::Accepted, None).unwrap();
        let submit = HttpNodeResult::new(inputs.request_id, vec![accepted]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
            query_ok(treasury.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);
        let expected_treasury_id = inputs.fee_treasury_object_id;
        let expected_fee_coin_id = inputs.fee_coin_id;

        execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap();

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 6);
        assert_eq!(requests[0].path, "/v1/context");
        assert_eq!(requests[5].method, sunrise_edge_client::Method::Post);
        let submitted_event = node_core::NodeEvent::decode(&requests[5].body).unwrap();
        let transaction = execution::decode_transaction(submitted_event.payload()).unwrap();
        assert_eq!(transaction.access_manifest.entries.len(), 3);
        let final_access = &transaction.access_manifest.entries[2];
        assert_eq!(final_access.object_ref.id, expected_treasury_id);
        assert_eq!(final_access.mode, AccessMode::Write);
        let payment = transaction
            .fee_payment
            .expect("transfer always declares a fee payment");
        assert_eq!(payment.asset_id, ASSET);
        assert_eq!(payment.max_fee, Amount::new(10));
        assert_eq!(payment.fee_object.id, expected_fee_coin_id);
    }

    #[test]
    fn execute_rejects_a_source_coin_owned_by_a_different_address() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let other_owner = Address::new([0xB2; 32]);
        let source = current_coin_owned_by(inputs.source_coin_id, 1, other_owner, ASSET, 1_000);

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(
            error,
            CliError::ObjectOwnerMismatch {
                flag: SOURCE_COIN,
                owner,
                ..
            } if owner == format!("address:{other_owner}")
        ));
    }

    #[test]
    fn execute_rejects_mismatched_asset_ids_between_source_and_fee_coin() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let other_asset = AssetId::new([0x51; 32]);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), other_asset, 500);

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(error, CliError::CoinAssetMismatch));
    }

    #[test]
    fn execute_rejects_a_fee_asset_id_that_differs_from_the_coins_asset() {
        let signer = sample_signer();
        let mut inputs = sample_inputs();
        inputs.fee_asset_id = AssetId::new([0x51; 32]);
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), ASSET, 500);

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(error, CliError::FeeAssetMismatch));
    }

    #[test]
    fn execute_rejects_a_fee_treasury_that_is_not_currently_inline() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), ASSET, 500);
        let absent_treasury = HttpObjectQueryResult::Absent {
            object_id: inputs.fee_treasury_object_id,
        };

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
            query_ok(absent_treasury.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(
            error,
            CliError::ObjectNotCurrentlyInline {
                flag: FEE_TREASURY_OBJECT,
                status: "absent",
                ..
            }
        ));
    }

    #[test]
    fn execute_rejects_a_rejected_submission_response_even_with_wait_requested() {
        let signer = sample_signer();
        let mut inputs = sample_inputs();
        inputs.wait_bounds = Some(ReceiptPollBounds {
            max_attempts: NonZeroU32::new(3).unwrap(),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_elapsed: Duration::from_millis(100),
        });
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), ASSET, 500);
        let treasury = current_inline_with_owner(
            inputs.fee_treasury_object_id,
            1,
            Owner::Address(Address::new([0x99; 32])),
            coin_object_bytes(ASSET, 1),
        );
        let rejected =
            NodeResponse::new(inputs.request_id, NodeResponseStatus::Rejected, None).unwrap();
        let submit = HttpNodeResult::new(inputs.request_id, vec![rejected]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
            query_ok(treasury.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(error, CliError::TransactionRejected { index: 0 }));
        assert_eq!(client.transport().requests().len(), 6);
    }

    #[test]
    fn execute_rejects_an_execution_failure_even_when_the_node_response_is_accepted() {
        let signer = sample_signer();
        let mut inputs = sample_inputs();
        inputs.wait_bounds = Some(ReceiptPollBounds {
            max_attempts: NonZeroU32::new(3).unwrap(),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_elapsed: Duration::from_millis(100),
        });
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), ASSET, 500);
        let treasury = current_inline_with_owner(
            inputs.fee_treasury_object_id,
            1,
            Owner::Address(Address::new([0x99; 32])),
            coin_object_bytes(ASSET, 1),
        );
        let effects = execution::ExecutionEffects {
            tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x0B; 32]),
            status: ExecutionStatus::Failure {
                reason: "trap: out of gas".to_string(),
            },
            object_effects: Vec::new(),
            events: Vec::new(),
            gas_used: 1_000,
        };
        let payload = execution::encode_execution_effects(&effects).unwrap();
        let accepted = NodeResponse::new(
            inputs.request_id,
            NodeResponseStatus::Accepted,
            Some(payload),
        )
        .unwrap();
        let submit = HttpNodeResult::new(inputs.request_id, vec![accepted]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
            query_ok(treasury.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(
            error,
            CliError::TransactionExecutionFailed { index: 0, reason }
                if reason == "trap: out of gas"
        ));
        assert_eq!(client.transport().requests().len(), 6);
    }

    #[test]
    fn execute_rejects_an_empty_submit_response() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let source =
            current_coin_owned_by(inputs.source_coin_id, 1, signer.address(), ASSET, 1_000);
        let fee = current_coin_owned_by(inputs.fee_coin_id, 1, signer.address(), ASSET, 500);
        let treasury = current_inline_with_owner(
            inputs.fee_treasury_object_id,
            1,
            Owner::Address(Address::new([0x99; 32])),
            coin_object_bytes(ASSET, 1),
        );
        let submit = HttpNodeResult::new(inputs.request_id, vec![]).unwrap();

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(source.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
            query_ok(treasury.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(error, CliError::EmptySubmitResponse));
    }

    #[test]
    fn execute_rejects_an_epoch_mismatch_between_context_and_nonce() {
        let signer = sample_signer();
        let inputs = sample_inputs();
        let context = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(6), 3);

        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
        ]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        assert!(matches!(
            error,
            CliError::EpochMismatch {
                context_epoch: 5,
                nonce_epoch: 6
            }
        ));
    }

    /// Runs `execute` against a `/v1/context` response that mismatches
    /// `sample_expected_context()` in exactly one field, and proves it stops
    /// after only that one context request — never issuing a second
    /// (nonce/object/submit) request — before returning the expected
    /// [`ProtocolContextMismatch`] variant.
    fn assert_context_mismatch_stops_before_further_dispatch(
        mismatched_context: HttpContextQueryResult,
        matches_expected_variant: impl Fn(&ProtocolContextMismatch) -> bool,
    ) {
        let signer = sample_signer();
        let inputs = sample_inputs();

        let transport = FakeTransport::new(vec![query_ok(mismatched_context.encode().unwrap())]);
        let client = Client::new(transport);

        let error = execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap_err();
        match error {
            CliError::Client(boxed) => match *boxed {
                ClientError::ProtocolContextMismatch(mismatch) => {
                    assert!(
                        matches_expected_variant(&mismatch),
                        "unexpected mismatch variant: {mismatch:?}"
                    );
                }
                other => panic!("expected ProtocolContextMismatch, got {other:?}"),
            },
            other => panic!("expected CliError::Client(ProtocolContextMismatch), got {other:?}"),
        }
        assert_eq!(client.transport().requests().len(), 1);
    }

    #[test]
    fn execute_rejects_a_mismatched_chain_id_before_any_later_dispatch() {
        let context = HttpContextQueryResult::new(
            ChainId::new("some-other-chain").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(5),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        assert_context_mismatch_stops_before_further_dispatch(context, |mismatch| {
            matches!(mismatch, ProtocolContextMismatch::ChainId { .. })
        });
    }

    #[test]
    fn execute_rejects_a_mismatched_protocol_version_before_any_later_dispatch() {
        let context = HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(5),
            Epoch::new(5),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        assert_context_mismatch_stops_before_further_dispatch(context, |mismatch| {
            matches!(mismatch, ProtocolContextMismatch::ProtocolVersion { .. })
        });
    }

    #[test]
    fn execute_rejects_a_mismatched_epoch_before_any_later_dispatch() {
        let context = HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(6),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        assert_context_mismatch_stops_before_further_dispatch(context, |mismatch| {
            matches!(mismatch, ProtocolContextMismatch::Epoch { .. })
        });
    }

    #[test]
    fn execute_rejects_a_mismatched_domain_before_any_later_dispatch() {
        let context = HttpContextQueryResult::new(
            ChainId::new("transfer-test-chain").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(5),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x55; 32]).unwrap(),
            vec![0xAA],
        )
        .unwrap();
        assert_context_mismatch_stops_before_further_dispatch(context, |mismatch| {
            matches!(mismatch, ProtocolContextMismatch::Domain { .. })
        });
    }

    #[test]
    fn parse_inputs_rejects_matching_source_and_fee_coin() {
        let mut args = base_flag_values();
        args.insert(FEE_COIN, "10".repeat(32));
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::SameSourceCoinAndFeeCoin)
        ));
    }

    #[test]
    fn parse_inputs_requires_an_explicit_recipient() {
        let mut args = base_flag_values();
        args.remove(RECIPIENT);
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::Args(crate::args::ArgsError::MissingFlag(
                RECIPIENT
            )))
        ));
    }

    #[test]
    fn parse_inputs_rejects_a_malformed_recipient() {
        let mut args = base_flag_values();
        args.insert(RECIPIENT, "not-hex".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(parse_inputs(&parsed), Err(CliError::Hex(_))));
    }

    #[test]
    fn parse_inputs_rejects_zero_gas_limit() {
        let mut args = base_flag_values();
        args.insert(GAS_LIMIT, "0".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(parse_inputs(&parsed), Err(CliError::ZeroGasLimit)));
    }

    #[test]
    fn parse_inputs_rejects_zero_request_id() {
        let mut args = base_flag_values();
        args.insert(REQUEST_ID, "00".repeat(32));
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(parse_inputs(&parsed), Err(CliError::NodeCore(_))));
    }

    #[test]
    fn parse_inputs_rejects_zero_max_fee_and_treasury_transfer_collisions() {
        let mut zero = base_flag_values();
        zero.insert(MAX_FEE, "0".to_string());
        let parsed = parse_flags(to_os(&zero), &transfer_specs()).unwrap();
        assert!(matches!(parse_inputs(&parsed), Err(CliError::ZeroMaxFee)));

        for conflicting_object in ["10".repeat(32), "20".repeat(32)] {
            let mut values = base_flag_values();
            values.insert(FEE_TREASURY_OBJECT, conflicting_object);
            let parsed = parse_flags(to_os(&values), &transfer_specs()).unwrap();
            assert!(matches!(
                parse_inputs(&parsed),
                Err(CliError::FeeTreasuryConflictsWithTransfer)
            ));
        }
    }

    #[test]
    fn parse_inputs_rejects_a_missing_expected_flag() {
        let mut args = base_flag_values();
        args.remove(EXPECTED_CHAIN_ID);
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::Args(crate::args::ArgsError::MissingFlag(
                EXPECTED_CHAIN_ID
            )))
        ));
    }

    #[test]
    fn parse_expected_context_rejects_an_empty_expected_chain_id() {
        let mut args = base_flag_values();
        args.insert(EXPECTED_CHAIN_ID, String::new());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_expected_context(&parsed),
            Err(CliError::InvalidExpectedProtocolType(_))
        ));
    }

    #[test]
    fn parse_expected_context_rejects_a_zero_expected_protocol_version() {
        let mut args = base_flag_values();
        args.insert(EXPECTED_PROTOCOL_VERSION, "0".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_expected_context(&parsed),
            Err(CliError::InvalidExpectedContext(
                sunrise_edge_client::ExpectedProtocolContextError::ZeroProtocolVersion
            ))
        ));
    }

    #[test]
    fn parse_expected_context_accepts_a_zero_expected_epoch() {
        // Epoch zero is the legitimate genesis epoch and must not be
        // rejected merely for being zero.
        let mut args = base_flag_values();
        args.insert(EXPECTED_EPOCH, "0".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(parse_expected_context(&parsed).is_ok());
    }

    #[test]
    fn parse_expected_context_rejects_a_zero_expected_hash_suite_id() {
        let mut args = base_flag_values();
        args.insert(EXPECTED_HASH_SUITE_ID, "0".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_expected_context(&parsed),
            Err(CliError::InvalidExpectedContext(
                sunrise_edge_client::ExpectedProtocolContextError::ZeroHashSuiteId
            ))
        ));
    }

    #[test]
    fn parse_expected_context_rejects_a_zero_expected_domain() {
        let mut args = base_flag_values();
        args.insert(EXPECTED_DOMAIN, "00".repeat(32));
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_expected_context(&parsed),
            Err(CliError::InvalidExpectedProtocolType(_))
        ));
    }

    #[test]
    fn parse_expected_context_rejects_a_malformed_expected_domain() {
        let mut args = base_flag_values();
        args.insert(EXPECTED_DOMAIN, "not-hex".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_expected_context(&parsed),
            Err(CliError::Hex(_))
        ));
    }

    #[test]
    fn parse_expected_context_rejects_a_malformed_expected_protocol_version() {
        let mut args = base_flag_values();
        args.insert(EXPECTED_PROTOCOL_VERSION, "not-a-number".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_expected_context(&parsed),
            Err(CliError::InvalidInteger {
                flag: EXPECTED_PROTOCOL_VERSION,
                ..
            })
        ));
    }

    #[test]
    fn wait_bound_flag_without_wait_is_rejected() {
        let mut args = base_flag_values();
        args.insert(WAIT_MAX_ATTEMPTS, "3".to_string());
        let parsed = parse_flags(to_os(&args), &transfer_specs()).unwrap();

        assert!(matches!(
            parse_wait_bounds(&parsed),
            Err(CliError::WaitBoundWithoutWait(WAIT_MAX_ATTEMPTS))
        ));
    }

    #[test]
    fn wait_without_all_bound_flags_is_rejected() {
        let args = to_os_vec(vec![OsString::from(WAIT)]);
        let parsed = parse_flags(args, &[switch(WAIT), scalar(WAIT_MAX_ATTEMPTS)]).unwrap();

        assert!(matches!(
            parse_wait_bounds(&parsed),
            Err(CliError::WaitBoundRequired(WAIT_MAX_ATTEMPTS))
        ));
    }

    #[test]
    fn wait_with_all_bound_flags_parses() {
        let args = to_os_vec(vec![
            OsString::from(WAIT),
            OsString::from(WAIT_MAX_ATTEMPTS),
            OsString::from("5"),
            OsString::from(WAIT_INITIAL_BACKOFF_MS),
            OsString::from("10"),
            OsString::from(WAIT_MAX_BACKOFF_MS),
            OsString::from("100"),
            OsString::from(WAIT_MAX_ELAPSED_MS),
            OsString::from("1000"),
        ]);
        let parsed = parse_flags(
            args,
            &[
                switch(WAIT),
                scalar(WAIT_MAX_ATTEMPTS),
                scalar(WAIT_INITIAL_BACKOFF_MS),
                scalar(WAIT_MAX_BACKOFF_MS),
                scalar(WAIT_MAX_ELAPSED_MS),
            ],
        )
        .unwrap();

        let bounds = parse_wait_bounds(&parsed).unwrap().unwrap();
        assert_eq!(bounds.max_attempts.get(), 5);
        assert_eq!(bounds.initial_backoff, Duration::from_millis(10));
        assert_eq!(bounds.max_backoff, Duration::from_millis(100));
        assert_eq!(bounds.max_elapsed, Duration::from_millis(1_000));
    }

    #[test]
    fn ledger_selection_is_rejected_before_device_or_network_dispatch() {
        let mut args: Vec<OsString> = to_os(&base_flag_values());
        args.extend([
            OsString::from(ENDPOINT),
            OsString::from("127.0.0.1:1"),
            OsString::from("--ledger-hid-path"),
            OsString::from("definitely-not-a-device"),
            OsString::from("--ledger-account"),
            OsString::from("0"),
            OsString::from("--ledger-expected-firmware-version"),
            OsString::from("1.2.3"),
        ]);

        let error: CliError = run(args).unwrap_err();
        assert!(matches!(
            error,
            CliError::LedgerStandardAssetTransferUnsupported
        ));
    }

    fn base_flag_values() -> std::collections::BTreeMap<&'static str, String> {
        let mut values = std::collections::BTreeMap::new();
        values.insert(MODULE_ID, "01".repeat(32));
        values.insert(MODULE_VERSION, "1".to_string());
        values.insert(MODULE_DIGEST_ALGORITHM, "1".to_string());
        values.insert(MODULE_DIGEST, "02".repeat(32));
        values.insert(SOURCE_COIN, "10".repeat(32));
        values.insert(FEE_COIN, "20".repeat(32));
        values.insert(RECIPIENT, "88".repeat(32));
        values.insert(GAS_LIMIT, "1000".to_string());
        values.insert(FEE_ASSET_ID, "50".repeat(32));
        values.insert(MAX_FEE, "1001".to_string());
        values.insert(FEE_TREASURY_OBJECT, "40".repeat(32));
        values.insert(REQUEST_ID, "30".repeat(32));
        values.insert(EXPECTED_CHAIN_ID, "transfer-test-chain".to_string());
        values.insert(EXPECTED_PROTOCOL_VERSION, "4".to_string());
        values.insert(EXPECTED_EPOCH, "5".to_string());
        values.insert(EXPECTED_HASH_SUITE_ID, "1".to_string());
        values.insert(EXPECTED_DOMAIN, "44".repeat(32));
        values
    }

    /// The subset of [`transfer_flag_specs`] the parsing-only unit tests
    /// below exercise (they never supply `--endpoint`, and signer selection
    /// is exercised separately by `crate::signer`'s own tests).
    fn transfer_specs() -> Vec<crate::args::FlagSpec> {
        transfer_flag_specs()
            .into_iter()
            .filter(|spec| spec.name != ENDPOINT)
            .collect()
    }

    fn to_os(values: &std::collections::BTreeMap<&'static str, String>) -> Vec<OsString> {
        let mut out = Vec::new();
        for (flag, value) in values {
            out.push(OsString::from(*flag));
            out.push(OsString::from(value.clone()));
        }
        out
    }

    fn to_os_vec(values: Vec<OsString>) -> Vec<OsString> {
        values
    }
}
