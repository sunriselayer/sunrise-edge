//! `split`: partial Standard Asset v1 transfer.
//!
//! The command deliberately exposes the exact source coin and amount while
//! keeping all balance arithmetic in the committed module. It performs local
//! ownership, type, and range checks before signing, then submits the exact
//! protocol-v5/module-v2 manifest: source `Write`, fee `Write`, and the
//! trusted treasury `Write`.

use std::ffi::OsString;

use standard_assets::{StandardAssetSplitArgsV1, encode_standard_asset_split_args_v1};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Amount, AssetId, Client,
    ExpectedProtocolContext, FeePayment, LocalSigner, ObjectId, ObjectRef, PreparedTransaction,
    RequestId, SignatureSchemeId, TransactionRequest, Transport,
};

use super::transfer;
use crate::args::{ParsedArgs, parse_flags, scalar, switch};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::net::{connect, tls_flag_specs};
use crate::parse::parse_u64;
use crate::seed::load_dev_seed;
use crate::signer::{SignerSelection, parse_signer_selection, signer_flag_specs};

const ENDPOINT: &str = "--endpoint";
const MODULE_ID: &str = "--module-id";
const MODULE_VERSION: &str = "--module-version";
const MODULE_DIGEST_ALGORITHM: &str = "--module-digest-algorithm";
const MODULE_DIGEST: &str = "--module-digest";
const SOURCE_COIN: &str = "--source-coin";
const RECIPIENT: &str = "--recipient";
const AMOUNT: &str = "--amount";
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
const SPLIT_ENTRYPOINT: &str = "split";

/// Runs the partial-transfer command.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = split_flag_specs();
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
        SignerSelection::Ledger { .. } => Err(CliError::LedgerStandardAssetOperationUnsupported {
            operation: SPLIT_ENTRYPOINT,
        }),
    }
}

fn split_flag_specs() -> Vec<crate::args::FlagSpec> {
    vec![
        scalar(ENDPOINT),
        scalar(MODULE_ID),
        scalar(MODULE_VERSION),
        scalar(MODULE_DIGEST_ALGORITHM),
        scalar(MODULE_DIGEST),
        scalar(SOURCE_COIN),
        scalar(RECIPIENT),
        scalar(AMOUNT),
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

struct SplitInputs {
    module_ref: ObjectRef,
    source_coin_id: ObjectId,
    recipient: Address,
    amount: u64,
    fee_coin_id: ObjectId,
    fee_asset_id: AssetId,
    max_fee: Amount,
    fee_treasury_object_id: ObjectId,
    gas_limit: u64,
    request_id: RequestId,
    expected_context: ExpectedProtocolContext,
    wait_bounds: Option<sunrise_edge_client::ReceiptPollBounds>,
}

fn parse_inputs(parsed: &ParsedArgs) -> Result<SplitInputs, CliError> {
    let module_ref = transfer::parse_module_ref(parsed)?;
    let source_coin_id = ObjectId::new(decode_hex_32(SOURCE_COIN, parsed.require(SOURCE_COIN)?)?);
    let recipient = Address::new(decode_hex_32(RECIPIENT, parsed.require(RECIPIENT)?)?);
    let amount = parse_u64(AMOUNT, parsed.require(AMOUNT)?)?;
    if amount == 0 {
        return Err(CliError::ZeroSplitAmount);
    }
    let fee_coin_id = ObjectId::new(decode_hex_32(FEE_COIN, parsed.require(FEE_COIN)?)?);
    if source_coin_id == fee_coin_id {
        return Err(CliError::SameSourceCoinAndFeeCoin);
    }
    let fee_treasury_object_id = ObjectId::new(decode_hex_32(
        FEE_TREASURY_OBJECT,
        parsed.require(FEE_TREASURY_OBJECT)?,
    )?);
    if fee_treasury_object_id == source_coin_id || fee_treasury_object_id == fee_coin_id {
        return Err(CliError::FeeTreasuryConflictsWithTransfer);
    }
    let max_fee_value = parse_u64(MAX_FEE, parsed.require(MAX_FEE)?)?;
    if max_fee_value == 0 {
        return Err(CliError::ZeroMaxFee);
    }
    let gas_limit = parse_u64(GAS_LIMIT, parsed.require(GAS_LIMIT)?)?;
    if gas_limit == 0 {
        return Err(CliError::ZeroGasLimit);
    }
    Ok(SplitInputs {
        module_ref,
        source_coin_id,
        recipient,
        amount,
        fee_coin_id,
        fee_asset_id: AssetId::new(decode_hex_32(FEE_ASSET_ID, parsed.require(FEE_ASSET_ID)?)?),
        max_fee: Amount::new(max_fee_value),
        fee_treasury_object_id,
        gas_limit,
        request_id: RequestId::new(decode_hex_32(REQUEST_ID, parsed.require(REQUEST_ID)?)?)?,
        expected_context: transfer::parse_expected_context(parsed)?,
        wait_bounds: transfer::parse_wait_bounds(parsed)?,
    })
}

fn execute<T, F>(
    client: &Client<T>,
    sender: Address,
    inputs: SplitInputs,
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
        transfer::require_owned_current_coin(client, SOURCE_COIN, inputs.source_coin_id, sender)?;
    if inputs.amount >= source_coin.amount() {
        return Err(CliError::SplitAmountNotBelowSource {
            amount: inputs.amount,
            source_amount: source_coin.amount(),
        });
    }
    let (fee_ref, fee_coin) =
        transfer::require_owned_current_coin(client, FEE_COIN, inputs.fee_coin_id, sender)?;
    if source_coin.asset_id() != fee_coin.asset_id() {
        return Err(CliError::CoinAssetMismatch);
    }
    if inputs.fee_asset_id != source_coin.asset_id() {
        return Err(CliError::FeeAssetMismatch);
    }
    let treasury_ref = transfer::require_current_inline(
        client,
        FEE_TREASURY_OBJECT,
        inputs.fee_treasury_object_id,
    )?;
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
    let args = encode_standard_asset_split_args_v1(&StandardAssetSplitArgsV1::new(
        inputs.amount,
        inputs.recipient,
    )?)
    .map_err(CliError::SplitArgsEncodingFailed)?;
    let request = TransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        nonce: nonce_result.next_nonce(),
        access_manifest,
        module_ref: inputs.module_ref,
        entrypoint: SPLIT_ENTRYPOINT.to_string(),
        args,
        gas_limit: inputs.gas_limit,
        fee_payment: Some(FeePayment {
            asset_id: inputs.fee_asset_id,
            max_fee: inputs.max_fee,
            fee_object: fee_ref,
        }),
    };
    let prepared = PreparedTransaction::prepare_submission(
        inputs.request_id,
        sender,
        SignatureSchemeId::Ed25519,
        request,
    )?;
    let signed_bytes = sign(prepared)?;
    transfer::submit_and_report(
        client,
        &context,
        inputs.request_id,
        signed_bytes,
        inputs.wait_bounds,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(amount: &str) -> Vec<OsString> {
        vec![
            OsString::from("--module-id"),
            OsString::from("11".repeat(32)),
            OsString::from("--module-version"),
            OsString::from("2"),
            OsString::from("--module-digest-algorithm"),
            OsString::from("1"),
            OsString::from("--module-digest"),
            OsString::from("22".repeat(32)),
            OsString::from("--source-coin"),
            OsString::from("33".repeat(32)),
            OsString::from("--recipient"),
            OsString::from("44".repeat(32)),
            OsString::from("--amount"),
            OsString::from(amount),
            OsString::from("--fee-coin"),
            OsString::from("55".repeat(32)),
            OsString::from("--gas-limit"),
            OsString::from("1000"),
            OsString::from("--fee-asset-id"),
            OsString::from("66".repeat(32)),
            OsString::from("--max-fee"),
            OsString::from("10"),
            OsString::from("--fee-treasury-object"),
            OsString::from("77".repeat(32)),
            OsString::from("--request-id"),
            OsString::from("88".repeat(32)),
            OsString::from("--expected-chain-id"),
            OsString::from("split-test"),
            OsString::from("--expected-protocol-version"),
            OsString::from("5"),
            OsString::from("--expected-epoch"),
            OsString::from("1"),
            OsString::from("--expected-hash-suite-id"),
            OsString::from("1"),
            OsString::from("--expected-domain"),
            OsString::from("99".repeat(32)),
        ]
    }

    #[test]
    fn parser_rejects_zero_split_amount_before_any_network_use() {
        let parsed = parse_flags(args("0"), &split_flag_specs()).unwrap();
        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::ZeroSplitAmount)
        ));
    }

    #[test]
    fn parser_accepts_protocol_v5_split_shape() {
        let parsed = parse_flags(args("7"), &split_flag_specs()).unwrap();
        let inputs = parse_inputs(&parsed).unwrap();
        assert_eq!(inputs.amount, 7);
        assert_eq!(inputs.module_ref.version, 2);
        assert_eq!(inputs.expected_context.protocol_version().get(), 5);
    }
}
