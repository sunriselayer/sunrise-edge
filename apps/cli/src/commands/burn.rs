//! `burn`: supply-accounted whole-coin destruction on the local devnet.
//!
//! Before signing, this command verifies the expected protocol context and
//! nonce, strictly decodes the sender-owned treasury cap, burned coin, and fee
//! coin, and requires one shared `AssetId`. The signed manifest is exactly cap
//! `Write`, burned coin `Consume`, fee coin `Write`, then the trusted fee
//! treasury `Write`; module arguments are empty.

use std::ffi::OsString;

use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Amount, AssetId, Client,
    ExpectedProtocolContext, FeePayment, LocalSigner, ObjectId, ObjectRef, PreparedTransaction,
    ReceiptPollBounds, RequestId, SignatureSchemeId, TransactionRequest, Transport,
};

use super::{mint, transfer};
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
const TREASURY_CAP: &str = "--treasury-cap";
const COIN: &str = "--coin";
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
const BURN_ENTRYPOINT: &str = "burn";

/// Runs the whole-coin burn command.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs: Vec<crate::args::FlagSpec> = burn_flag_specs();
    specs.extend(tls_flag_specs());
    specs.extend(signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let endpoint: &str = parsed.require(ENDPOINT)?;
    let inputs: BurnInputs = parse_inputs(&parsed)?;

    match parse_signer_selection(&parsed)? {
        SignerSelection::Local { seed_file } => {
            let seed: [u8; 32] = load_dev_seed(std::path::Path::new(&seed_file))?;
            let signer: LocalSigner = LocalSigner::from_seed(seed);
            let sender: Address = signer.address();
            let client = connect(endpoint, &parsed)?;
            execute(&client, sender, inputs, |prepared: PreparedTransaction| {
                prepared
                    .sign_and_finalize_with(&signer)
                    .map_err(CliError::from)
            })
        }
        SignerSelection::Ledger { .. } => Err(CliError::LedgerStandardAssetOperationUnsupported {
            operation: BURN_ENTRYPOINT,
        }),
    }
}

fn burn_flag_specs() -> Vec<crate::args::FlagSpec> {
    vec![
        scalar(ENDPOINT),
        scalar(MODULE_ID),
        scalar(MODULE_VERSION),
        scalar(MODULE_DIGEST_ALGORITHM),
        scalar(MODULE_DIGEST),
        scalar(TREASURY_CAP),
        scalar(COIN),
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

struct BurnInputs {
    module_ref: ObjectRef,
    treasury_cap_id: ObjectId,
    coin_id: ObjectId,
    fee_coin_id: ObjectId,
    fee_asset_id: AssetId,
    max_fee: Amount,
    fee_treasury_object_id: ObjectId,
    gas_limit: u64,
    request_id: RequestId,
    expected_context: ExpectedProtocolContext,
    wait_bounds: Option<ReceiptPollBounds>,
}

fn parse_inputs(parsed: &ParsedArgs) -> Result<BurnInputs, CliError> {
    let module_ref: ObjectRef = transfer::parse_module_ref(parsed)?;
    let treasury_cap_id: ObjectId =
        ObjectId::new(decode_hex_32(TREASURY_CAP, parsed.require(TREASURY_CAP)?)?);
    let coin_id: ObjectId = ObjectId::new(decode_hex_32(COIN, parsed.require(COIN)?)?);
    let fee_coin_id: ObjectId = ObjectId::new(decode_hex_32(FEE_COIN, parsed.require(FEE_COIN)?)?);
    let fee_treasury_object_id: ObjectId = ObjectId::new(decode_hex_32(
        FEE_TREASURY_OBJECT,
        parsed.require(FEE_TREASURY_OBJECT)?,
    )?);
    if treasury_cap_id == coin_id
        || treasury_cap_id == fee_coin_id
        || treasury_cap_id == fee_treasury_object_id
        || coin_id == fee_coin_id
        || coin_id == fee_treasury_object_id
        || fee_coin_id == fee_treasury_object_id
    {
        return Err(CliError::StandardAssetOperationObjectsMustBeDistinct);
    }
    let max_fee_value: u64 = parse_u64(MAX_FEE, parsed.require(MAX_FEE)?)?;
    if max_fee_value == 0 {
        return Err(CliError::ZeroMaxFee);
    }
    let gas_limit: u64 = parse_u64(GAS_LIMIT, parsed.require(GAS_LIMIT)?)?;
    if gas_limit == 0 {
        return Err(CliError::ZeroGasLimit);
    }
    Ok(BurnInputs {
        module_ref,
        treasury_cap_id,
        coin_id,
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
    inputs: BurnInputs,
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
    let (cap_ref, cap) =
        mint::require_owned_current_treasury_cap(client, inputs.treasury_cap_id, sender)?;
    let (coin_ref, coin) =
        transfer::require_owned_current_coin(client, COIN, inputs.coin_id, sender)?;
    let (fee_ref, fee_coin) =
        transfer::require_owned_current_coin(client, FEE_COIN, inputs.fee_coin_id, sender)?;
    if cap.asset_id() != coin.asset_id() || cap.asset_id() != fee_coin.asset_id() {
        return Err(CliError::TreasuryCapAssetMismatch);
    }
    if inputs.fee_asset_id != cap.asset_id() {
        return Err(CliError::FeeAssetMismatch);
    }
    if coin.amount() > cap.total_supply() {
        return Err(CliError::BurnExceedsTotalSupply {
            total_supply: cap.total_supply(),
            amount: coin.amount(),
        });
    }
    let treasury_ref: ObjectRef = transfer::require_current_inline(
        client,
        FEE_TREASURY_OBJECT,
        inputs.fee_treasury_object_id,
    )?;
    let mut access_manifest: AccessManifest = AccessManifest::new();
    access_manifest.push(AccessEntry {
        object_ref: cap_ref,
        mode: AccessMode::Write,
    });
    access_manifest.push(AccessEntry {
        object_ref: coin_ref,
        mode: AccessMode::Consume,
    });
    access_manifest.push(AccessEntry {
        object_ref: fee_ref.clone(),
        mode: AccessMode::Write,
    });
    access_manifest.push(AccessEntry {
        object_ref: treasury_ref,
        mode: AccessMode::Write,
    });
    let request: TransactionRequest = TransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        nonce: nonce_result.next_nonce(),
        access_manifest,
        module_ref: inputs.module_ref,
        entrypoint: BURN_ENTRYPOINT.to_string(),
        args: Vec::new(),
        gas_limit: inputs.gas_limit,
        fee_payment: Some(FeePayment {
            asset_id: inputs.fee_asset_id,
            max_fee: inputs.max_fee,
            fee_object: fee_ref,
        }),
    };
    let prepared: PreparedTransaction = PreparedTransaction::prepare_submission(
        inputs.request_id,
        sender,
        SignatureSchemeId::Ed25519,
        request,
    )?;
    let signed_bytes: Vec<u8> = sign(prepared)?;
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
    use crate::test_support::{FakeTransport, node_result_ok, query_ok};
    use hashing::{BuiltinHashFunction, HashFunction};
    use objects::Owner;
    use protocol_types::HashPurpose;
    use standard_assets::{
        StandardAssetCoinV1, StandardAssetTreasuryCapV1, encode_standard_asset_coin_v1,
        encode_standard_asset_treasury_cap_v1,
    };
    use sunrise_edge_client::{
        AtomicityDomainId, ChainId, Digest32,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, HashAlgorithmId,
        HashSuiteId, HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult,
        HttpObjectQueryResult, NodeResponse, NodeResponseStatus, ProtocolVersion,
    };

    const ASSET: AssetId = AssetId::new([0x50; 32]);

    fn expected_context() -> ExpectedProtocolContext {
        ExpectedProtocolContext::new(
            ChainId::new("burn-test-chain").unwrap(),
            ProtocolVersion::new(6),
            Epoch::new(5),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
        )
        .unwrap()
    }

    fn context() -> HttpContextQueryResult {
        HttpContextQueryResult::new(
            ChainId::new("burn-test-chain").unwrap(),
            ProtocolVersion::new(6),
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

    fn current_inline(object_id: ObjectId, owner: Owner, data: Vec<u8>) -> HttpObjectQueryResult {
        let chain_id: ChainId = ChainId::new("burn-test-chain").unwrap();
        let protocol_version: ProtocolVersion = ProtocolVersion::new(6);
        let object = objects::Object {
            id: object_id,
            version: 1,
            owner,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x09; 32]),
            schema_version: 1,
            data,
        };
        let canonical_object_bytes: Vec<u8> = objects::encode_object(&object).unwrap();
        let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
            .hash(
                HashPurpose::Object,
                protocol_version,
                &chain_id,
                &canonical_object_bytes,
            )
            .unwrap();
        HttpObjectQueryResult::CurrentInline {
            object_id,
            head_revision: runtime::ObjectHeadRevision::new(1).unwrap(),
            object_version: runtime::DurableObjectVersion::new(1).unwrap(),
            digest,
            creating_chain_id: chain_id,
            creating_protocol_version: protocol_version,
            canonical_object_bytes,
        }
    }

    fn inputs() -> BurnInputs {
        BurnInputs {
            module_ref: ObjectRef {
                id: ObjectId::new([0x01; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
            },
            treasury_cap_id: ObjectId::new([0x10; 32]),
            coin_id: ObjectId::new([0x20; 32]),
            fee_coin_id: ObjectId::new([0x30; 32]),
            fee_asset_id: ASSET,
            max_fee: Amount::new(10),
            fee_treasury_object_id: ObjectId::new([0x40; 32]),
            gas_limit: 1_000,
            request_id: RequestId::new([0x50; 32]).unwrap(),
            expected_context: expected_context(),
            wait_bounds: None,
        }
    }

    fn base_args() -> Vec<OsString> {
        vec![
            OsString::from(MODULE_ID),
            OsString::from("01".repeat(32)),
            OsString::from(MODULE_VERSION),
            OsString::from("1"),
            OsString::from(MODULE_DIGEST_ALGORITHM),
            OsString::from("1"),
            OsString::from(MODULE_DIGEST),
            OsString::from("02".repeat(32)),
            OsString::from(TREASURY_CAP),
            OsString::from("10".repeat(32)),
            OsString::from(COIN),
            OsString::from("20".repeat(32)),
            OsString::from(FEE_COIN),
            OsString::from("30".repeat(32)),
            OsString::from(GAS_LIMIT),
            OsString::from("1000"),
            OsString::from(FEE_ASSET_ID),
            OsString::from("50".repeat(32)),
            OsString::from(MAX_FEE),
            OsString::from("10"),
            OsString::from(FEE_TREASURY_OBJECT),
            OsString::from("40".repeat(32)),
            OsString::from(REQUEST_ID),
            OsString::from("60".repeat(32)),
            OsString::from(EXPECTED_CHAIN_ID),
            OsString::from("burn-test-chain"),
            OsString::from(EXPECTED_PROTOCOL_VERSION),
            OsString::from("6"),
            OsString::from(EXPECTED_EPOCH),
            OsString::from("5"),
            OsString::from(EXPECTED_HASH_SUITE_ID),
            OsString::from("1"),
            OsString::from(EXPECTED_DOMAIN),
            OsString::from("44".repeat(32)),
        ]
    }

    #[test]
    fn execute_submits_exact_manifest_and_empty_arguments() {
        let signer: LocalSigner = LocalSigner::from_seed([0x77; 32]);
        let inputs: BurnInputs = inputs();
        let ids: [ObjectId; 4] = [
            inputs.treasury_cap_id,
            inputs.coin_id,
            inputs.fee_coin_id,
            inputs.fee_treasury_object_id,
        ];
        let cap_bytes: Vec<u8> = encode_standard_asset_treasury_cap_v1(
            &StandardAssetTreasuryCapV1::new(ASSET, 500, 1_000).unwrap(),
        )
        .unwrap();
        let coin_bytes: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(ASSET, 25).unwrap()).unwrap();
        let fee_bytes: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(ASSET, 100).unwrap()).unwrap();
        let accepted =
            NodeResponse::new(inputs.request_id, NodeResponseStatus::Accepted, None).unwrap();
        let result: HttpNodeResult =
            HttpNodeResult::new(inputs.request_id, vec![accepted]).unwrap();
        let transport = FakeTransport::new(vec![
            query_ok(context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(ids[0], Owner::Address(signer.address()), cap_bytes)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(ids[1], Owner::Address(signer.address()), coin_bytes)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(ids[2], Owner::Address(signer.address()), fee_bytes)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(ids[3], Owner::System, vec![1])
                    .encode()
                    .unwrap(),
            ),
            node_result_ok(result.encode().unwrap()),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);
        let signer_for_closure: LocalSigner = signer.clone();
        execute(
            &client,
            signer.address(),
            inputs,
            move |prepared: PreparedTransaction| {
                prepared
                    .sign_and_finalize_with(&signer_for_closure)
                    .map_err(CliError::from)
            },
        )
        .unwrap();

        let requests = client.transport().requests();
        let event = node_core::NodeEvent::decode(&requests[6].body).unwrap();
        let transaction = execution::decode_transaction(event.payload()).unwrap();
        assert_eq!(transaction.entrypoint, BURN_ENTRYPOINT);
        assert!(transaction.args.is_empty());
        let modes: [AccessMode; 4] = [
            AccessMode::Write,
            AccessMode::Consume,
            AccessMode::Write,
            AccessMode::Write,
        ];
        for (index, entry) in transaction.access_manifest.entries.iter().enumerate() {
            assert_eq!(entry.object_ref.id, ids[index]);
            assert_eq!(entry.mode, modes[index]);
        }
    }

    #[test]
    fn execute_rejects_asset_mismatch_before_fee_treasury_query_or_signing() {
        let signer: LocalSigner = LocalSigner::from_seed([0x77; 32]);
        let inputs: BurnInputs = inputs();
        let cap_bytes: Vec<u8> = encode_standard_asset_treasury_cap_v1(
            &StandardAssetTreasuryCapV1::new(ASSET, 500, 1_000).unwrap(),
        )
        .unwrap();
        let other_asset: AssetId = AssetId::new([0x51; 32]);
        let coin_bytes: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(other_asset, 25).unwrap())
                .unwrap();
        let fee_bytes: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(ASSET, 100).unwrap()).unwrap();
        let transport = FakeTransport::new(vec![
            query_ok(context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(
                    inputs.treasury_cap_id,
                    Owner::Address(signer.address()),
                    cap_bytes,
                )
                .encode()
                .unwrap(),
            ),
            query_ok(
                current_inline(inputs.coin_id, Owner::Address(signer.address()), coin_bytes)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(
                    inputs.fee_coin_id,
                    Owner::Address(signer.address()),
                    fee_bytes,
                )
                .encode()
                .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);
        let error: CliError = execute(&client, signer.address(), inputs, |_| {
            panic!("asset mismatch must fail before signing")
        })
        .unwrap_err();
        assert!(matches!(error, CliError::TreasuryCapAssetMismatch));
        assert_eq!(client.transport().requests().len(), 5);
    }

    #[test]
    fn execute_rejects_burn_above_total_supply_before_treasury_query_or_signing() {
        let signer: LocalSigner = LocalSigner::from_seed([0x77; 32]);
        let inputs: BurnInputs = inputs();
        let cap_bytes: Vec<u8> = encode_standard_asset_treasury_cap_v1(
            &StandardAssetTreasuryCapV1::new(ASSET, 20, 1_000).unwrap(),
        )
        .unwrap();
        let coin_bytes: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(ASSET, 25).unwrap()).unwrap();
        let fee_bytes: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(ASSET, 100).unwrap()).unwrap();
        let transport = FakeTransport::new(vec![
            query_ok(context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(
                    inputs.treasury_cap_id,
                    Owner::Address(signer.address()),
                    cap_bytes,
                )
                .encode()
                .unwrap(),
            ),
            query_ok(
                current_inline(inputs.coin_id, Owner::Address(signer.address()), coin_bytes)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                current_inline(
                    inputs.fee_coin_id,
                    Owner::Address(signer.address()),
                    fee_bytes,
                )
                .encode()
                .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);
        let error: CliError = execute(&client, signer.address(), inputs, |_| {
            panic!("supply underflow must fail before signing")
        })
        .unwrap_err();
        assert!(matches!(
            error,
            CliError::BurnExceedsTotalSupply {
                total_supply: 20,
                amount: 25,
            }
        ));
        assert_eq!(client.transport().requests().len(), 5);
    }

    #[test]
    fn ledger_selection_is_rejected_before_device_or_network_dispatch() {
        let mut args: Vec<OsString> = base_args();
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
            CliError::LedgerStandardAssetOperationUnsupported { operation: "burn" }
        ));
    }
}
