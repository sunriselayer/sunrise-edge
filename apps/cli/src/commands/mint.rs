//! `mint`: authorized Standard Asset v1 issuance on the local devnet.
//!
//! The command requires an explicit sender-owned treasury cap and fee
//! coin. Before signing, it verifies the expected protocol context and nonce,
//! queries and strictly decodes both objects, and requires the treasury cap,
//! fee coin, and signed fee payment to identify one `AssetId`. The submitted
//! manifest is fixed to treasury cap `Write` index 0, fee coin `Write` index 1,
//! and the trusted treasury `Write` as the final entry.

use std::ffi::OsString;

use standard_assets::{
    StandardAssetMintArgsV1, StandardAssetTreasuryCapV1, decode_standard_asset_treasury_cap_v1,
    encode_standard_asset_mint_args_v1,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Amount, AssetId, Client,
    ExpectedProtocolContext, FeePayment, LocalSigner, ObjectId, ObjectRef, Owner,
    PreparedTransaction, ReceiptPollBounds, RequestId, SignatureSchemeId, TransactionRequest,
    Transport, decode_object,
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
const TREASURY_CAP: &str = "--treasury-cap";
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
const MINT_ENTRYPOINT: &str = "mint";

/// Runs the authorized mint command.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs: Vec<crate::args::FlagSpec> = mint_flag_specs();
    specs.extend(tls_flag_specs());
    specs.extend(signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let endpoint: &str = parsed.require(ENDPOINT)?;
    let inputs: MintInputs = parse_inputs(&parsed)?;

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
            operation: MINT_ENTRYPOINT,
        }),
    }
}

fn mint_flag_specs() -> Vec<crate::args::FlagSpec> {
    vec![
        scalar(ENDPOINT),
        scalar(MODULE_ID),
        scalar(MODULE_VERSION),
        scalar(MODULE_DIGEST_ALGORITHM),
        scalar(MODULE_DIGEST),
        scalar(TREASURY_CAP),
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

struct MintInputs {
    module_ref: ObjectRef,
    treasury_cap_id: ObjectId,
    recipient: Address,
    amount: u64,
    fee_coin_id: ObjectId,
    fee_asset_id: AssetId,
    max_fee: Amount,
    fee_treasury_object_id: ObjectId,
    gas_limit: u64,
    request_id: RequestId,
    expected_context: ExpectedProtocolContext,
    wait_bounds: Option<ReceiptPollBounds>,
}

fn parse_inputs(parsed: &ParsedArgs) -> Result<MintInputs, CliError> {
    let module_ref: ObjectRef = transfer::parse_module_ref(parsed)?;
    let treasury_cap_id: ObjectId =
        ObjectId::new(decode_hex_32(TREASURY_CAP, parsed.require(TREASURY_CAP)?)?);
    let recipient: Address = Address::new(decode_hex_32(RECIPIENT, parsed.require(RECIPIENT)?)?);
    let amount: u64 = parse_u64(AMOUNT, parsed.require(AMOUNT)?)?;
    if amount == 0 {
        return Err(CliError::ZeroMintAmount);
    }
    let fee_coin_id: ObjectId = ObjectId::new(decode_hex_32(FEE_COIN, parsed.require(FEE_COIN)?)?);
    let fee_treasury_object_id: ObjectId = ObjectId::new(decode_hex_32(
        FEE_TREASURY_OBJECT,
        parsed.require(FEE_TREASURY_OBJECT)?,
    )?);
    if treasury_cap_id == fee_coin_id
        || treasury_cap_id == fee_treasury_object_id
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

    Ok(MintInputs {
        module_ref,
        treasury_cap_id,
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
    inputs: MintInputs,
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

    let (treasury_cap_ref, treasury_cap): (ObjectRef, StandardAssetTreasuryCapV1) =
        require_owned_current_treasury_cap(client, inputs.treasury_cap_id, sender)?;
    let new_total_supply: u64 = treasury_cap
        .total_supply()
        .checked_add(inputs.amount)
        .ok_or(CliError::MintSupplyOverflow)?;
    if new_total_supply > treasury_cap.max_supply() {
        return Err(CliError::MintExceedsMaxSupply {
            total_supply: treasury_cap.total_supply(),
            amount: inputs.amount,
            max_supply: treasury_cap.max_supply(),
        });
    }
    let (fee_ref, fee_coin) =
        transfer::require_owned_current_coin(client, FEE_COIN, inputs.fee_coin_id, sender)?;
    if treasury_cap.asset_id() != fee_coin.asset_id() {
        return Err(CliError::TreasuryCapAssetMismatch);
    }
    if inputs.fee_asset_id != treasury_cap.asset_id() {
        return Err(CliError::FeeAssetMismatch);
    }
    let treasury_ref: ObjectRef = transfer::require_current_inline(
        client,
        FEE_TREASURY_OBJECT,
        inputs.fee_treasury_object_id,
    )?;

    let mut access_manifest: AccessManifest = AccessManifest::new();
    access_manifest.push(AccessEntry {
        object_ref: treasury_cap_ref,
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

    let mint_args: StandardAssetMintArgsV1 =
        StandardAssetMintArgsV1::new(inputs.amount, inputs.recipient)
            .map_err(CliError::MintArgsEncodingFailed)?;
    let args: Vec<u8> =
        encode_standard_asset_mint_args_v1(&mint_args).map_err(CliError::MintArgsEncodingFailed)?;
    let request = TransactionRequest {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        nonce: nonce_result.next_nonce(),
        access_manifest,
        module_ref: inputs.module_ref,
        entrypoint: MINT_ENTRYPOINT.to_string(),
        args,
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

pub(super) fn require_owned_current_treasury_cap<T>(
    client: &Client<T>,
    object_id: ObjectId,
    expected_owner: Address,
) -> Result<(ObjectRef, StandardAssetTreasuryCapV1), CliError>
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
        sunrise_edge_client::HttpObjectQueryResult::Absent { .. } => {
            return Err(CliError::ObjectNotCurrentlyInline {
                flag: TREASURY_CAP,
                object_id: object_id.to_string(),
                status: "absent",
            });
        }
        sunrise_edge_client::HttpObjectQueryResult::Tombstoned { .. } => {
            return Err(CliError::ObjectNotCurrentlyInline {
                flag: TREASURY_CAP,
                object_id: object_id.to_string(),
                status: "tombstoned",
            });
        }
        sunrise_edge_client::HttpObjectQueryResult::HistoricalCurrentInline { .. } => {
            return Err(CliError::ObjectNotCurrentlyInline {
                flag: TREASURY_CAP,
                object_id: object_id.to_string(),
                status: "historical_current_inline_unverified",
            });
        }
        sunrise_edge_client::HttpObjectQueryResult::CurrentBlobReference { .. } => {
            return Err(CliError::ObjectNotCurrentlyInline {
                flag: TREASURY_CAP,
                object_id: object_id.to_string(),
                status: "current_blob_reference",
            });
        }
    };
    let object = decode_object(canonical_object_bytes).map_err(|source| {
        CliError::ObjectBodyDecodeFailed {
            flag: TREASURY_CAP,
            object_id: object_id.to_string(),
            source,
        }
    })?;
    match &object.owner {
        Owner::Address(owner) if *owner == expected_owner => {}
        owner => {
            let owner_label: String = match owner {
                Owner::Address(address) => format!("address:{address}"),
                Owner::Shared => "shared".to_string(),
                Owner::Immutable => "immutable".to_string(),
                Owner::System => "system".to_string(),
            };
            return Err(CliError::ObjectOwnerMismatch {
                flag: TREASURY_CAP,
                object_id: object_id.to_string(),
                expected_owner: expected_owner.to_string(),
                owner: owner_label,
            });
        }
    }
    let treasury_cap: StandardAssetTreasuryCapV1 =
        decode_standard_asset_treasury_cap_v1(&object.data).map_err(|source| {
            CliError::TreasuryCapBodyDecodeFailed {
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
        treasury_cap,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeTransport, node_result_ok, query_ok};
    use hashing::{BuiltinHashFunction, HashFunction};
    use protocol_types::HashPurpose;
    use standard_assets::{
        StandardAssetCoinV1, encode_standard_asset_coin_v1, encode_standard_asset_treasury_cap_v1,
    };
    use sunrise_edge_client::{
        AtomicityDomainId, ChainId, Digest32,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, HashAlgorithmId,
        HashSuiteId, HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult,
        HttpObjectQueryResult, NodeResponse, NodeResponseStatus, ProtocolVersion,
        QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH,
    };

    const ASSET: AssetId = AssetId::new([0x50; 32]);

    fn sample_signer() -> LocalSigner {
        LocalSigner::from_seed([0x77; 32])
    }

    fn sample_expected_context() -> ExpectedProtocolContext {
        ExpectedProtocolContext::new(
            ChainId::new("mint-test-chain").unwrap(),
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

    fn sample_inputs() -> MintInputs {
        MintInputs {
            module_ref: ObjectRef {
                id: ObjectId::new([0x01; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
            },
            treasury_cap_id: ObjectId::new([0x10; 32]),
            recipient: Address::new([0x88; 32]),
            amount: 25,
            fee_coin_id: ObjectId::new([0x20; 32]),
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
            ChainId::new("mint-test-chain").unwrap(),
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

    fn current_inline_with_owner(
        object_id: ObjectId,
        version: u64,
        owner: Owner,
        data: Vec<u8>,
    ) -> HttpObjectQueryResult {
        let creating_chain_id: ChainId = ChainId::new("mint-test-chain").unwrap();
        let creating_protocol_version: ProtocolVersion = ProtocolVersion::new(6);
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

    fn treasury_cap_owned_by(
        object_id: ObjectId,
        owner: Address,
        asset_id: AssetId,
    ) -> HttpObjectQueryResult {
        treasury_cap_with_supply(object_id, owner, asset_id, 100, 1_000)
    }

    fn treasury_cap_with_supply(
        object_id: ObjectId,
        owner: Address,
        asset_id: AssetId,
        total_supply: u64,
        max_supply: u64,
    ) -> HttpObjectQueryResult {
        let treasury_cap: StandardAssetTreasuryCapV1 =
            StandardAssetTreasuryCapV1::new(asset_id, total_supply, max_supply).unwrap();
        current_inline_with_owner(
            object_id,
            1,
            Owner::Address(owner),
            encode_standard_asset_treasury_cap_v1(&treasury_cap).unwrap(),
        )
    }

    fn coin_owned_by(
        object_id: ObjectId,
        owner: Address,
        asset_id: AssetId,
    ) -> HttpObjectQueryResult {
        let coin = StandardAssetCoinV1::new(asset_id, 500).unwrap();
        current_inline_with_owner(
            object_id,
            1,
            Owner::Address(owner),
            encode_standard_asset_coin_v1(&coin).unwrap(),
        )
    }

    fn sign_locally(
        signer: &LocalSigner,
    ) -> impl FnOnce(PreparedTransaction) -> Result<Vec<u8>, CliError> {
        let signer: LocalSigner = signer.clone();
        move |prepared: PreparedTransaction| {
            prepared
                .sign_and_finalize_with(&signer)
                .map_err(CliError::from)
        }
    }

    fn fail_if_sign_called(_: PreparedTransaction) -> Result<Vec<u8>, CliError> {
        panic!("rejected mint must not be signed")
    }

    #[test]
    fn execute_submits_exact_mint_manifest_and_arguments() {
        let signer: LocalSigner = sample_signer();
        let inputs: MintInputs = sample_inputs();
        let expected_request_id: RequestId = inputs.request_id;
        let expected_treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let expected_fee_coin_id: ObjectId = inputs.fee_coin_id;
        let expected_treasury_id: ObjectId = inputs.fee_treasury_object_id;
        let context: HttpContextQueryResult = sample_context();
        let nonce = HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3);
        let treasury_cap: HttpObjectQueryResult =
            treasury_cap_owned_by(expected_treasury_cap_id, signer.address(), ASSET);
        let fee: HttpObjectQueryResult =
            coin_owned_by(expected_fee_coin_id, signer.address(), ASSET);
        let treasury: HttpObjectQueryResult =
            current_inline_with_owner(expected_treasury_id, 1, Owner::System, vec![0x01]);
        let accepted =
            NodeResponse::new(expected_request_id, NodeResponseStatus::Accepted, None).unwrap();
        let submit: HttpNodeResult =
            HttpNodeResult::new(expected_request_id, vec![accepted]).unwrap();
        let transport = FakeTransport::new(vec![
            query_ok(context.encode().unwrap()),
            query_ok(nonce.encode().unwrap()),
            query_ok(treasury_cap.encode().unwrap()),
            query_ok(fee.encode().unwrap()),
            query_ok(treasury.encode().unwrap()),
            node_result_ok(submit.encode().unwrap()),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        execute(&client, signer.address(), inputs, sign_locally(&signer)).unwrap();

        let requests = client.transport().requests();
        assert_eq!(requests.len(), 6);
        assert_eq!(requests[0].path, "/v1/context");
        assert_eq!(
            requests[1].path,
            QUERY_NEXT_NONCE_PATH.replace("{sender}", &signer.address().to_string())
        );
        assert_eq!(
            requests[2].path,
            QUERY_OBJECT_PATH.replace("{object_id}", &expected_treasury_cap_id.to_string())
        );
        assert_eq!(
            requests[3].path,
            QUERY_OBJECT_PATH.replace("{object_id}", &expected_fee_coin_id.to_string())
        );
        let submitted_event = node_core::NodeEvent::decode(&requests[5].body).unwrap();
        let transaction = execution::decode_transaction(submitted_event.payload()).unwrap();
        assert_eq!(transaction.entrypoint, MINT_ENTRYPOINT);
        assert_eq!(transaction.nonce, 3);
        assert_eq!(transaction.access_manifest.entries.len(), 3);
        assert_eq!(
            transaction.access_manifest.entries[0].object_ref.id,
            expected_treasury_cap_id
        );
        assert_eq!(
            transaction.access_manifest.entries[0].mode,
            AccessMode::Write
        );
        assert_eq!(
            transaction.access_manifest.entries[1].object_ref.id,
            expected_fee_coin_id
        );
        assert_eq!(
            transaction.access_manifest.entries[1].mode,
            AccessMode::Write
        );
        assert_eq!(
            transaction.access_manifest.entries[2].object_ref.id,
            expected_treasury_id
        );
        assert_eq!(
            transaction.access_manifest.entries[2].mode,
            AccessMode::Write
        );
        let expected_args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(25, Address::new([0x88; 32])).unwrap(),
        )
        .unwrap();
        assert_eq!(transaction.args, expected_args);
        let payment: FeePayment = transaction.fee_payment.unwrap();
        assert_eq!(payment.asset_id, ASSET);
        assert_eq!(payment.fee_object.id, expected_fee_coin_id);
    }

    #[test]
    fn execute_rejects_treasury_cap_owner_mismatch_before_fee_query_or_signing() {
        let signer: LocalSigner = sample_signer();
        let inputs: MintInputs = sample_inputs();
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let other_owner: Address = Address::new([0x99; 32]);
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                treasury_cap_owned_by(treasury_cap_id, other_owner, ASSET)
                    .encode()
                    .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(
            error,
            CliError::ObjectOwnerMismatch {
                flag: TREASURY_CAP,
                owner,
                ..
            } if owner == format!("address:{other_owner}")
        ));
        assert_eq!(client.transport().requests().len(), 3);
    }

    #[test]
    fn execute_rejects_supply_overflow_before_fee_query_or_signing() {
        let signer: LocalSigner = sample_signer();
        let mut inputs: MintInputs = sample_inputs();
        inputs.amount = 2;
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                treasury_cap_with_supply(
                    treasury_cap_id,
                    signer.address(),
                    ASSET,
                    u64::MAX - 1,
                    u64::MAX,
                )
                .encode()
                .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(error, CliError::MintSupplyOverflow));
        assert_eq!(client.transport().requests().len(), 3);
    }

    #[test]
    fn execute_rejects_amount_above_max_supply_before_fee_query_or_signing() {
        let signer: LocalSigner = sample_signer();
        let inputs: MintInputs = sample_inputs();
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                treasury_cap_with_supply(treasury_cap_id, signer.address(), ASSET, 990, 1_000)
                    .encode()
                    .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(
            error,
            CliError::MintExceedsMaxSupply {
                total_supply: 990,
                amount: 25,
                max_supply: 1_000,
            }
        ));
        assert_eq!(client.transport().requests().len(), 3);
    }

    #[test]
    fn execute_rejects_treasury_cap_and_fee_asset_mismatch() {
        let signer: LocalSigner = sample_signer();
        let inputs: MintInputs = sample_inputs();
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let fee_coin_id: ObjectId = inputs.fee_coin_id;
        let other_asset: AssetId = AssetId::new([0x51; 32]);
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                treasury_cap_owned_by(treasury_cap_id, signer.address(), ASSET)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                coin_owned_by(fee_coin_id, signer.address(), other_asset)
                    .encode()
                    .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(error, CliError::TreasuryCapAssetMismatch));
    }

    #[test]
    fn execute_rejects_a_non_treasury_cap_body_before_fee_query_or_signing() {
        let signer: LocalSigner = sample_signer();
        let inputs: MintInputs = sample_inputs();
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let wrong_body: Vec<u8> =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(ASSET, 1).unwrap()).unwrap();
        let not_a_treasury_cap: HttpObjectQueryResult = current_inline_with_owner(
            treasury_cap_id,
            1,
            Owner::Address(signer.address()),
            wrong_body,
        );
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(not_a_treasury_cap.encode().unwrap()),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(
            error,
            CliError::TreasuryCapBodyDecodeFailed { .. }
        ));
        assert_eq!(client.transport().requests().len(), 3);
    }

    #[test]
    fn execute_rejects_fee_asset_flag_mismatch_before_treasury_query_or_signing() {
        let signer: LocalSigner = sample_signer();
        let mut inputs: MintInputs = sample_inputs();
        inputs.fee_asset_id = AssetId::new([0x51; 32]);
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let fee_coin_id: ObjectId = inputs.fee_coin_id;
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                treasury_cap_owned_by(treasury_cap_id, signer.address(), ASSET)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                coin_owned_by(fee_coin_id, signer.address(), ASSET)
                    .encode()
                    .unwrap(),
            ),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(error, CliError::FeeAssetMismatch));
        assert_eq!(client.transport().requests().len(), 4);
    }

    #[test]
    fn execute_rejects_a_non_coin_fee_body_before_treasury_query_or_signing() {
        let signer: LocalSigner = sample_signer();
        let inputs: MintInputs = sample_inputs();
        let treasury_cap_id: ObjectId = inputs.treasury_cap_id;
        let fee_coin_id: ObjectId = inputs.fee_coin_id;
        let treasury_cap_body: Vec<u8> = encode_standard_asset_treasury_cap_v1(
            &StandardAssetTreasuryCapV1::new(ASSET, 100, 1_000).unwrap(),
        )
        .unwrap();
        let not_a_coin: HttpObjectQueryResult = current_inline_with_owner(
            fee_coin_id,
            1,
            Owner::Address(signer.address()),
            treasury_cap_body,
        );
        let transport = FakeTransport::new(vec![
            query_ok(sample_context().encode().unwrap()),
            query_ok(
                HttpNextNonceQueryResult::new(signer.address(), Epoch::new(5), 3)
                    .encode()
                    .unwrap(),
            ),
            query_ok(
                treasury_cap_owned_by(treasury_cap_id, signer.address(), ASSET)
                    .encode()
                    .unwrap(),
            ),
            query_ok(not_a_coin.encode().unwrap()),
        ]);
        let client: Client<FakeTransport> = Client::new(transport);

        let error: CliError =
            execute(&client, signer.address(), inputs, fail_if_sign_called).unwrap_err();
        assert!(matches!(
            error,
            CliError::CoinBodyDecodeFailed { flag: FEE_COIN, .. }
        ));
        assert_eq!(client.transport().requests().len(), 4);
    }

    fn base_args(amount: &str) -> Vec<OsString> {
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
            OsString::from(RECIPIENT),
            OsString::from("88".repeat(32)),
            OsString::from(AMOUNT),
            OsString::from(amount),
            OsString::from(FEE_COIN),
            OsString::from("20".repeat(32)),
            OsString::from(GAS_LIMIT),
            OsString::from("1000"),
            OsString::from(FEE_ASSET_ID),
            OsString::from("50".repeat(32)),
            OsString::from(MAX_FEE),
            OsString::from("10"),
            OsString::from(FEE_TREASURY_OBJECT),
            OsString::from("40".repeat(32)),
            OsString::from(REQUEST_ID),
            OsString::from("30".repeat(32)),
            OsString::from(EXPECTED_CHAIN_ID),
            OsString::from("mint-test-chain"),
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
    fn parser_rejects_zero_amount_before_network_use() {
        let parsed: ParsedArgs = parse_flags(base_args("0"), &mint_flag_specs()).unwrap();
        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::ZeroMintAmount)
        ));
    }

    #[test]
    fn parser_rejects_zero_gas_and_max_fee_before_network_use() {
        let mut zero_gas_args: Vec<OsString> = base_args("25");
        let gas_index: usize = zero_gas_args
            .iter()
            .position(|value: &OsString| value == GAS_LIMIT)
            .unwrap()
            + 1;
        zero_gas_args[gas_index] = OsString::from("0");
        let parsed: ParsedArgs = parse_flags(zero_gas_args, &mint_flag_specs()).unwrap();
        assert!(matches!(parse_inputs(&parsed), Err(CliError::ZeroGasLimit)));

        let mut zero_fee_args: Vec<OsString> = base_args("25");
        let fee_index: usize = zero_fee_args
            .iter()
            .position(|value: &OsString| value == MAX_FEE)
            .unwrap()
            + 1;
        zero_fee_args[fee_index] = OsString::from("0");
        let parsed: ParsedArgs = parse_flags(zero_fee_args, &mint_flag_specs()).unwrap();
        assert!(matches!(parse_inputs(&parsed), Err(CliError::ZeroMaxFee)));
    }

    #[test]
    fn parser_rejects_non_distinct_operation_objects() {
        let mut args: Vec<OsString> = base_args("25");
        let treasury_value_index: usize = args
            .iter()
            .position(|value: &OsString| value == FEE_TREASURY_OBJECT)
            .unwrap()
            + 1;
        args[treasury_value_index] = OsString::from("10".repeat(32));
        let parsed: ParsedArgs = parse_flags(args, &mint_flag_specs()).unwrap();
        assert!(matches!(
            parse_inputs(&parsed),
            Err(CliError::StandardAssetOperationObjectsMustBeDistinct)
        ));
    }

    #[test]
    fn ledger_selection_is_rejected_before_device_or_network_dispatch() {
        let mut args: Vec<OsString> = base_args("25");
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
            CliError::LedgerStandardAssetOperationUnsupported { operation: "mint" }
        ));
    }
}
