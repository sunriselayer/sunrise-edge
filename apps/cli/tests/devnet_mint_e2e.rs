//! File-backed protocol-v6/canonical-module-v1 Standard Asset supply-control E2E.
//!
//! This test drives one treasury-cap-authorized mint through the real loopback
//! HTTP router and SQLite durable store. It verifies the seeded authority
//! objects, independently derives the created coin id, and proves replay and
//! request-id conflict handling remain non-reapplying across a real restart.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use execution::{decode_transaction, derive_created_object_id, hash_transaction};
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use standard_assets::{
    STANDARD_ASSET_SCHEMA_VERSION_V1, StandardAssetDefinitionV1, StandardAssetMintArgsV1,
    StandardAssetTreasuryCapV1, decode_standard_asset_definition_v1,
    decode_standard_asset_treasury_cap_v1, derive_coin_type_id, derive_definition_type_id,
    derive_treasury_cap_type_id, encode_standard_asset_mint_args_v1,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Amount, Client, ClientError, ExecutionStatus,
    FeePayment, HttpContextQueryResult, HttpNodeResult, HttpObjectQueryResult,
    HttpReceiptQueryResult, LocalSigner, LoopbackHttpTransport, NodeResponseStatus, Object,
    ObjectId, ObjectRef, Owner, PreparedTransaction, RequestId, SignatureSchemeId,
    StandardAssetCoinV1, SubmitTransactionRequest, TransactionRequest, decode_execution_effects,
    decode_object, decode_standard_asset_coin_v1,
};
use sunrise_edge_devnet::{
    BURN_ENTRYPOINT, DevOwner, DevnetConfig, MINT_ENTRYPOINT, STANDARD_ASSET_MODULE_WASM,
    SeedAssetAuthorityObjectsOutcome, SeedDevOwnerCoinsOutcome, SeedTreasuryCoinOutcome,
    boot_local_store, build_devnet_protocol_context, build_standard_asset_module,
    compose_devnet_router, seed_asset_authority_objects, seed_dev_owner_coins, seed_treasury_coin,
    verify_seeded_asset_supply,
};

const GAS_LIMIT: u64 = 1_000_000;
const MINT_AMOUNT: u64 = 250_000;
const MINT_REQUEST_BYTE: u8 = 0x71;
const BURN_REQUEST_BYTE: u8 = 0x72;

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence: u64 = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-cli-mint-e2e-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored: Result<(), std::io::Error> = fs::remove_dir_all(&self.0);
    }
}

fn make_client(address: SocketAddr) -> Client<LoopbackHttpTransport> {
    let transport: LoopbackHttpTransport = LoopbackHttpTransport::new(
        address,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(1024 * 1024).unwrap(),
    )
    .unwrap();
    Client::new(transport)
}

struct CurrentObject {
    object_ref: ObjectRef,
    object: Object,
    query_bytes: Vec<u8>,
}

fn query_current_object(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> CurrentObject {
    let result: HttpObjectQueryResult = client
        .query_object(object_id)
        .expect("object query should succeed");
    let query_bytes: Vec<u8> = result
        .encode()
        .expect("object result should encode canonically");
    match result {
        HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => {
            let object: Object = decode_object(&canonical_object_bytes)
                .expect("canonical inline object should decode");
            CurrentObject {
                object_ref: ObjectRef {
                    id: object_id,
                    version: object_version.get(),
                    digest,
                },
                object,
                query_bytes,
            }
        }
        other => panic!("expected {object_id} to be CurrentInline, got {other:?}"),
    }
}

fn query_current_coin(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (CurrentObject, StandardAssetCoinV1) {
    let current: CurrentObject = query_current_object(client, object_id);
    let coin: StandardAssetCoinV1 = decode_standard_asset_coin_v1(&current.object.data)
        .expect("object body should decode as Standard Asset v1 coin");
    (current, coin)
}

fn query_object_bytes(client: &Client<LoopbackHttpTransport>, object_id: ObjectId) -> Vec<u8> {
    client
        .query_object(object_id)
        .expect("object query should succeed")
        .encode()
        .expect("object result should encode canonically")
}

fn query_receipt_bytes(
    client: &Client<LoopbackHttpTransport>,
    request_id: RequestId,
) -> (HttpReceiptQueryResult, Vec<u8>) {
    let result: HttpReceiptQueryResult = client
        .query_receipt(request_id)
        .expect("receipt query should succeed");
    let bytes: Vec<u8> = result
        .encode()
        .expect("receipt result should encode canonically");
    (result, bytes)
}

fn submit(
    client: &Client<LoopbackHttpTransport>,
    context: &HttpContextQueryResult,
    request_id: RequestId,
    signed_transaction_bytes: Vec<u8>,
) -> HttpNodeResult {
    let result: HttpNodeResult = client
        .submit_transaction(SubmitTransactionRequest {
            chain_id: context.chain_id().clone(),
            protocol_version: context.protocol_version(),
            epoch: context.epoch(),
            request_id,
            signed_transaction_bytes,
        })
        .expect("transaction submission should succeed");
    assert_eq!(result.responses().len(), 1);
    assert_eq!(result.responses()[0].status(), NodeResponseStatus::Accepted);
    result
}

struct PersistedState {
    definition_bytes: Vec<u8>,
    treasury_cap_bytes: Vec<u8>,
    created_id: ObjectId,
    created_bytes: Vec<u8>,
    fee_bytes: Vec<u8>,
    treasury_bytes: Vec<u8>,
    mint_receipt: HttpReceiptQueryResult,
    mint_receipt_bytes: Vec<u8>,
    burn_receipt: HttpReceiptQueryResult,
    burn_receipt_bytes: Vec<u8>,
    next_nonce: u64,
    mint_result_bytes: Vec<u8>,
    mint_signed_bytes: Vec<u8>,
    burn_result_bytes: Vec<u8>,
    burn_signed_bytes: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mint_is_restart_safe_and_request_id_conflicts_leave_state_unchanged() {
    let signer: LocalSigner = LocalSigner::from_seed([0x41; 32]);
    let sender = signer.address();
    let recipient = sender;
    let treasury = LocalSigner::from_seed([0x42; 32]).address();
    let directory: TestDirectory = TestDirectory::new();
    let config: DevnetConfig = DevnetConfig::parse_from(vec![
        "--data-dir".into(),
        directory.0.as_os_str().to_owned(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        "mint-e2e-devnet".into(),
        "--epoch".into(),
        "17".into(),
        "--dev-owner".into(),
        sender.to_string().into(),
        "--fee-treasury-owner".into(),
        treasury.to_string().into(),
        "--max-concurrent".into(),
        "4".into(),
    ])
    .unwrap();

    let first_boot = boot_local_store(&config).unwrap();
    let first_generation = first_boot.boot_generation();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let asset_id = protocol_context.asset_id();
    let first_module =
        build_standard_asset_module(protocol_context, STANDARD_ASSET_MODULE_WASM.to_vec()).unwrap();
    let hash_resolver = first_module.resolver().clone();
    let module_ref: ObjectRef = first_module.module_ref().clone();

    let deadline_millis: u64 = SystemClock
        .now_unix_millis()
        .unwrap()
        .checked_add(30_000)
        .unwrap();
    let deadline: StorageDeadline = StorageDeadline::new(deadline_millis).unwrap();
    let authority_seed_context: DurableOperationContext = DurableOperationContext::new(
        first_generation,
        deadline,
        StorageCorrelationId::new([0x71; 16]).unwrap(),
    );
    let authority_seed = seed_asset_authority_objects(
        first_boot.store(),
        first_boot.blob_store(),
        first_module.resolver(),
        config.epoch(),
        asset_id,
        DevOwner::new(*sender.as_bytes()),
        config.dev_owners().len(),
        first_generation,
        &authority_seed_context,
    )
    .unwrap();
    let owner_seed_context: DurableOperationContext = DurableOperationContext::new(
        first_generation,
        deadline,
        StorageCorrelationId::new([0x72; 16]).unwrap(),
    );
    let owner_seed = seed_dev_owner_coins(
        first_boot.store(),
        first_boot.blob_store(),
        first_module.resolver(),
        config.epoch(),
        asset_id,
        DevOwner::new(*sender.as_bytes()),
        first_generation,
        &owner_seed_context,
    )
    .unwrap();
    let treasury_seed_context: DurableOperationContext = DurableOperationContext::new(
        first_generation,
        deadline,
        StorageCorrelationId::new([0x73; 16]).unwrap(),
    );
    let treasury_seed = seed_treasury_coin(
        first_boot.store(),
        first_boot.blob_store(),
        first_module.resolver(),
        config.epoch(),
        asset_id,
        config.fee_treasury_owner(),
        first_generation,
        &treasury_seed_context,
    )
    .unwrap();
    verify_seeded_asset_supply(std::slice::from_ref(&owner_seed), &treasury_seed).unwrap();
    let definition_id: ObjectId = authority_seed.objects().definition().id;
    let treasury_cap_id: ObjectId = authority_seed.objects().treasury_cap().id;
    let fee_id: ObjectId = owner_seed.coins().fee_coin().id;
    let treasury_id: ObjectId = treasury_seed.coin().coin().id;

    let (first_structured_store, first_blob_store) = first_boot.into_parts();
    let first_store = Arc::new(first_structured_store);
    let first_blob_store = Arc::new(first_blob_store);
    let first_router = compose_devnet_router(
        Arc::clone(&first_store),
        Arc::clone(&first_blob_store),
        first_module,
        first_generation,
        config.max_concurrent(),
        3,
        treasury_id,
    )
    .unwrap();
    let first_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
    let first_address: SocketAddr = first_listener.local_addr().unwrap();
    let (first_shutdown_tx, first_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let first_server = tokio::spawn(native_http::serve(first_listener, first_router, async {
        let _ignored: Result<(), tokio::sync::oneshot::error::RecvError> = first_shutdown_rx.await;
    }));

    let signer_after_restart: LocalSigner = signer.clone();
    let module_ref_after_restart: ObjectRef = module_ref.clone();
    let mint_request_id: RequestId = RequestId::new([MINT_REQUEST_BYTE; 32]).unwrap();
    let persisted: PersistedState = tokio::task::spawn_blocking(move || {
        let client: Client<LoopbackHttpTransport> = make_client(first_address);
        let context: HttpContextQueryResult = client.query_context().unwrap();

        let definition_before: CurrentObject = query_current_object(&client, definition_id);
        let definition: StandardAssetDefinitionV1 =
            decode_standard_asset_definition_v1(&definition_before.object.data).unwrap();
        assert_eq!(definition.asset_id, asset_id);
        assert_eq!(definition_before.object.owner, Owner::Immutable);
        assert_eq!(definition_before.object.version, 1);
        assert_eq!(
            definition_before.object.type_hash,
            derive_definition_type_id(&hash_resolver, context.epoch(), asset_id).unwrap()
        );
        assert_eq!(
            definition_before.object.schema_version,
            STANDARD_ASSET_SCHEMA_VERSION_V1
        );

        let treasury_cap_before: CurrentObject = query_current_object(&client, treasury_cap_id);
        let treasury_cap: StandardAssetTreasuryCapV1 =
            decode_standard_asset_treasury_cap_v1(&treasury_cap_before.object.data).unwrap();
        assert_eq!(treasury_cap.asset_id(), asset_id);
        assert_eq!(treasury_cap.total_supply(), 2_000_001);
        assert!(treasury_cap.max_supply() > treasury_cap.total_supply());
        assert_eq!(treasury_cap_before.object.owner, Owner::Address(sender));
        assert_eq!(treasury_cap_before.object.version, 1);
        assert_eq!(
            treasury_cap_before.object.type_hash,
            derive_treasury_cap_type_id(&hash_resolver, context.epoch(), asset_id).unwrap()
        );
        assert_eq!(
            treasury_cap_before.object.schema_version,
            STANDARD_ASSET_SCHEMA_VERSION_V1
        );

        let (fee_before_object, fee_before) = query_current_coin(&client, fee_id);
        let (treasury_before_object, treasury_before) = query_current_coin(&client, treasury_id);
        assert_eq!(fee_before_object.object.owner, Owner::Address(sender));
        assert_eq!(
            treasury_before_object.object.owner,
            Owner::Address(treasury)
        );

        let mut manifest: AccessManifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: treasury_cap_before.object_ref.clone(),
            mode: AccessMode::Write,
        });
        manifest.push(AccessEntry {
            object_ref: fee_before_object.object_ref.clone(),
            mode: AccessMode::Write,
        });
        manifest.push(AccessEntry {
            object_ref: treasury_before_object.object_ref,
            mode: AccessMode::Write,
        });
        let mint_args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(MINT_AMOUNT, recipient).unwrap(),
        )
        .unwrap();
        let signed_bytes: Vec<u8> = PreparedTransaction::prepare_submission(
            mint_request_id,
            sender,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: client.query_next_nonce(sender).unwrap().next_nonce(),
                access_manifest: manifest,
                module_ref: module_ref.clone(),
                entrypoint: MINT_ENTRYPOINT.to_string(),
                args: mint_args,
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: fee_before_object.object_ref,
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&signer)
        .unwrap();
        let transaction = decode_transaction(&signed_bytes).unwrap();
        let transaction_hash = hash_transaction(&transaction, &hash_resolver).unwrap();
        let created_id: ObjectId =
            derive_created_object_id(context.protocol_version(), transaction_hash, 0);

        let result: HttpNodeResult =
            submit(&client, &context, mint_request_id, signed_bytes.clone());
        let result_bytes: Vec<u8> = result.encode().unwrap();
        let payload: &[u8] = result.responses()[0]
            .payload()
            .expect("accepted mint should carry execution effects");
        let effects = decode_execution_effects(payload).unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Success));
        assert_eq!(effects.object_effects.len(), 2);

        let definition_after: CurrentObject = query_current_object(&client, definition_id);
        let treasury_cap_after: CurrentObject = query_current_object(&client, treasury_cap_id);
        let treasury_cap_after_body: StandardAssetTreasuryCapV1 =
            decode_standard_asset_treasury_cap_v1(&treasury_cap_after.object.data).unwrap();
        let (created_after_object, created_after) = query_current_coin(&client, created_id);
        let (fee_after_object, fee_after) = query_current_coin(&client, fee_id);
        let (treasury_after_object, treasury_after) = query_current_coin(&client, treasury_id);

        assert_eq!(definition_after.query_bytes, definition_before.query_bytes);
        assert_eq!(treasury_cap_after.object.version, 2);
        assert_eq!(
            treasury_cap_after_body.total_supply(),
            treasury_cap.total_supply() + MINT_AMOUNT
        );
        assert_eq!(
            treasury_cap_after_body.max_supply(),
            treasury_cap.max_supply()
        );
        assert_eq!(created_after_object.object.id, created_id);
        assert_eq!(created_after_object.object.version, 1);
        assert_eq!(created_after_object.object.owner, Owner::Address(recipient));
        assert_eq!(created_after.asset_id(), asset_id);
        assert_eq!(created_after.amount(), MINT_AMOUNT);
        assert_eq!(
            created_after_object.object.type_hash,
            derive_coin_type_id(&hash_resolver, context.epoch(), asset_id).unwrap()
        );
        assert_eq!(
            created_after_object.object.schema_version,
            STANDARD_ASSET_SCHEMA_VERSION_V1
        );

        let charged_fee: u64 = 1_u64.checked_add(effects.gas_used).unwrap();
        assert_eq!(
            fee_after.amount(),
            fee_before.amount().checked_sub(charged_fee).unwrap()
        );
        assert_eq!(
            treasury_after.amount(),
            treasury_before.amount().checked_add(charged_fee).unwrap()
        );
        assert_eq!(fee_after_object.object.owner, Owner::Address(sender));
        assert_eq!(treasury_after_object.object.owner, Owner::Address(treasury));
        assert_eq!(
            fee_after_object.object_ref.version,
            fee_before_object.object.version + 1
        );
        assert_eq!(
            treasury_after_object.object_ref.version,
            treasury_before_object.object.version + 1
        );

        let (mint_receipt, mint_receipt_bytes) = query_receipt_bytes(&client, mint_request_id);
        assert!(matches!(
            mint_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let nonce_after_mint: u64 = client.query_next_nonce(sender).unwrap().next_nonce();
        let replay: HttpNodeResult =
            submit(&client, &context, mint_request_id, signed_bytes.clone());
        assert_eq!(replay.encode().unwrap(), result_bytes);
        assert_eq!(
            query_object_bytes(&client, definition_id),
            definition_after.query_bytes
        );
        assert_eq!(
            query_object_bytes(&client, treasury_cap_id),
            treasury_cap_after.query_bytes
        );
        assert_eq!(
            query_object_bytes(&client, created_id),
            created_after_object.query_bytes
        );
        assert_eq!(
            query_object_bytes(&client, fee_id),
            fee_after_object.query_bytes
        );
        assert_eq!(
            query_object_bytes(&client, treasury_id),
            treasury_after_object.query_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, mint_request_id).1,
            mint_receipt_bytes
        );
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            nonce_after_mint
        );

        let burn_request_id: RequestId = RequestId::new([BURN_REQUEST_BYTE; 32]).unwrap();
        let mut burn_manifest: AccessManifest = AccessManifest::new();
        burn_manifest.push(AccessEntry {
            object_ref: treasury_cap_after.object_ref.clone(),
            mode: AccessMode::Write,
        });
        burn_manifest.push(AccessEntry {
            object_ref: created_after_object.object_ref.clone(),
            mode: AccessMode::Consume,
        });
        burn_manifest.push(AccessEntry {
            object_ref: fee_after_object.object_ref.clone(),
            mode: AccessMode::Write,
        });
        burn_manifest.push(AccessEntry {
            object_ref: treasury_after_object.object_ref.clone(),
            mode: AccessMode::Write,
        });
        let burn_signed_bytes: Vec<u8> = PreparedTransaction::prepare_submission(
            burn_request_id,
            sender,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: nonce_after_mint,
                access_manifest: burn_manifest,
                module_ref: module_ref.clone(),
                entrypoint: BURN_ENTRYPOINT.to_string(),
                args: Vec::new(),
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: fee_after_object.object_ref,
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&signer)
        .unwrap();
        let burn_result: HttpNodeResult = submit(
            &client,
            &context,
            burn_request_id,
            burn_signed_bytes.clone(),
        );
        let burn_result_bytes: Vec<u8> = burn_result.encode().unwrap();
        let burn_effects = decode_execution_effects(
            burn_result.responses()[0]
                .payload()
                .expect("accepted burn should carry execution effects"),
        )
        .unwrap();
        assert!(matches!(burn_effects.status, ExecutionStatus::Success));
        assert_eq!(burn_effects.object_effects.len(), 2);

        let treasury_cap_after_burn: CurrentObject = query_current_object(&client, treasury_cap_id);
        let cap_after_burn: StandardAssetTreasuryCapV1 =
            decode_standard_asset_treasury_cap_v1(&treasury_cap_after_burn.object.data).unwrap();
        assert_eq!(treasury_cap_after_burn.object.version, 3);
        assert_eq!(cap_after_burn.total_supply(), treasury_cap.total_supply());
        assert_eq!(cap_after_burn.max_supply(), treasury_cap.max_supply());
        let burned_result: HttpObjectQueryResult = client.query_object(created_id).unwrap();
        assert!(matches!(
            burned_result,
            HttpObjectQueryResult::Tombstoned { .. }
        ));
        let burned_bytes: Vec<u8> = burned_result.encode().unwrap();
        let (fee_after_burn_object, _) = query_current_coin(&client, fee_id);
        let (treasury_after_burn_object, _) = query_current_coin(&client, treasury_id);
        let (burn_receipt, burn_receipt_bytes) = query_receipt_bytes(&client, burn_request_id);
        assert!(matches!(
            burn_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let next_nonce: u64 = client.query_next_nonce(sender).unwrap().next_nonce();
        assert_eq!(next_nonce, nonce_after_mint + 1);

        let burn_replay: HttpNodeResult = submit(
            &client,
            &context,
            burn_request_id,
            burn_signed_bytes.clone(),
        );
        assert_eq!(burn_replay.encode().unwrap(), burn_result_bytes);
        assert_eq!(
            query_object_bytes(&client, treasury_cap_id),
            treasury_cap_after_burn.query_bytes
        );
        assert_eq!(query_object_bytes(&client, created_id), burned_bytes);
        assert_eq!(
            query_object_bytes(&client, fee_id),
            fee_after_burn_object.query_bytes
        );
        assert_eq!(
            query_object_bytes(&client, treasury_id),
            treasury_after_burn_object.query_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, burn_request_id).1,
            burn_receipt_bytes
        );
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            next_nonce
        );

        PersistedState {
            definition_bytes: definition_after.query_bytes,
            treasury_cap_bytes: treasury_cap_after_burn.query_bytes,
            created_id,
            created_bytes: burned_bytes,
            fee_bytes: fee_after_burn_object.query_bytes,
            treasury_bytes: treasury_after_burn_object.query_bytes,
            mint_receipt,
            mint_receipt_bytes,
            burn_receipt,
            burn_receipt_bytes,
            next_nonce,
            mint_result_bytes: result_bytes,
            mint_signed_bytes: signed_bytes,
            burn_result_bytes,
            burn_signed_bytes,
        }
    })
    .await
    .unwrap();

    first_shutdown_tx.send(()).unwrap();
    first_server.await.unwrap().unwrap();
    drop(Arc::try_unwrap(first_store).unwrap());
    drop(Arc::try_unwrap(first_blob_store).unwrap());

    let second_boot = boot_local_store(&config).unwrap();
    let second_generation = second_boot.boot_generation();
    assert_eq!(second_generation.get(), first_generation.get() + 1);
    let second_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let second_module =
        build_standard_asset_module(second_context, STANDARD_ASSET_MODULE_WASM.to_vec()).unwrap();
    let second_deadline_millis: u64 = SystemClock
        .now_unix_millis()
        .unwrap()
        .checked_add(30_000)
        .unwrap();
    let second_deadline: StorageDeadline = StorageDeadline::new(second_deadline_millis).unwrap();
    let second_authority_seed: SeedAssetAuthorityObjectsOutcome = seed_asset_authority_objects(
        second_boot.store(),
        second_boot.blob_store(),
        second_module.resolver(),
        config.epoch(),
        asset_id,
        DevOwner::new(*sender.as_bytes()),
        config.dev_owners().len(),
        second_generation,
        &DurableOperationContext::new(
            second_generation,
            second_deadline,
            StorageCorrelationId::new([0x74; 16]).unwrap(),
        ),
    )
    .unwrap();
    assert!(matches!(
        &second_authority_seed,
        SeedAssetAuthorityObjectsOutcome::Existing(_)
    ));
    assert_eq!(
        second_authority_seed.objects().definition().id,
        definition_id
    );
    assert_eq!(
        second_authority_seed.objects().treasury_cap().id,
        treasury_cap_id
    );
    let second_owner_seed: SeedDevOwnerCoinsOutcome = seed_dev_owner_coins(
        second_boot.store(),
        second_boot.blob_store(),
        second_module.resolver(),
        config.epoch(),
        asset_id,
        DevOwner::new(*sender.as_bytes()),
        second_generation,
        &DurableOperationContext::new(
            second_generation,
            second_deadline,
            StorageCorrelationId::new([0x75; 16]).unwrap(),
        ),
    )
    .unwrap();
    assert!(matches!(
        &second_owner_seed,
        SeedDevOwnerCoinsOutcome::Existing(_)
    ));
    let second_treasury_seed: SeedTreasuryCoinOutcome = seed_treasury_coin(
        second_boot.store(),
        second_boot.blob_store(),
        second_module.resolver(),
        config.epoch(),
        asset_id,
        config.fee_treasury_owner(),
        second_generation,
        &DurableOperationContext::new(
            second_generation,
            second_deadline,
            StorageCorrelationId::new([0x76; 16]).unwrap(),
        ),
    )
    .unwrap();
    assert!(matches!(
        &second_treasury_seed,
        SeedTreasuryCoinOutcome::Existing(_)
    ));
    verify_seeded_asset_supply(
        std::slice::from_ref(&second_owner_seed),
        &second_treasury_seed,
    )
    .unwrap();
    let (second_structured_store, second_blob_store) = second_boot.into_parts();
    let second_store = Arc::new(second_structured_store);
    let second_blob_store = Arc::new(second_blob_store);
    let second_router = compose_devnet_router(
        Arc::clone(&second_store),
        Arc::clone(&second_blob_store),
        second_module,
        second_generation,
        config.max_concurrent(),
        3,
        treasury_id,
    )
    .unwrap();
    let second_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
    let second_address: SocketAddr = second_listener.local_addr().unwrap();
    let (second_shutdown_tx, second_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let second_server = tokio::spawn(native_http::serve(second_listener, second_router, async {
        let _ignored: Result<(), tokio::sync::oneshot::error::RecvError> = second_shutdown_rx.await;
    }));

    tokio::task::spawn_blocking(move || {
        let client: Client<LoopbackHttpTransport> = make_client(second_address);
        let context: HttpContextQueryResult = client.query_context().unwrap();
        assert_eq!(
            query_object_bytes(&client, definition_id),
            persisted.definition_bytes
        );
        assert_eq!(
            query_object_bytes(&client, treasury_cap_id),
            persisted.treasury_cap_bytes
        );
        assert_eq!(
            query_object_bytes(&client, persisted.created_id),
            persisted.created_bytes
        );
        assert_eq!(query_object_bytes(&client, fee_id), persisted.fee_bytes);
        assert_eq!(
            query_object_bytes(&client, treasury_id),
            persisted.treasury_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, mint_request_id).0,
            persisted.mint_receipt
        );
        assert_eq!(
            query_receipt_bytes(&client, mint_request_id).1,
            persisted.mint_receipt_bytes
        );
        let burn_request_id: RequestId = RequestId::new([BURN_REQUEST_BYTE; 32]).unwrap();
        assert_eq!(
            query_receipt_bytes(&client, burn_request_id).0,
            persisted.burn_receipt
        );
        assert_eq!(
            query_receipt_bytes(&client, burn_request_id).1,
            persisted.burn_receipt_bytes
        );
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            persisted.next_nonce
        );

        let replay: HttpNodeResult = submit(
            &client,
            &context,
            mint_request_id,
            persisted.mint_signed_bytes.clone(),
        );
        assert_eq!(replay.encode().unwrap(), persisted.mint_result_bytes);
        let burn_replay: HttpNodeResult = submit(
            &client,
            &context,
            burn_request_id,
            persisted.burn_signed_bytes.clone(),
        );
        assert_eq!(burn_replay.encode().unwrap(), persisted.burn_result_bytes);

        let treasury_cap_current: CurrentObject = query_current_object(&client, treasury_cap_id);
        let (fee_current_object, _) = query_current_coin(&client, fee_id);
        let (treasury_current_object, _) = query_current_coin(&client, treasury_id);
        let mut conflicting_manifest: AccessManifest = AccessManifest::new();
        conflicting_manifest.push(AccessEntry {
            object_ref: treasury_cap_current.object_ref,
            mode: AccessMode::Write,
        });
        conflicting_manifest.push(AccessEntry {
            object_ref: fee_current_object.object_ref.clone(),
            mode: AccessMode::Write,
        });
        conflicting_manifest.push(AccessEntry {
            object_ref: treasury_current_object.object_ref,
            mode: AccessMode::Write,
        });
        let conflicting_args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(MINT_AMOUNT + 1, recipient).unwrap(),
        )
        .unwrap();
        let conflicting_signed_bytes: Vec<u8> = PreparedTransaction::prepare_submission(
            mint_request_id,
            sender,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: persisted.next_nonce,
                access_manifest: conflicting_manifest,
                module_ref: module_ref_after_restart,
                entrypoint: MINT_ENTRYPOINT.to_string(),
                args: conflicting_args,
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: fee_current_object.object_ref,
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&signer_after_restart)
        .unwrap();
        let error: ClientError = client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: mint_request_id,
                signed_transaction_bytes: conflicting_signed_bytes,
            })
            .expect_err("reusing the mint request id for different signed bytes must fail");
        assert!(matches!(
            error,
            ClientError::UnexpectedStatus { status: 409, .. }
        ));

        assert_eq!(
            query_object_bytes(&client, definition_id),
            persisted.definition_bytes
        );
        assert_eq!(
            query_object_bytes(&client, treasury_cap_id),
            persisted.treasury_cap_bytes
        );
        assert_eq!(
            query_object_bytes(&client, persisted.created_id),
            persisted.created_bytes
        );
        assert_eq!(query_object_bytes(&client, fee_id), persisted.fee_bytes);
        assert_eq!(
            query_object_bytes(&client, treasury_id),
            persisted.treasury_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, mint_request_id).1,
            persisted.mint_receipt_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, burn_request_id).1,
            persisted.burn_receipt_bytes
        );
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            persisted.next_nonce
        );
    })
    .await
    .unwrap();

    second_shutdown_tx.send(()).unwrap();
    second_server.await.unwrap().unwrap();
    drop(Arc::try_unwrap(second_store).unwrap());
    drop(Arc::try_unwrap(second_blob_store).unwrap());
}
