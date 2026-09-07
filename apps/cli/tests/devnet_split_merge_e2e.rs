//! File-backed canonical Standard Asset module-v1 split/merge E2E.
//!
//! This test drives signed transactions through the real loopback HTTP router
//! and SQLite durable store. It independently derives the split-created object
//! id, proves checked value movement and merge consumption, then closes and
//! reopens the database to verify exact replay reconciliation and request-id
//! conflict handling do not reapply either operation.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use execution::{decode_transaction, derive_created_object_id, hash_transaction};
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use standard_assets::{StandardAssetSplitArgsV1, encode_standard_asset_split_args_v1};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Amount, Client, ClientError, FeePayment,
    HttpContextQueryResult, HttpNodeResult, HttpObjectQueryResult, HttpReceiptQueryResult,
    LocalSigner, LoopbackHttpTransport, NodeResponseStatus, ObjectId, ObjectRef, Owner,
    PreparedTransaction, RequestId, SignatureSchemeId, StandardAssetCoinV1,
    StandardAssetTransferArgsV1, SubmitTransactionRequest, TransactionRequest, decode_object,
    decode_standard_asset_coin_v1, encode_standard_asset_transfer_args_v1,
};
use sunrise_edge_devnet::{
    DevOwner, DevnetConfig, MERGE_ENTRYPOINT, SPLIT_ENTRYPOINT, STANDARD_ASSET_MODULE_WASM,
    TRANSFER_ENTRYPOINT, boot_local_store, build_devnet_protocol_context,
    build_standard_asset_module, compose_devnet_router, seed_dev_owner_coins, seed_treasury_coin,
    verify_seeded_asset_supply,
};

const GAS_LIMIT: u64 = 1_000_000;
const SPLIT_AMOUNT: u64 = 250_000;
const SPLIT_REQUEST_BYTE: u8 = 0x61;
const MERGE_REQUEST_BYTE: u8 = 0x62;

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence: u64 = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-cli-split-merge-e2e-{}-{sequence}",
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

fn query_current_coin(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (ObjectRef, StandardAssetCoinV1, Owner, Vec<u8>) {
    let result: HttpObjectQueryResult = client
        .query_object(object_id)
        .expect("object query should succeed");
    let result_bytes: Vec<u8> = result
        .encode()
        .expect("object result should encode canonically");
    match result {
        HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => {
            let object = decode_object(&canonical_object_bytes)
                .expect("canonical inline object should decode");
            let coin: StandardAssetCoinV1 = decode_standard_asset_coin_v1(&object.data)
                .expect("object body should decode as Standard Asset v1");
            (
                ObjectRef {
                    id: object_id,
                    version: object_version.get(),
                    digest,
                },
                coin,
                object.owner,
                result_bytes,
            )
        }
        other => panic!("expected {object_id} to be CurrentInline, got {other:?}"),
    }
}

fn query_object_bytes(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (HttpObjectQueryResult, Vec<u8>) {
    let result: HttpObjectQueryResult = client
        .query_object(object_id)
        .expect("object query should succeed");
    let bytes: Vec<u8> = result
        .encode()
        .expect("object result should encode canonically");
    (result, bytes)
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
    source_bytes: Vec<u8>,
    created_result: HttpObjectQueryResult,
    created_bytes: Vec<u8>,
    fee_bytes: Vec<u8>,
    treasury_bytes: Vec<u8>,
    split_receipt: HttpReceiptQueryResult,
    split_receipt_bytes: Vec<u8>,
    merge_receipt: HttpReceiptQueryResult,
    merge_receipt_bytes: Vec<u8>,
    next_nonce: u64,
    split_result_bytes: Vec<u8>,
    merge_result_bytes: Vec<u8>,
    split_signed_bytes: Vec<u8>,
    merge_signed_bytes: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_and_merge_are_restart_safe_and_request_id_conflicts_leave_state_unchanged() {
    let signer: LocalSigner = LocalSigner::from_seed([0x41; 32]);
    let sender = signer.address();
    let treasury = LocalSigner::from_seed([0x42; 32]).address();
    let directory: TestDirectory = TestDirectory::new();
    let config: DevnetConfig = DevnetConfig::parse_from(vec![
        "--data-dir".into(),
        directory.0.as_os_str().to_owned(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        "split-merge-e2e-devnet".into(),
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

    let deadline: StorageDeadline =
        StorageDeadline::new(SystemClock.now_unix_millis().unwrap() + 30_000).unwrap();
    let owner_seed_context = DurableOperationContext::new(
        first_generation,
        deadline,
        StorageCorrelationId::new([0x71; 16]).unwrap(),
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
    let treasury_seed_context = DurableOperationContext::new(
        first_generation,
        deadline,
        StorageCorrelationId::new([0x72; 16]).unwrap(),
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
    let source_id: ObjectId = owner_seed.coins().transfer_coin().id;
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
    let split_request_id: RequestId = RequestId::new([SPLIT_REQUEST_BYTE; 32]).unwrap();
    let merge_request_id: RequestId = RequestId::new([MERGE_REQUEST_BYTE; 32]).unwrap();
    let persisted: PersistedState = tokio::task::spawn_blocking(move || {
        let client: Client<LoopbackHttpTransport> = make_client(first_address);
        let context: HttpContextQueryResult = client.query_context().unwrap();
        let (source_ref_before, source_before, source_owner_before, _) =
            query_current_coin(&client, source_id);
        let (fee_ref_before, fee_before, fee_owner_before, _) = query_current_coin(&client, fee_id);
        let (treasury_ref_before, treasury_before, treasury_owner_before, _) =
            query_current_coin(&client, treasury_id);
        assert_eq!(source_owner_before, Owner::Address(sender));
        assert_eq!(fee_owner_before, Owner::Address(sender));
        assert_eq!(treasury_owner_before, Owner::Address(treasury));

        let mut split_manifest = AccessManifest::new();
        split_manifest.push(AccessEntry {
            object_ref: source_ref_before.clone(),
            mode: AccessMode::Write,
        });
        split_manifest.push(AccessEntry {
            object_ref: fee_ref_before.clone(),
            mode: AccessMode::Write,
        });
        split_manifest.push(AccessEntry {
            object_ref: treasury_ref_before,
            mode: AccessMode::Write,
        });
        let split_args: Vec<u8> = encode_standard_asset_split_args_v1(
            &StandardAssetSplitArgsV1::new(SPLIT_AMOUNT, sender).unwrap(),
        )
        .unwrap();
        let split_signed_bytes: Vec<u8> = PreparedTransaction::prepare_submission(
            split_request_id,
            sender,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: client.query_next_nonce(sender).unwrap().next_nonce(),
                access_manifest: split_manifest,
                module_ref: module_ref.clone(),
                entrypoint: SPLIT_ENTRYPOINT.to_string(),
                args: split_args,
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: fee_ref_before,
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&signer)
        .unwrap();
        let split_transaction = decode_transaction(&split_signed_bytes).unwrap();
        let split_hash = hash_transaction(&split_transaction, &hash_resolver).unwrap();
        let created_id: ObjectId =
            derive_created_object_id(context.protocol_version(), split_hash, 0);
        let split_result: HttpNodeResult = submit(
            &client,
            &context,
            split_request_id,
            split_signed_bytes.clone(),
        );
        let split_result_bytes: Vec<u8> = split_result.encode().unwrap();

        let (
            source_ref_after_split,
            source_after_split,
            source_owner_after_split,
            source_split_bytes,
        ) = query_current_coin(&client, source_id);
        let (created_ref, created_after_split, created_owner_after_split, created_split_bytes) =
            query_current_coin(&client, created_id);
        let (fee_ref_after_split, fee_after_split, fee_owner_after_split, fee_split_bytes) =
            query_current_coin(&client, fee_id);
        let (
            treasury_ref_after_split,
            treasury_after_split,
            treasury_owner_after_split,
            treasury_split_bytes,
        ) = query_current_coin(&client, treasury_id);
        assert_eq!(source_owner_after_split, Owner::Address(sender));
        assert_eq!(created_owner_after_split, Owner::Address(sender));
        assert_eq!(fee_owner_after_split, Owner::Address(sender));
        assert_eq!(treasury_owner_after_split, Owner::Address(treasury));
        assert_eq!(source_after_split.asset_id(), source_before.asset_id());
        assert_eq!(created_after_split.asset_id(), source_before.asset_id());
        assert_eq!(
            source_after_split.amount(),
            source_before.amount() - SPLIT_AMOUNT
        );
        assert_eq!(created_after_split.amount(), SPLIT_AMOUNT);
        assert_eq!(
            source_ref_after_split.version,
            source_ref_before.version + 1
        );
        assert_eq!(created_ref.version, 1);
        let split_fee: u64 = treasury_after_split.amount() - treasury_before.amount();
        assert_eq!(fee_after_split.amount(), fee_before.amount() - split_fee);

        let split_receipt = query_receipt_bytes(&client, split_request_id);
        let nonce_after_split: u64 = client.query_next_nonce(sender).unwrap().next_nonce();
        let split_replay: HttpNodeResult = submit(
            &client,
            &context,
            split_request_id,
            split_signed_bytes.clone(),
        );
        assert_eq!(split_replay.encode().unwrap(), split_result_bytes);
        assert_eq!(query_object_bytes(&client, source_id).1, source_split_bytes);
        assert_eq!(
            query_object_bytes(&client, created_id).1,
            created_split_bytes
        );
        assert_eq!(query_object_bytes(&client, fee_id).1, fee_split_bytes);
        assert_eq!(
            query_object_bytes(&client, treasury_id).1,
            treasury_split_bytes
        );
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            nonce_after_split
        );

        let mut merge_manifest = AccessManifest::new();
        merge_manifest.push(AccessEntry {
            object_ref: source_ref_after_split,
            mode: AccessMode::Write,
        });
        merge_manifest.push(AccessEntry {
            object_ref: created_ref,
            mode: AccessMode::Consume,
        });
        merge_manifest.push(AccessEntry {
            object_ref: fee_ref_after_split.clone(),
            mode: AccessMode::Write,
        });
        merge_manifest.push(AccessEntry {
            object_ref: treasury_ref_after_split,
            mode: AccessMode::Write,
        });
        let merge_signed_bytes: Vec<u8> = PreparedTransaction::prepare_submission(
            merge_request_id,
            sender,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: nonce_after_split,
                access_manifest: merge_manifest,
                module_ref: module_ref.clone(),
                entrypoint: MERGE_ENTRYPOINT.to_string(),
                args: Vec::new(),
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: fee_ref_after_split,
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&signer)
        .unwrap();
        let merge_result: HttpNodeResult = submit(
            &client,
            &context,
            merge_request_id,
            merge_signed_bytes.clone(),
        );
        let merge_result_bytes: Vec<u8> = merge_result.encode().unwrap();
        let (_source_ref_after_merge, source_after_merge, source_owner_after_merge, source_bytes) =
            query_current_coin(&client, source_id);
        let (created_result, created_bytes) = query_object_bytes(&client, created_id);
        let (_fee_ref_after_merge, fee_after_merge, fee_owner_after_merge, fee_bytes) =
            query_current_coin(&client, fee_id);
        let (
            _treasury_ref_after_merge,
            treasury_after_merge,
            treasury_owner_after_merge,
            treasury_bytes,
        ) = query_current_coin(&client, treasury_id);
        assert_eq!(source_after_merge, source_before);
        assert_eq!(source_owner_after_merge, Owner::Address(sender));
        assert!(matches!(
            created_result,
            HttpObjectQueryResult::Tombstoned { .. }
        ));
        assert_eq!(fee_owner_after_merge, Owner::Address(sender));
        assert_eq!(treasury_owner_after_merge, Owner::Address(treasury));
        let total_fee: u64 = treasury_after_merge.amount() - treasury_before.amount();
        assert_eq!(fee_after_merge.amount(), fee_before.amount() - total_fee);

        let (merge_receipt, merge_receipt_bytes) = query_receipt_bytes(&client, merge_request_id);
        let next_nonce: u64 = client.query_next_nonce(sender).unwrap().next_nonce();
        let merge_replay: HttpNodeResult = submit(
            &client,
            &context,
            merge_request_id,
            merge_signed_bytes.clone(),
        );
        assert_eq!(merge_replay.encode().unwrap(), merge_result_bytes);
        assert_eq!(query_object_bytes(&client, source_id).1, source_bytes);
        assert_eq!(query_object_bytes(&client, created_id).1, created_bytes);
        assert_eq!(query_object_bytes(&client, fee_id).1, fee_bytes);
        assert_eq!(query_object_bytes(&client, treasury_id).1, treasury_bytes);
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            next_nonce
        );

        PersistedState {
            source_bytes,
            created_result,
            created_bytes,
            fee_bytes,
            treasury_bytes,
            split_receipt: split_receipt.0,
            split_receipt_bytes: split_receipt.1,
            merge_receipt,
            merge_receipt_bytes,
            next_nonce,
            split_result_bytes,
            merge_result_bytes,
            split_signed_bytes,
            merge_signed_bytes,
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
            query_object_bytes(&client, source_id).1,
            persisted.source_bytes
        );
        let created_after_restart =
            query_object_bytes(&client, persisted.created_result.object_id());
        assert_eq!(created_after_restart.0, persisted.created_result);
        assert_eq!(created_after_restart.1, persisted.created_bytes);
        assert_eq!(query_object_bytes(&client, fee_id).1, persisted.fee_bytes);
        assert_eq!(
            query_object_bytes(&client, treasury_id).1,
            persisted.treasury_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, split_request_id).0,
            persisted.split_receipt
        );
        assert_eq!(
            query_receipt_bytes(&client, split_request_id).1,
            persisted.split_receipt_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, merge_request_id).0,
            persisted.merge_receipt
        );
        assert_eq!(
            query_receipt_bytes(&client, merge_request_id).1,
            persisted.merge_receipt_bytes
        );
        assert_eq!(
            client.query_next_nonce(sender).unwrap().next_nonce(),
            persisted.next_nonce
        );

        let split_replay: HttpNodeResult = submit(
            &client,
            &context,
            split_request_id,
            persisted.split_signed_bytes.clone(),
        );
        assert_eq!(split_replay.encode().unwrap(), persisted.split_result_bytes);
        let merge_replay: HttpNodeResult = submit(
            &client,
            &context,
            merge_request_id,
            persisted.merge_signed_bytes.clone(),
        );
        assert_eq!(merge_replay.encode().unwrap(), persisted.merge_result_bytes);

        let (_source_ref, _, _, _) = query_current_coin(&client, source_id);
        let (fee_ref, _, _, _) = query_current_coin(&client, fee_id);
        let (treasury_ref, _, _, _) = query_current_coin(&client, treasury_id);
        let mut conflicting_manifest = AccessManifest::new();
        conflicting_manifest.push(AccessEntry {
            object_ref: _source_ref,
            mode: AccessMode::Write,
        });
        conflicting_manifest.push(AccessEntry {
            object_ref: fee_ref.clone(),
            mode: AccessMode::Write,
        });
        conflicting_manifest.push(AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        });
        let conflicting_args: Vec<u8> =
            encode_standard_asset_transfer_args_v1(&StandardAssetTransferArgsV1::new(sender))
                .unwrap();
        let conflicting_signed_bytes: Vec<u8> = PreparedTransaction::prepare_submission(
            split_request_id,
            sender,
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: persisted.next_nonce,
                access_manifest: conflicting_manifest,
                module_ref: module_ref_after_restart,
                entrypoint: TRANSFER_ENTRYPOINT.to_string(),
                args: conflicting_args,
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: fee_ref,
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
                request_id: split_request_id,
                signed_transaction_bytes: conflicting_signed_bytes,
            })
            .expect_err("reusing the split request id for a different transaction must fail");
        assert!(matches!(
            error,
            ClientError::UnexpectedStatus { status: 409, .. }
        ));

        assert_eq!(
            query_object_bytes(&client, source_id).1,
            persisted.source_bytes
        );
        assert_eq!(
            query_object_bytes(&client, persisted.created_result.object_id()).1,
            persisted.created_bytes
        );
        assert_eq!(query_object_bytes(&client, fee_id).1, persisted.fee_bytes);
        assert_eq!(
            query_object_bytes(&client, treasury_id).1,
            persisted.treasury_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, split_request_id).1,
            persisted.split_receipt_bytes
        );
        assert_eq!(
            query_receipt_bytes(&client, merge_request_id).1,
            persisted.merge_receipt_bytes
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
