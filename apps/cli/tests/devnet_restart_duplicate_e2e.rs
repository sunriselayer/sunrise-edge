//! Real loopback TCP restart/duplicate E2E for the Standard Asset v1
//! whole-coin transfer slice (DR-0107; see `TODO.md`'s Asset Standards
//! Gate).
//!
//! This uses a real file-backed `SqliteDurableStore`, the real composed
//! devnet router, real loopback TCP, `sunrise_edge_cli::run` for the
//! user-facing transfer leg, and `sunrise-edge-client` directly for
//! independent verification and for building/replaying raw
//! `SubmitTransactionRequest`s. It proves exactly:
//!
//! 1. A trapped invocation (malformed args) before any real transfer
//!    discards its application effects but charges the normalized actual
//!    gas through fee-only source/treasury writes.
//! 2. A fee-enabled CLI transfer of dev owner A's whole transferable coin to
//!    an unseeded recipient address: the coin's owner changes, its body
//!    (asset id + amount) and type/schema stay byte-identical, and the
//!    distinct fee coin and treasury are debited/credited by the actual
//!    committed gas.
//! 3. A second, directly-built (not through the CLI) whole-coin transfer by
//!    an independent dev owner B, signed with B's own key, to the same
//!    recipient. It deliberately swaps the two startup labels: B's seeded
//!    fee coin is transferred while B's seeded transfer coin pays the fee,
//!    proving those labels are not protocol roles.
//! 4. An orderly stop (graceful HTTP shutdown, awaited server task, every
//!    `Arc<SqliteDurableStore>` reference dropped so the SQLite file is
//!    genuinely closed) followed by a real reopen through `boot_local_store`
//!    that advances the writer generation, and a reseed of both dev owners'
//!    coin pairs and the treasury coin that verifies the exact same seed
//!    identities — including owner A's seeded transfer coin and owner B's
//!    seeded fee coin now owned by the recipient (F9's role-independent
//!    restart verification).
//! 5. State (coin bodies/owners, sequences via version, receipts, next
//!    nonce) observed immediately before the restart is observed
//!    byte-identically after it.
//! 6. The second transfer's signed transaction, replayed byte-identically
//!    both in the same boot and after restart: the canonical response bytes
//!    are identical and neither duplicate re-applies its effects.
//! 7. Reusing an already-committed request id (the trapped invocation's) for
//!    a different transaction is a typed, nonzero, fail-closed HTTP conflict
//!    with no state change.
//! 8. The pre-restart writer generation is fenced on the reopened store.
//!
//! This intentionally proves only orderly stop/reopen: it says nothing about
//! `kill -9`, power loss, torn writes, load, concurrency, or SQLite's
//! suitability for production use.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use runtime::{
    Clock, DurableOperationContext, DurableReadError, DurableRequestId, StorageCorrelationId,
    StorageDeadline, StructuredDurableDomainStateStore, SystemClock,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Amount, AtomicityDomainId, Client, ClientError,
    ExecutionStatus, FeePayment, HttpNodeResult, HttpObjectQueryResult, HttpReceiptQueryResult,
    LocalSigner, LoopbackHttpTransport, NodeResponseStatus, ObjectId, ObjectRef, Owner,
    PreparedTransaction, RequestId, SignatureSchemeId, StandardAssetCoinV1,
    StandardAssetTransferArgsV1, SubmitTransactionRequest, TransactionRequest,
    decode_execution_effects, decode_object, decode_standard_asset_coin_v1,
    encode_standard_asset_transfer_args_v1,
};
use sunrise_edge_devnet::{
    DevOwner, DevnetConfig, STANDARD_ASSET_TRANSFER_WASM, SeedDevOwnerCoinsOutcome,
    TRANSFER_ENTRYPOINT, boot_local_store, build_devnet_protocol_context,
    build_standard_asset_module, compose_devnet_router,
    genesis::{DEVNET_DOMAIN_BYTES, DEVNET_PROTOCOL_VERSION},
    seed_dev_owner_coins, seed_treasury_coin, verify_seeded_asset_supply,
};

const GAS_LIMIT: u64 = 1_000_000;
const REQUEST_ID_R0_BYTE: u8 = 0x50;
const REQUEST_ID_R1_BYTE: u8 = 0x51;
const REQUEST_ID_R2_BYTE: u8 = 0x52;
const TRAP_GAS_LIMIT: u64 = 10_000;
const EXPECTED_CHAIN_ID: &str = "cli-restart-duplicate-e2e-devnet";
const EXPECTED_EPOCH: &str = "13";
const EXPECTED_HASH_SUITE_ID: &str = "1";

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-cli-{label}-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

struct TempSeedFile(PathBuf);

impl TempSeedFile {
    fn new(seed: [u8; 32]) -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sunrise-edge-cli-restart-seed-{}-{sequence}",
            std::process::id()
        ));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        fs::write(&path, hex.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(path)
    }
}

impl Drop for TempSeedFile {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.0);
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn make_client(address: SocketAddr) -> Client<LoopbackHttpTransport> {
    let transport = LoopbackHttpTransport::new(
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

/// Independently queries and decodes `object_id`'s current inline body,
/// returning a fresh [`ObjectRef`], the decoded coin, the current owner, and
/// the query result's exact canonical bytes for restart comparisons.
/// Standard Asset v1 coin bodies remain below DR-0096's fixed
/// blob-publication threshold, so seeing a blob reference here would be a
/// product-surface regression for the current CLI.
fn query_current_coin(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (ObjectRef, StandardAssetCoinV1, Owner, Vec<u8>) {
    let result = client
        .query_object(object_id)
        .expect("object query should succeed");
    let canonical_result_bytes = result
        .encode()
        .expect("object query result should encode canonically");
    match result {
        HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            ref canonical_object_bytes,
            ..
        } => {
            let object =
                decode_object(canonical_object_bytes).expect("canonical object should decode");
            let coin = decode_standard_asset_coin_v1(&object.data)
                .expect("object body should decode as a Standard Asset v1 coin");
            let owner: Owner = object.owner;
            let object_ref = ObjectRef {
                id: object_id,
                version: object_version.get(),
                digest,
            };
            (object_ref, coin, owner, canonical_result_bytes)
        }
        other => panic!("expected object {object_id} to be CurrentInline, got {other:?}"),
    }
}

/// Everything captured immediately before the server stops, so the
/// post-restart phase can assert byte-identical continuity.
struct PreRestartState {
    source_a: StandardAssetCoinV1,
    source_a_ref: ObjectRef,
    fee_a: StandardAssetCoinV1,
    fee_a_ref: ObjectRef,
    source_b: StandardAssetCoinV1,
    source_b_ref: ObjectRef,
    fee_b: StandardAssetCoinV1,
    fee_b_ref: ObjectRef,
    treasury: StandardAssetCoinV1,
    treasury_ref: ObjectRef,
    source_a_query_bytes: Vec<u8>,
    fee_a_query_bytes: Vec<u8>,
    source_b_query_bytes: Vec<u8>,
    fee_b_query_bytes: Vec<u8>,
    treasury_query_bytes: Vec<u8>,
    trapped_receipt: HttpReceiptQueryResult,
    trapped_receipt_bytes: Vec<u8>,
    cli_receipt: HttpReceiptQueryResult,
    cli_receipt_bytes: Vec<u8>,
    second_transfer_receipt: HttpReceiptQueryResult,
    second_transfer_receipt_bytes: Vec<u8>,
    next_nonce_a: u64,
    next_nonce_a_query_bytes: Vec<u8>,
    request_id_r2: RequestId,
    signed_transaction_bytes_r2: Vec<u8>,
    submit_result_r2: HttpNodeResult,
    submit_result_r2_bytes: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devnet_survives_orderly_restart_and_rejects_duplicate_and_reused_requests() {
    let owner_a_signer = LocalSigner::from_seed([0x5B; 32]);
    let owner_a_address = owner_a_signer.address();
    let owner_b_signer = LocalSigner::from_seed([0x6B; 32]);
    let owner_b_address = owner_b_signer.address();
    let recipient_address = LocalSigner::from_seed([0x8B; 32]).address();
    let treasury_address = LocalSigner::from_seed([0x7B; 32]).address();
    let seed_file = TempSeedFile::new([0x5B; 32]);
    let dev_owner_a = DevOwner::new(*owner_a_address.as_bytes());
    let dev_owner_b = DevOwner::new(*owner_b_address.as_bytes());

    let directory = TestDirectory::new("restart-duplicate-e2e");
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("cli-restart-duplicate-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("13"),
        OsString::from("--dev-owner"),
        OsString::from(owner_a_address.to_string()),
        OsString::from("--dev-owner"),
        OsString::from(owner_b_address.to_string()),
        OsString::from("--fee-treasury-owner"),
        OsString::from(treasury_address.to_string()),
        OsString::from("--max-concurrent"),
        OsString::from("4"),
    ])
    .unwrap();

    // --- Boot generation N, seed coins. ---
    let first_boot = boot_local_store(&config).unwrap();
    let first_generation = first_boot.boot_generation();
    let first_protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let asset_id = first_protocol_context.asset_id();
    let first_module = build_standard_asset_module(
        first_protocol_context,
        STANDARD_ASSET_TRANSFER_WASM.to_vec(),
    )
    .unwrap();

    let now_unix_millis = SystemClock.now_unix_millis().unwrap();
    let seed_deadline = StorageDeadline::new(now_unix_millis + 30_000).unwrap();
    let seed_context_a = DurableOperationContext::new(
        first_generation,
        seed_deadline,
        StorageCorrelationId::new([0x61; 16]).unwrap(),
    );
    let seed_outcome_a = seed_dev_owner_coins(
        first_boot.store(),
        first_boot.blob_store(),
        first_module.resolver(),
        config.epoch(),
        asset_id,
        dev_owner_a,
        first_generation,
        &seed_context_a,
    )
    .unwrap();
    assert!(matches!(
        seed_outcome_a,
        SeedDevOwnerCoinsOutcome::Created(_)
    ));
    let seed_context_b = DurableOperationContext::new(
        first_generation,
        seed_deadline,
        StorageCorrelationId::new([0x64; 16]).unwrap(),
    );
    let seed_outcome_b = seed_dev_owner_coins(
        first_boot.store(),
        first_boot.blob_store(),
        first_module.resolver(),
        config.epoch(),
        asset_id,
        dev_owner_b,
        first_generation,
        &seed_context_b,
    )
    .unwrap();
    assert!(matches!(
        seed_outcome_b,
        SeedDevOwnerCoinsOutcome::Created(_)
    ));
    let treasury_context = DurableOperationContext::new(
        first_generation,
        seed_deadline,
        StorageCorrelationId::new([0x66; 16]).unwrap(),
    );
    let treasury_outcome = seed_treasury_coin(
        first_boot.store(),
        first_boot.blob_store(),
        first_module.resolver(),
        config.epoch(),
        asset_id,
        config.fee_treasury_owner(),
        first_generation,
        &treasury_context,
    )
    .unwrap();
    verify_seeded_asset_supply(
        &[seed_outcome_a.clone(), seed_outcome_b.clone()],
        &treasury_outcome,
    )
    .unwrap();
    let source_a_id = seed_outcome_a.coins().transfer_coin().id;
    let fee_a_id = seed_outcome_a.coins().fee_coin().id;
    let source_b_id = seed_outcome_b.coins().transfer_coin().id;
    let fee_b_id = seed_outcome_b.coins().fee_coin().id;
    let treasury_id = treasury_outcome.coin().coin().id;
    let module_ref = first_module.module_ref().clone();

    // --- Serve on an ephemeral loopback port. ---
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
    let first_address = first_listener.local_addr().unwrap();
    let (first_shutdown_tx, first_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let first_server = tokio::spawn(native_http::serve(first_listener, first_router, async {
        let _ = first_shutdown_rx.await;
    }));

    let request_id_r0 = RequestId::new([REQUEST_ID_R0_BYTE; 32]).unwrap();
    let request_id_r1 = RequestId::new([REQUEST_ID_R1_BYTE; 32]).unwrap();
    let request_id_r2 = RequestId::new([REQUEST_ID_R2_BYTE; 32]).unwrap();
    let endpoint = first_address.to_string();
    let seed_path = seed_file.0.clone();
    let module_ref_for_blocking = module_ref.clone();
    let owner_a_signer_after_restart = owner_a_signer.clone();
    let pre_restart: PreRestartState = tokio::task::spawn_blocking(move || {
        let module_ref = module_ref_for_blocking;
        let verify_client = make_client(first_address);

        // Baseline, independent of the seeding code above.
        let (source_a_ref_baseline, source_a_baseline, source_a_owner_baseline, _) =
            query_current_coin(&verify_client, source_a_id);
        let (fee_a_ref_baseline, fee_a_baseline, fee_a_owner_baseline, _) =
            query_current_coin(&verify_client, fee_a_id);
        let (treasury_ref_baseline, treasury_baseline, treasury_owner_baseline, _) =
            query_current_coin(&verify_client, treasury_id);
        assert_eq!(source_a_owner_baseline, Owner::Address(owner_a_address));
        assert_eq!(fee_a_owner_baseline, Owner::Address(owner_a_address));
        assert_eq!(treasury_owner_baseline, Owner::Address(treasury_address));

        // Property 1: a trapped invocation (malformed args) before any real
        // transfer. Both declared Write coins are still owned by owner A at
        // this point, so this is admissible; the module traps on the wrong
        // args length, discarding application effects, while the normalized
        // `gas_used == gas_limit` charge still commits fee-only writes.
        let context = verify_client
            .query_context()
            .expect("context query should succeed");
        let nonce_before_trap = verify_client
            .query_next_nonce(owner_a_address)
            .expect("next-nonce before trapped invocation should succeed");
        let mut trap_manifest = AccessManifest::new();
        trap_manifest.push(AccessEntry {
            object_ref: source_a_ref_baseline.clone(),
            mode: AccessMode::Write,
        });
        trap_manifest.push(AccessEntry {
            object_ref: fee_a_ref_baseline.clone(),
            mode: AccessMode::Write,
        });
        trap_manifest.push(AccessEntry {
            object_ref: treasury_ref_baseline,
            mode: AccessMode::Write,
        });
        let trapped_signed_bytes = PreparedTransaction::prepare_submission(
            request_id_r0,
            owner_a_signer.address(),
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: nonce_before_trap.next_nonce(),
                access_manifest: trap_manifest,
                module_ref: module_ref.clone(),
                entrypoint: TRANSFER_ENTRYPOINT.to_string(),
                args: vec![0],
                gas_limit: TRAP_GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(TRAP_GAS_LIMIT + 1),
                    fee_object: fee_a_ref_baseline,
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&owner_a_signer)
        .unwrap();
        let trapped_result = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r0,
                signed_transaction_bytes: trapped_signed_bytes.clone(),
            })
            .expect("trapped execution should commit its rejected receipt and fee effects");
        assert_eq!(trapped_result.responses().len(), 1);
        assert_eq!(
            trapped_result.responses()[0].status(),
            NodeResponseStatus::Rejected
        );
        let trapped_effects = decode_execution_effects(
            trapped_result.responses()[0]
                .payload()
                .expect("trapped execution should carry normalized effects"),
        )
        .unwrap();
        assert!(matches!(
            trapped_effects.status,
            ExecutionStatus::Failure { .. }
        ));
        assert_eq!(trapped_effects.gas_used, TRAP_GAS_LIMIT);
        assert!(trapped_effects.object_effects.is_empty());
        let _trapped_result_bytes = trapped_result
            .encode()
            .expect("trapped submit result should encode canonically");

        let (source_a_ref_after_trap, source_a_after_trap, source_a_owner_after_trap, _) =
            query_current_coin(&verify_client, source_a_id);
        let (_fee_a_ref_after_trap, fee_a_after_trap, fee_a_owner_after_trap, _) =
            query_current_coin(&verify_client, fee_a_id);
        let (_, treasury_after_trap, treasury_owner_after_trap, _) =
            query_current_coin(&verify_client, treasury_id);
        assert_eq!(source_a_after_trap, source_a_baseline);
        assert_eq!(source_a_owner_after_trap, Owner::Address(owner_a_address));
        assert_eq!(
            fee_a_after_trap.amount(),
            fee_a_baseline.amount() - TRAP_GAS_LIMIT - 1
        );
        assert_eq!(fee_a_owner_after_trap, Owner::Address(owner_a_address));
        assert_eq!(
            treasury_after_trap.amount(),
            treasury_baseline.amount() + TRAP_GAS_LIMIT + 1
        );
        assert_eq!(treasury_owner_after_trap, Owner::Address(treasury_address));

        let trapped_receipt = verify_client
            .query_receipt(request_id_r0)
            .expect("trapped invocation receipt query should succeed");
        assert!(matches!(
            trapped_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let trapped_receipt_bytes = trapped_receipt
            .encode()
            .expect("trapped receipt result should encode canonically");

        // Property 2: user-facing whole-coin transfer through the real CLI
        // binary entrypoint: owner A's transferable coin moves to the
        // unseeded recipient address, fee coin debited, treasury credited.
        sunrise_edge_cli::run(vec![
            OsString::from("transfer"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--seed-file"),
            OsString::from(seed_path.as_os_str()),
            OsString::from("--module-id"),
            OsString::from(module_ref.id.to_string()),
            OsString::from("--module-version"),
            OsString::from(module_ref.version.to_string()),
            OsString::from("--module-digest-algorithm"),
            OsString::from(module_ref.digest.algorithm().as_u16().to_string()),
            OsString::from("--module-digest"),
            OsString::from(hex32(&module_ref.digest.bytes())),
            OsString::from("--source-coin"),
            OsString::from(source_a_id.to_string()),
            OsString::from("--recipient"),
            OsString::from(recipient_address.to_string()),
            OsString::from("--fee-coin"),
            OsString::from(fee_a_id.to_string()),
            OsString::from("--gas-limit"),
            OsString::from(GAS_LIMIT.to_string()),
            OsString::from("--fee-asset-id"),
            OsString::from(hex32(asset_id.as_bytes())),
            OsString::from("--max-fee"),
            OsString::from((GAS_LIMIT + 1).to_string()),
            OsString::from("--fee-treasury-object"),
            OsString::from(treasury_id.to_string()),
            OsString::from("--request-id"),
            OsString::from(hex32(&[REQUEST_ID_R1_BYTE; 32])),
            OsString::from("--expected-chain-id"),
            OsString::from(EXPECTED_CHAIN_ID),
            OsString::from("--expected-protocol-version"),
            OsString::from(DEVNET_PROTOCOL_VERSION.get().to_string()),
            OsString::from("--expected-epoch"),
            OsString::from(EXPECTED_EPOCH),
            OsString::from("--expected-hash-suite-id"),
            OsString::from(EXPECTED_HASH_SUITE_ID),
            OsString::from("--expected-domain"),
            OsString::from(hex32(&DEVNET_DOMAIN_BYTES)),
            OsString::from("--wait"),
            OsString::from("--wait-max-attempts"),
            OsString::from("20"),
            OsString::from("--wait-initial-backoff-ms"),
            OsString::from("10"),
            OsString::from("--wait-max-backoff-ms"),
            OsString::from("50"),
            OsString::from("--wait-max-elapsed-ms"),
            OsString::from("5000"),
        ])
        .expect("CLI transfer should succeed against the real seeded devnet router");

        // DR-0096: node-core only publishes a new version to the `BlobStore`
        // when its canonical bytes exceed the fixed inline threshold. A
        // Standard Asset v1 coin body is a few dozen bytes, so the version
        // the CLI transfer just committed stays inline.
        assert!(matches!(
            verify_client
                .query_object(source_a_id)
                .expect("post-transfer object query should succeed"),
            HttpObjectQueryResult::CurrentInline { .. }
        ));

        let (source_a_ref_after_cli, source_a_after_cli, source_a_owner_after_cli, _) =
            query_current_coin(&verify_client, source_a_id);
        let (_fee_a_ref_after_cli, fee_a_after_cli, fee_a_owner_after_cli, _) =
            query_current_coin(&verify_client, fee_a_id);
        let (treasury_ref_after_cli, treasury_after_cli, _treasury_owner_after_cli, _) =
            query_current_coin(&verify_client, treasury_id);
        let cli_fee: u64 = treasury_after_cli.amount() - treasury_after_trap.amount();
        // Owner-only mutation: body/type/schema stay byte-identical, only
        // the owner and version change.
        assert_eq!(source_a_after_cli, source_a_baseline);
        assert_eq!(source_a_owner_after_cli, Owner::Address(recipient_address));
        assert_eq!(
            source_a_ref_after_cli.version,
            source_a_ref_after_trap.version + 1
        );
        assert_eq!(
            fee_a_after_cli.amount(),
            fee_a_after_trap.amount() - cli_fee
        );
        assert_eq!(fee_a_owner_after_cli, Owner::Address(owner_a_address));
        assert!(cli_fee > 1, "execution must add a non-zero metered fee");
        assert!(
            cli_fee < GAS_LIMIT + 1,
            "successful execution must charge actual gas, not the gas limit"
        );

        let cli_receipt = verify_client
            .query_receipt(request_id_r1)
            .expect("CLI transfer receipt query should succeed");
        assert!(matches!(
            cli_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let cli_receipt_bytes = cli_receipt
            .encode()
            .expect("CLI receipt result should encode canonically");

        // Property 3: a second, directly-built whole-coin transfer by an
        // independent dev owner B, signed with B's own key and deliberately
        // using the two seeded coins in the opposite roles from their startup
        // labels. The seeded fee coin is the transfer source and the seeded
        // transfer coin pays the fee. This proves those labels are only an
        // operator convenience, not a protocol distinction, and pins the
        // restart regression found during review. Built once, submitted once,
        // then replayed same-boot and after restart (Property 6).
        let nonce_b = verify_client
            .query_next_nonce(owner_b_address)
            .expect("next-nonce query for owner B should succeed");
        let (source_b_ref_before_r2, source_b_before_r2, _, _) =
            query_current_coin(&verify_client, source_b_id);
        let (fee_b_ref_before_r2, fee_b_before_r2, _, _) =
            query_current_coin(&verify_client, fee_b_id);
        let mut manifest_b = AccessManifest::new();
        manifest_b.push(AccessEntry {
            object_ref: fee_b_ref_before_r2,
            mode: AccessMode::Write,
        });
        manifest_b.push(AccessEntry {
            object_ref: source_b_ref_before_r2.clone(),
            mode: AccessMode::Write,
        });
        manifest_b.push(AccessEntry {
            object_ref: treasury_ref_after_cli,
            mode: AccessMode::Write,
        });
        let args = encode_standard_asset_transfer_args_v1(&StandardAssetTransferArgsV1::new(
            recipient_address,
        ))
        .unwrap();
        let transaction_request = TransactionRequest {
            chain_id: context.chain_id().clone(),
            protocol_version: context.protocol_version(),
            epoch: context.epoch(),
            nonce: nonce_b.next_nonce(),
            access_manifest: manifest_b,
            module_ref: module_ref.clone(),
            entrypoint: TRANSFER_ENTRYPOINT.to_string(),
            args,
            gas_limit: GAS_LIMIT,
            fee_payment: Some(FeePayment {
                asset_id,
                max_fee: Amount::new(GAS_LIMIT + 1),
                fee_object: source_b_ref_before_r2,
            }),
        };
        let signed_transaction_bytes_r2 = PreparedTransaction::prepare_submission(
            request_id_r2,
            owner_b_signer.address(),
            SignatureSchemeId::Ed25519,
            transaction_request,
        )
        .unwrap()
        .sign_and_finalize_with(&owner_b_signer)
        .unwrap();

        let submit_result_r2 = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r2,
                signed_transaction_bytes: signed_transaction_bytes_r2.clone(),
            })
            .expect("the second, directly built transfer should be accepted");
        let submit_result_r2_bytes = submit_result_r2
            .encode()
            .expect("submit result should encode canonically");
        assert_eq!(submit_result_r2.responses().len(), 1);
        assert_eq!(
            submit_result_r2.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let payload = submit_result_r2.responses()[0]
            .payload()
            .expect("accepted transfer should carry execution effects");
        let effects = decode_execution_effects(payload).unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Success));
        assert_eq!(effects.object_effects.len(), 1);

        let (source_b_ref_after_r2, source_b_after_r2, source_b_owner_after_r2, _) =
            query_current_coin(&verify_client, source_b_id);
        let (fee_b_ref_after_r2, fee_b_after_r2, fee_b_owner_after_r2, _) =
            query_current_coin(&verify_client, fee_b_id);
        let (treasury_ref_after_r2, treasury_after_r2, treasury_owner_after_r2, _) =
            query_current_coin(&verify_client, treasury_id);
        let r2_fee: u64 = treasury_after_r2.amount() - treasury_after_cli.amount();
        assert_eq!(r2_fee, 1 + effects.gas_used);
        assert_eq!(source_b_owner_after_r2, Owner::Address(owner_b_address));
        assert_eq!(
            source_b_after_r2.amount(),
            source_b_before_r2.amount() - r2_fee
        );
        assert_eq!(fee_b_owner_after_r2, Owner::Address(recipient_address));
        assert_eq!(fee_b_after_r2, fee_b_before_r2);
        assert_eq!(treasury_owner_after_r2, Owner::Address(treasury_address));

        let second_transfer_receipt = verify_client
            .query_receipt(request_id_r2)
            .expect("second transfer receipt query should succeed");
        assert!(matches!(
            second_transfer_receipt,
            HttpReceiptQueryResult::Present { .. }
        ));
        let second_transfer_receipt_bytes = second_transfer_receipt
            .encode()
            .expect("second receipt result should encode canonically");

        let next_nonce_result = verify_client
            .query_next_nonce(owner_a_address)
            .expect("next-nonce query should succeed");
        let next_nonce_a_final = next_nonce_result.next_nonce();
        let next_nonce_a_query_bytes = next_nonce_result
            .encode()
            .expect("next-nonce result should encode canonically");

        // Same-boot duplicate evidence: replay the exact R2 request before
        // the restart and prove both the canonical response and every
        // persisted observation remain byte-identical.
        let duplicate_before_restart = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r2,
                signed_transaction_bytes: signed_transaction_bytes_r2.clone(),
            })
            .expect("the exact same-boot duplicate should reconcile");
        assert_eq!(
            duplicate_before_restart
                .encode()
                .expect("duplicate submit result should encode canonically"),
            submit_result_r2_bytes
        );
        let (_, source_b_after_dup, source_b_owner_after_dup, source_b_bytes_after_dup) =
            query_current_coin(&verify_client, source_b_id);
        let (_, fee_b_after_dup, fee_b_owner_after_dup, fee_b_bytes_after_dup) =
            query_current_coin(&verify_client, fee_b_id);
        let (_, treasury_after_dup, treasury_owner_after_dup, treasury_bytes_after_dup) =
            query_current_coin(&verify_client, treasury_id);
        assert_eq!(source_b_after_dup, source_b_after_r2);
        assert_eq!(source_b_owner_after_dup, Owner::Address(owner_b_address));
        assert_eq!(fee_b_after_dup, fee_b_after_r2);
        assert_eq!(fee_b_owner_after_dup, Owner::Address(recipient_address));
        assert_eq!(treasury_after_dup, treasury_after_r2);
        assert_eq!(treasury_owner_after_dup, Owner::Address(treasury_address));

        let (source_a_ref_final, source_a_final, _source_a_owner_final, source_a_bytes_final) =
            query_current_coin(&verify_client, source_a_id);
        let (fee_a_ref_final, fee_a_final, _fee_a_owner_final, fee_a_bytes_final) =
            query_current_coin(&verify_client, fee_a_id);

        PreRestartState {
            source_a: source_a_final,
            source_a_ref: source_a_ref_final,
            fee_a: fee_a_final,
            fee_a_ref: fee_a_ref_final,
            source_b: source_b_after_dup,
            source_b_ref: source_b_ref_after_r2,
            fee_b: fee_b_after_dup,
            fee_b_ref: fee_b_ref_after_r2,
            treasury: treasury_after_dup,
            treasury_ref: treasury_ref_after_r2,
            source_a_query_bytes: source_a_bytes_final,
            fee_a_query_bytes: fee_a_bytes_final,
            source_b_query_bytes: source_b_bytes_after_dup,
            fee_b_query_bytes: fee_b_bytes_after_dup,
            treasury_query_bytes: treasury_bytes_after_dup,
            trapped_receipt,
            trapped_receipt_bytes,
            cli_receipt,
            cli_receipt_bytes,
            second_transfer_receipt,
            second_transfer_receipt_bytes,
            next_nonce_a: next_nonce_a_final,
            next_nonce_a_query_bytes,
            request_id_r2,
            signed_transaction_bytes_r2,
            submit_result_r2,
            submit_result_r2_bytes,
        }
    })
    .await
    .unwrap();

    // --- Stop and await the server; drop every store/router reference. ---
    first_shutdown_tx
        .send(())
        .expect("shutdown signal should reach the still-running server task");
    first_server
        .await
        .expect("server task should not panic")
        .expect("graceful shutdown should complete without error");
    let closed_store = Arc::try_unwrap(first_store)
        .expect("no other durable-store reference should remain after orderly shutdown");
    drop(closed_store);
    let closed_blob_store = Arc::try_unwrap(first_blob_store)
        .expect("no other blob-store reference should remain after orderly shutdown");
    drop(closed_blob_store);

    // --- Reopen through boot_local_store; assert generation N+1. ---
    let second_boot = boot_local_store(&config).unwrap();
    let second_generation = second_boot.boot_generation();
    assert_eq!(second_generation.get(), first_generation.get() + 1);

    // Property 8: the pre-restart writer generation is fenced on the
    // reopened store.
    let domain = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap();
    let stale_generation_context = DurableOperationContext::new(
        first_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x62; 16]).unwrap(),
    );
    let durable_request_id_r0 = DurableRequestId::new(*request_id_r0.as_bytes()).unwrap();
    let fencing_result = second_boot.store().get_request_receipt(
        &stale_generation_context,
        domain,
        durable_request_id_r0,
    );
    assert_eq!(
        fencing_result,
        Err(DurableReadError::WriterFenced {
            active_generation: second_generation
        })
    );

    // Property 4: reseed both dev owners' coin pairs and the treasury coin,
    // requiring Existing with identical seed identities. Owner A's seeded
    // transfer coin and owner B's seeded fee coin are now owned by
    // `recipient_address`; F9's role-independent verification must accept
    // both arrangements.
    let second_protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    assert_eq!(second_protocol_context.asset_id(), asset_id);
    let second_module = build_standard_asset_module(
        second_protocol_context,
        STANDARD_ASSET_TRANSFER_WASM.to_vec(),
    )
    .unwrap();
    let reseed_context_a = DurableOperationContext::new(
        second_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x63; 16]).unwrap(),
    );
    let reseed_outcome_a = seed_dev_owner_coins(
        second_boot.store(),
        second_boot.blob_store(),
        second_module.resolver(),
        config.epoch(),
        asset_id,
        dev_owner_a,
        second_generation,
        &reseed_context_a,
    )
    .unwrap();
    assert!(matches!(
        reseed_outcome_a,
        SeedDevOwnerCoinsOutcome::Existing(_)
    ));
    let reseed_context_b = DurableOperationContext::new(
        second_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x65; 16]).unwrap(),
    );
    let reseed_outcome_b = seed_dev_owner_coins(
        second_boot.store(),
        second_boot.blob_store(),
        second_module.resolver(),
        config.epoch(),
        asset_id,
        dev_owner_b,
        second_generation,
        &reseed_context_b,
    )
    .unwrap();
    assert!(matches!(
        reseed_outcome_b,
        SeedDevOwnerCoinsOutcome::Existing(_)
    ));
    let treasury_reseed_context = DurableOperationContext::new(
        second_generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x67; 16]).unwrap(),
    );
    let treasury_reseed_outcome = seed_treasury_coin(
        second_boot.store(),
        second_boot.blob_store(),
        second_module.resolver(),
        config.epoch(),
        asset_id,
        config.fee_treasury_owner(),
        second_generation,
        &treasury_reseed_context,
    )
    .unwrap();
    verify_seeded_asset_supply(
        &[reseed_outcome_a.clone(), reseed_outcome_b.clone()],
        &treasury_reseed_outcome,
    )
    .unwrap();
    assert_eq!(reseed_outcome_a.coins().owner(), dev_owner_a);
    assert_eq!(
        reseed_outcome_a.coins().transfer_coin(),
        &pre_restart.source_a_ref
    );
    assert_eq!(reseed_outcome_a.coins().fee_coin(), &pre_restart.fee_a_ref);
    assert_eq!(reseed_outcome_b.coins().owner(), dev_owner_b);
    assert_eq!(
        reseed_outcome_b.coins().transfer_coin(),
        &pre_restart.source_b_ref
    );
    assert_eq!(reseed_outcome_b.coins().fee_coin(), &pre_restart.fee_b_ref);
    assert_eq!(second_module.module_ref(), &module_ref);

    // --- Recompose on a fresh ephemeral port. ---
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
    let second_address = second_listener.local_addr().unwrap();
    let (second_shutdown_tx, second_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let second_server = tokio::spawn(native_http::serve(second_listener, second_router, async {
        let _ = second_shutdown_rx.await;
    }));

    tokio::task::spawn_blocking(move || {
        let verify_client = make_client(second_address);

        // DR-0096: a Standard Asset v1 coin body stays under the fixed
        // inline threshold, so the version committed before restart is
        // still `CurrentInline` after it.
        assert!(matches!(
            verify_client
                .query_object(source_a_id)
                .expect("post-restart object query should succeed"),
            HttpObjectQueryResult::CurrentInline { .. }
        ));

        // Property 5: coin bodies/owners, receipts, and next nonce are
        // byte-identical to the values captured immediately before restart.
        let (_, source_a_after_restart, source_a_owner_after_restart, source_a_bytes_after_restart) =
            query_current_coin(&verify_client, source_a_id);
        let (_, fee_a_after_restart, fee_a_owner_after_restart, fee_a_bytes_after_restart) =
            query_current_coin(&verify_client, fee_a_id);
        let (_, source_b_after_restart, source_b_owner_after_restart, source_b_bytes_after_restart) =
            query_current_coin(&verify_client, source_b_id);
        let (_, fee_b_after_restart, fee_b_owner_after_restart, fee_b_bytes_after_restart) =
            query_current_coin(&verify_client, fee_b_id);
        let (treasury_ref_after_restart, treasury_after_restart, treasury_owner_after_restart, treasury_bytes_after_restart) =
            query_current_coin(&verify_client, treasury_id);
        assert_eq!(source_a_after_restart, pre_restart.source_a);
        assert_eq!(source_a_owner_after_restart, Owner::Address(recipient_address));
        assert_eq!(fee_a_after_restart, pre_restart.fee_a);
        assert_eq!(fee_a_owner_after_restart, Owner::Address(owner_a_address));
        assert_eq!(source_b_after_restart, pre_restart.source_b);
        assert_eq!(source_b_owner_after_restart, Owner::Address(owner_b_address));
        assert_eq!(fee_b_after_restart, pre_restart.fee_b);
        assert_eq!(fee_b_owner_after_restart, Owner::Address(recipient_address));
        assert_eq!(treasury_after_restart, pre_restart.treasury);
        assert_eq!(treasury_ref_after_restart, pre_restart.treasury_ref);
        assert_eq!(treasury_owner_after_restart, Owner::Address(treasury_address));
        assert_eq!(source_a_bytes_after_restart, pre_restart.source_a_query_bytes);
        assert_eq!(fee_a_bytes_after_restart, pre_restart.fee_a_query_bytes);
        assert_eq!(source_b_bytes_after_restart, pre_restart.source_b_query_bytes);
        assert_eq!(fee_b_bytes_after_restart, pre_restart.fee_b_query_bytes);
        assert_eq!(treasury_bytes_after_restart, pre_restart.treasury_query_bytes);

        let trapped_receipt_after_restart = verify_client
            .query_receipt(request_id_r0)
            .expect("trapped receipt query should succeed after restart");
        assert_eq!(trapped_receipt_after_restart, pre_restart.trapped_receipt);
        assert_eq!(
            trapped_receipt_after_restart
                .encode()
                .expect("trapped receipt should encode canonically after restart"),
            pre_restart.trapped_receipt_bytes
        );

        let cli_receipt_after_restart = verify_client
            .query_receipt(request_id_r1)
            .expect("CLI transfer receipt query should succeed after restart");
        assert_eq!(cli_receipt_after_restart, pre_restart.cli_receipt);
        assert_eq!(
            cli_receipt_after_restart
                .encode()
                .expect("CLI receipt result should encode canonically after restart"),
            pre_restart.cli_receipt_bytes
        );

        let second_transfer_receipt_after_restart = verify_client
            .query_receipt(pre_restart.request_id_r2)
            .expect("second transfer receipt query should succeed after restart");
        assert_eq!(
            second_transfer_receipt_after_restart,
            pre_restart.second_transfer_receipt
        );
        assert_eq!(
            second_transfer_receipt_after_restart
                .encode()
                .expect("second receipt result should encode canonically after restart"),
            pre_restart.second_transfer_receipt_bytes
        );

        let next_nonce_result_after_restart = verify_client
            .query_next_nonce(owner_a_address)
            .expect("next-nonce query should succeed after restart");
        assert_eq!(
            next_nonce_result_after_restart.next_nonce(),
            pre_restart.next_nonce_a
        );
        assert_eq!(
            next_nonce_result_after_restart
                .encode()
                .expect("next-nonce result should encode canonically after restart"),
            pre_restart.next_nonce_a_query_bytes
        );

        // Property 6: submit the exact same signed R2 transaction
        // byte-for-byte with the same request id, across restart. It must
        // return the same response and must not change state further.
        let context = verify_client
            .query_context()
            .expect("context query should succeed after restart");
        let duplicate_result = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: pre_restart.request_id_r2,
                signed_transaction_bytes: pre_restart.signed_transaction_bytes_r2.clone(),
            })
            .expect("the exact duplicate submission should still be accepted as a replay");
        assert_eq!(duplicate_result, pre_restart.submit_result_r2);
        assert_eq!(
            duplicate_result
                .encode()
                .expect("duplicate result should encode canonically after restart"),
            pre_restart.submit_result_r2_bytes
        );

        let (_, source_b_after_duplicate, source_b_owner_after_duplicate, source_b_bytes_after_duplicate) =
            query_current_coin(&verify_client, source_b_id);
        let (_, fee_b_after_duplicate, fee_b_owner_after_duplicate, fee_b_bytes_after_duplicate) =
            query_current_coin(&verify_client, fee_b_id);
        let (_, treasury_after_duplicate, treasury_owner_after_duplicate, treasury_bytes_after_duplicate) =
            query_current_coin(&verify_client, treasury_id);
        assert_eq!(source_b_after_duplicate, pre_restart.source_b);
        assert_eq!(source_b_owner_after_duplicate, Owner::Address(owner_b_address));
        assert_eq!(fee_b_after_duplicate, pre_restart.fee_b);
        assert_eq!(fee_b_owner_after_duplicate, Owner::Address(recipient_address));
        assert_eq!(treasury_after_duplicate, pre_restart.treasury);
        assert_eq!(treasury_owner_after_duplicate, Owner::Address(treasury_address));
        assert_eq!(source_b_bytes_after_duplicate, pre_restart.source_b_query_bytes);
        assert_eq!(fee_b_bytes_after_duplicate, pre_restart.fee_b_query_bytes);
        assert_eq!(treasury_bytes_after_duplicate, pre_restart.treasury_query_bytes);

        // Property 7: reusing an already-committed request id
        // (`request_id_r0`, the trapped invocation) for a different
        // transaction is a typed, nonzero, fail-closed HTTP conflict, with
        // no state change.
        let mut reused_id_manifest = AccessManifest::new();
        reused_id_manifest.push(AccessEntry {
            object_ref: pre_restart.source_a_ref.clone(),
            mode: AccessMode::Write,
        });
        reused_id_manifest.push(AccessEntry {
            object_ref: pre_restart.fee_a_ref.clone(),
            mode: AccessMode::Write,
        });
        reused_id_manifest.push(AccessEntry {
            object_ref: pre_restart.treasury_ref.clone(),
            mode: AccessMode::Write,
        });
        let next_nonce_a_now = verify_client
            .query_next_nonce(owner_a_address)
            .expect("next-nonce query before reuse attempt should succeed")
            .next_nonce();
        let args =
            encode_standard_asset_transfer_args_v1(&StandardAssetTransferArgsV1::new(recipient_address))
                .unwrap();
        let reused_id_signed_bytes = PreparedTransaction::prepare_submission(
            request_id_r0,
            owner_a_signer_after_restart.address(),
            SignatureSchemeId::Ed25519,
            TransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                nonce: next_nonce_a_now,
                access_manifest: reused_id_manifest,
                module_ref: module_ref.clone(),
                entrypoint: TRANSFER_ENTRYPOINT.to_string(),
                args,
                gas_limit: GAS_LIMIT,
                fee_payment: Some(FeePayment {
                    asset_id,
                    max_fee: Amount::new(GAS_LIMIT + 1),
                    fee_object: pre_restart.fee_a_ref.clone(),
                }),
            },
        )
        .unwrap()
        .sign_and_finalize_with(&owner_a_signer_after_restart)
        .unwrap();
        let reused_id_error = verify_client
            .submit_transaction(SubmitTransactionRequest {
                chain_id: context.chain_id().clone(),
                protocol_version: context.protocol_version(),
                epoch: context.epoch(),
                request_id: request_id_r0,
                signed_transaction_bytes: reused_id_signed_bytes,
            })
            .expect_err("reusing a committed request id for a different transaction must fail");
        match reused_id_error {
            ClientError::UnexpectedStatus { status, .. } => {
                assert_ne!(status, 0);
                assert_eq!(status, 409);
            }
            other => panic!("expected a typed fail-closed HTTP conflict, got {other:?}"),
        }

        let (_, source_a_after_reuse, source_a_owner_after_reuse, source_a_bytes_after_reuse) =
            query_current_coin(&verify_client, source_a_id);
        let (_, fee_a_after_reuse, fee_a_owner_after_reuse, fee_a_bytes_after_reuse) =
            query_current_coin(&verify_client, fee_a_id);
        assert_eq!(source_a_after_reuse, pre_restart.source_a);
        assert_eq!(source_a_owner_after_reuse, Owner::Address(recipient_address));
        assert_eq!(fee_a_after_reuse, pre_restart.fee_a);
        assert_eq!(fee_a_owner_after_reuse, Owner::Address(owner_a_address));
        assert_eq!(source_a_bytes_after_reuse, pre_restart.source_a_query_bytes);
        assert_eq!(fee_a_bytes_after_reuse, pre_restart.fee_a_query_bytes);
        assert_eq!(
            verify_client
                .query_receipt(request_id_r0)
                .expect("trapped receipt query should succeed after the rejected reuse attempt")
                .encode()
                .expect("trapped receipt should encode canonically after rejected reuse"),
            pre_restart.trapped_receipt_bytes
        );
        let next_nonce_after_reuse_attempt = verify_client
            .query_next_nonce(owner_a_address)
            .expect("next-nonce query should succeed after the rejected reuse attempt")
            .next_nonce();
        assert_eq!(next_nonce_after_reuse_attempt, pre_restart.next_nonce_a);
    })
    .await
    .unwrap();

    second_shutdown_tx
        .send(())
        .expect("shutdown signal should reach the still-running server task");
    second_server
        .await
        .expect("server task should not panic")
        .expect("graceful shutdown should complete without error");
    let closed_second_store = Arc::try_unwrap(second_store)
        .expect("no other durable-store reference should remain after the final shutdown");
    drop(closed_second_store);
    let closed_second_blob_store = Arc::try_unwrap(second_blob_store)
        .expect("no other blob-store reference should remain after the final shutdown");
    drop(closed_second_blob_store);
}
