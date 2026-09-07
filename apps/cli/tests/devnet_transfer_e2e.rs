//! Real loopback TCP E2E: the `transfer` subcommand against a real, seeded,
//! composed local devnet router, exactly as a user would invoke the
//! `sunrise-edge-cli` binary.
//!
//! This does not just check that the CLI command and a follow-up query
//! return success: it independently queries the transferred, fee, and
//! treasury coins afterward through `sunrise-edge-client` directly, decodes
//! their canonical bodies, and asserts the exact expected owner-only
//! mutation, fee debit/credit, and conservation.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use sunrise_edge_client::{
    Client, LoopbackHttpTransport, ObjectId, StandardAssetCoinV1, decode_object,
    decode_standard_asset_coin_v1,
};
use sunrise_edge_devnet::{
    DevOwner, DevnetConfig, STANDARD_ASSET_MODULE_WASM, boot_local_store,
    build_devnet_protocol_context, build_standard_asset_module, compose_devnet_router,
    genesis::{DEVNET_DOMAIN_BYTES, DEVNET_PROTOCOL_VERSION},
    seed_dev_owner_coins, seed_treasury_coin, verify_seeded_asset_supply,
};

const TRANSFER_COIN_AMOUNT: u64 = 1_000_000;
const EXPECTED_CHAIN_ID: &str = "cli-transfer-e2e-devnet";
const EXPECTED_EPOCH: &str = "11";
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
            "sunrise-edge-cli-transfer-seed-{}-{sequence}",
            std::process::id()
        ));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(hex.as_bytes()).unwrap();
        drop(file);
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

/// Queries `object_id` directly through `sunrise-edge-client` (independent
/// of anything the CLI itself printed) and decodes its canonical body as a
/// Standard Asset v1 coin. Coin bodies remain below DR-0096's fixed
/// blob-publication threshold, so seeing a blob reference here would be a
/// product-surface regression for the current CLI.
fn query_coin(
    client: &Client<LoopbackHttpTransport>,
    object_id: ObjectId,
) -> (
    sunrise_edge_client::ObjectRef,
    sunrise_edge_client::Owner,
    StandardAssetCoinV1,
) {
    let result = client
        .query_object(object_id)
        .expect("object query should succeed");
    match result {
        sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => {
            let object =
                decode_object(&canonical_object_bytes).expect("canonical object should decode");
            let coin = decode_standard_asset_coin_v1(&object.data)
                .expect("object body should decode as a Standard Asset v1 coin");
            (
                sunrise_edge_client::ObjectRef {
                    id: object_id,
                    version: object_version.get(),
                    digest,
                },
                object.owner,
                coin,
            )
        }
        other => panic!("expected object {object_id} to be CurrentInline, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_transfer_command_moves_the_whole_coin_through_the_real_devnet_router_over_tcp() {
    let owner_signer = sunrise_edge_client::LocalSigner::from_seed([0x5A; 32]);
    let owner_address = owner_signer.address();
    let recipient_address = sunrise_edge_client::LocalSigner::from_seed([0x5B; 32]).address();
    let treasury_address = sunrise_edge_client::LocalSigner::from_seed([0x6A; 32]).address();
    let seed_file = TempSeedFile::new([0x5A; 32]);

    let directory = TestDirectory::new("transfer-e2e");
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("cli-transfer-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("11"),
        OsString::from("--dev-owner"),
        OsString::from(owner_address.to_string()),
        OsString::from("--fee-treasury-owner"),
        OsString::from(treasury_address.to_string()),
        OsString::from("--max-concurrent"),
        OsString::from("4"),
    ])
    .unwrap();

    let boot = boot_local_store(&config).unwrap();
    let boot_generation = boot.boot_generation();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let asset_id = protocol_context.asset_id();
    let module =
        build_standard_asset_module(protocol_context, STANDARD_ASSET_MODULE_WASM.to_vec()).unwrap();

    let dev_owner = DevOwner::new(*owner_address.as_bytes());
    let now_unix_millis = SystemClock.now_unix_millis().unwrap();
    let seed_deadline = StorageDeadline::new(now_unix_millis + 30_000).unwrap();
    let seed_context = DurableOperationContext::new(
        boot_generation,
        seed_deadline,
        StorageCorrelationId::new([0x77; 16]).unwrap(),
    );
    let seed_outcome = seed_dev_owner_coins(
        boot.store(),
        boot.blob_store(),
        module.resolver(),
        config.epoch(),
        asset_id,
        dev_owner,
        boot_generation,
        &seed_context,
    )
    .unwrap();
    let treasury_context = DurableOperationContext::new(
        boot_generation,
        seed_deadline,
        StorageCorrelationId::new([0x78; 16]).unwrap(),
    );
    let treasury_outcome = seed_treasury_coin(
        boot.store(),
        boot.blob_store(),
        module.resolver(),
        config.epoch(),
        asset_id,
        config.fee_treasury_owner(),
        boot_generation,
        &treasury_context,
    )
    .unwrap();
    verify_seeded_asset_supply(std::slice::from_ref(&seed_outcome), &treasury_outcome).unwrap();
    let coins = seed_outcome.coins();
    let source_coin_id = coins.transfer_coin().id;
    let fee_coin_id = coins.fee_coin().id;
    let treasury_id = treasury_outcome.coin().coin().id;
    let module_ref = module.module_ref().clone();

    let (structured_store, blob_store) = boot.into_parts();
    let router = compose_devnet_router(
        Arc::new(structured_store),
        Arc::new(blob_store),
        module,
        boot_generation,
        config.max_concurrent(),
        2,
        treasury_id,
    )
    .unwrap();

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(native_http::serve(
        listener,
        router,
        std::future::pending::<()>(),
    ));

    let endpoint = address.to_string();
    let seed_path = seed_file.0.clone();
    tokio::task::spawn_blocking(move || {
        // Baseline: query every coin before the transfer, independent of the
        // seeding code above, so the assertions below are anchored to what
        // the running server itself reports.
        let verify_transport = LoopbackHttpTransport::new(
            address,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(1024 * 1024).unwrap(),
        )
        .unwrap();
        let verify_client = Client::new(verify_transport);

        let (source_ref_before, source_owner_before, source_before) =
            query_coin(&verify_client, source_coin_id);
        let (fee_ref_before, fee_owner_before, fee_before) =
            query_coin(&verify_client, fee_coin_id);
        let (treasury_ref_before, treasury_owner_before, treasury_before) =
            query_coin(&verify_client, treasury_id);
        assert_eq!(source_before.amount(), TRANSFER_COIN_AMOUNT);
        assert_eq!(
            source_owner_before,
            sunrise_edge_client::Owner::Address(owner_address)
        );
        assert_eq!(
            fee_owner_before,
            sunrise_edge_client::Owner::Address(owner_address)
        );
        assert_eq!(
            treasury_owner_before,
            sunrise_edge_client::Owner::Address(treasury_address)
        );

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
            OsString::from(source_coin_id.to_string()),
            OsString::from("--recipient"),
            OsString::from(recipient_address.to_string()),
            OsString::from("--fee-coin"),
            OsString::from(fee_coin_id.to_string()),
            OsString::from("--gas-limit"),
            OsString::from("1000000"),
            OsString::from("--fee-asset-id"),
            OsString::from(hex32(asset_id.as_bytes())),
            OsString::from("--max-fee"),
            OsString::from("1000001"),
            OsString::from("--fee-treasury-object"),
            OsString::from(treasury_id.to_string()),
            OsString::from("--request-id"),
            OsString::from("50".repeat(32)),
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
        .expect("transfer command should succeed against the real seeded devnet router");

        sunrise_edge_cli::run(vec![
            OsString::from("object"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--object-id"),
            OsString::from(source_coin_id.to_string()),
        ])
        .expect("post-transfer object query should succeed");

        // The real assertion: independently query and decode every coin
        // after the transfer and prove the exact expected owner-only
        // mutation, fee debit/credit, and conservation — not merely that
        // the commands above returned success.
        let (source_ref_after, source_owner_after, source_after) =
            query_coin(&verify_client, source_coin_id);
        let (fee_ref_after, fee_owner_after, fee_after) = query_coin(&verify_client, fee_coin_id);
        let (treasury_ref_after, treasury_owner_after, treasury_after) =
            query_coin(&verify_client, treasury_id);
        let charged_fee = treasury_after.amount() - treasury_before.amount();

        // Owner-only mutation: the transferred coin's owner changes to the
        // recipient, its data (asset id + amount) stays byte-identical, and
        // its version advances by exactly one.
        assert_eq!(
            source_owner_after,
            sunrise_edge_client::Owner::Address(recipient_address)
        );
        assert_eq!(source_after.asset_id(), source_before.asset_id());
        assert_eq!(source_after.amount(), source_before.amount());
        assert_eq!(source_ref_after.version, source_ref_before.version + 1);

        // Fee coin: owner unchanged, amount decreases by exactly the settled
        // fee, version advances by exactly one.
        assert_eq!(fee_owner_after, fee_owner_before);
        assert_eq!(
            fee_after.amount(),
            fee_before.amount() - charged_fee,
            "fee coin should decrease by exactly the settled fee"
        );
        assert_eq!(fee_ref_after.version, fee_ref_before.version + 1);

        // Treasury: owner unchanged, amount increases by exactly the same
        // settled fee, version advances by exactly one.
        assert_eq!(treasury_owner_after, treasury_owner_before);
        assert_eq!(treasury_ref_after.version, treasury_ref_before.version + 1);
        assert!(charged_fee > 1, "execution must add a non-zero metered fee");
        assert!(
            charged_fee < 1_000_001,
            "successful execution must charge actual gas, not the gas limit"
        );
        assert_eq!(
            fee_after.amount() + treasury_after.amount(),
            fee_before.amount() + treasury_before.amount(),
            "the fee asset must be conserved across fee settlement"
        );
    })
    .await
    .unwrap();

    server.abort();
    let _ignored = server.await;
}
