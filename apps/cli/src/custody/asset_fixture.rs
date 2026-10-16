//! Exact ignored entry point for the contained, distinct-UID transfer fixture.
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use sunrise_edge_client::{Address, ChainId, Epoch, LocalSigner, PublicationContext};
use sunrise_edge_devnet::{DevOwner, DevnetConfig};

fn required(name: &str) -> String {
    std::env::var(name).expect("transfer fixture missing explicit prerequisite")
}

#[test]
#[ignore = "requires the bounded Docker distinct-UID transfer fixture"]
fn distinct_uid_transfer_probe() {
    let mode: String = required("CUSTODY_TRANSFER_MODE");
    let directory: PathBuf = required("CUSTODY_TRANSFER_DIR").into();
    let owner: Address = Address::new(
        crate::hex::decode_hex_32(
            "fixture public key",
            &required("CUSTODY_TRANSFER_PUBLIC_KEY"),
        )
        .unwrap(),
    );
    let recipient: Address = LocalSigner::from_seed([0x74; 32]).address();
    let fee_recipient: Address = LocalSigner::from_seed([0x7A; 32]).address();
    let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
        ChainId::new("custody-whole-coin-test").unwrap(),
        Epoch::new(0),
    )
    .unwrap();
    let context = PublicationContext::new(
        protocol.chain_id().clone(),
        protocol.resolver().protocol_version(),
        protocol.epoch(),
    )
    .unwrap();
    let (manifest, metadata) = sunrise_edge_devnet::build_paid_genesis_manifest(
        protocol.resolver(),
        &context,
        &[DevOwner::new(*owner.as_bytes())],
        DevOwner::new(*fee_recipient.as_bytes()),
    )
    .unwrap();
    let coins = metadata.owner_coins[0];
    match mode.as_str() {
        "generate" => {
            let digest =
                node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                    .unwrap();
            for (name, bytes) in [
                (
                    "genesis.bin",
                    node_core::genesis::encode_genesis_manifest(&manifest).unwrap(),
                ),
                (
                    "coin.bin",
                    objects::encode_object(
                        &manifest
                            .objects
                            .iter()
                            .find(|entry| entry.object.id == coins.spend_coin)
                            .unwrap()
                            .object,
                    )
                    .unwrap(),
                ),
                (
                    "fee.bin",
                    objects::encode_object(
                        &manifest
                            .objects
                            .iter()
                            .find(|entry| entry.object.id == coins.fee_coin)
                            .unwrap()
                            .object,
                    )
                    .unwrap(),
                ),
            ] {
                super::write_review_preimage(&directory.join(name), &bytes).unwrap();
            }
            println!(
                "{{\"mode\":\"generate\",\"digest\":\"{}\",\"coin\":\"{}\",\"fee\":\"{}\",\"recipient\":\"{}\"}}",
                crate::hex::encode_hex(&digest.bytes()),
                coins.spend_coin,
                coins.fee_coin,
                recipient
            );
        }
        "serve" => {
            let config: DevnetConfig = DevnetConfig::parse_from(vec![
                "--data-dir".to_owned(),
                directory.join("node").display().to_string(),
                "--listen".to_owned(),
                "127.0.0.1:7400".to_owned(),
                "--chain-id".to_owned(),
                "custody-whole-coin-test".to_owned(),
                "--epoch".to_owned(),
                "0".to_owned(),
                "--dev-owner".to_owned(),
                owner.to_string(),
                "--fee-recipient".to_owned(),
                fee_recipient.to_string(),
                "--max-concurrent".to_owned(),
                "4".to_owned(),
            ])
            .unwrap();
            let boot: sunrise_edge_devnet::DevnetBoot =
                sunrise_edge_devnet::boot_local_store(&config).unwrap();
            let fence = boot.boot_generation();
            let operation = |id: u8| {
                runtime::DurableOperationContext::new(
                    fence,
                    runtime::StorageDeadline::new(u64::MAX).unwrap(),
                    runtime::StorageCorrelationId::new([id; 16]).unwrap(),
                )
            };
            sunrise_edge_devnet::verify_or_seed_protocol_context(
                boot.store(),
                protocol.resolver(),
                protocol.epoch(),
                fence,
                &operation(1),
                true,
            )
            .unwrap();
            let activation = sunrise_edge_devnet::install_paid_contracts(
                boot.store(),
                &operation(2),
                protocol.domain(),
                protocol.resolver(),
                &context,
                config.dev_owners(),
                config.fee_recipient(),
            )
            .unwrap();
            assert_eq!(
                activation.manifest_digest,
                node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                    .unwrap()
            );
            let (store, blobs) = boot.into_parts();
            let router = sunrise_edge_devnet::compose_devnet_router(
                Arc::new(store),
                Arc::new(blobs),
                protocol,
                fence,
                4,
                2,
                native_http::PaidExecutionComposition::new(
                    activation.base_policy,
                    activation.fee_policy,
                ),
            )
            .unwrap();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let stop_directory = directory.clone();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                println!("{{\"address\":\"{}\"}}", listener.local_addr().unwrap());
                std::io::stdout().flush().unwrap();
                let stopped = stop_directory.join("stop-native");
                let stop_signal = stopped.clone();
                native_http::serve_with_policy(
                    listener,
                    router,
                    native_http::NativeHttpServePolicy::default(),
                    async move {
                        for _ in 0..600 {
                            if stop_signal.is_file() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    },
                )
                .await
                .unwrap();
                assert!(
                    stopped.is_file(),
                    "bounded fixture requires explicit completion signal"
                );
            });
        }
        "verify" => {
            let address = required("CUSTODY_TRANSFER_ENDPOINT").parse().unwrap();
            let transport = sunrise_edge_client::LoopbackHttpTransport::new(
                address,
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
                std::num::NonZeroUsize::new(16384).unwrap(),
                std::num::NonZeroUsize::new(1048576).unwrap(),
            )
            .unwrap();
            let client = sunrise_edge_client::Client::new(transport);
            let sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
                canonical_object_bytes,
                object_version,
                ..
            } = client.query_object(coins.spend_coin).unwrap()
            else {
                panic!("transferred coin must remain inline");
            };
            let object = objects::decode_object(&canonical_object_bytes).unwrap();
            assert_eq!(object.owner, sunrise_edge_client::Owner::Address(recipient));
            assert_ne!(recipient.as_bytes(), &manifest.fee_policy.fee_recipient);
            assert_eq!(
                public_standard_asset::coin_amount(&object.data).unwrap(),
                sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
            );
            assert_eq!(object_version.get(), 2);
            assert_eq!(client.query_next_nonce(owner).unwrap().next_nonce(), 1);
            let signed = std::fs::read(directory.join("submission.bin")).unwrap();
            let decoded = sunrise_edge_client::decode_signed_paid_intent(&signed).unwrap();
            let replay = client
                .submit_paid_execution(&decoded, protocol.resolver())
                .unwrap();
            assert_eq!(
                replay.status,
                sunrise_edge_client::PaidExecutionStatus::Success
            );
            assert_eq!(client.query_next_nonce(owner).unwrap().next_nonce(), 1);
            assert_eq!(
                std::fs::read(directory.join("submission.bin")).unwrap(),
                signed
            );
            let result = sunrise_edge_client::encode_paid_execution_result(&replay).unwrap();
            assert_eq!(std::fs::read(directory.join("result.bin")).unwrap(), result);
            println!(
                "{{\"mode\":\"verify\",\"whole_coin\":true,\"replay_equal\":true,\"nonce\":1}}"
            );
        }
        _ => panic!("unknown transfer fixture mode"),
    }
    assert!(Path::new(&directory).is_dir());
}
