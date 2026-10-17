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

/// Separate two-owner genesis fixture: a real whole Coin moves A -> B -> A.
/// It does not change application creator authority or migrate fee balances.
#[test]
#[ignore = "requires the bounded Docker distinct-UID genesis Coin handoff fixture"]
fn distinct_uid_genesis_coin_identity_handoff_probe() {
    use std::{collections::BTreeSet, io::Read, net::SocketAddr};
    use sunrise_edge_client::{
        Client, HttpObjectQueryResult, LoopbackHttpTransport, Object, ObjectEffect, ObjectId,
        Owner, PaidApplication, PaidChargedOutcome, PaidExecutionResult, PaidExecutionStatus,
        RequestId, SignedPaidIntent,
    };

    fn read(path: &Path) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        std::fs::File::open(path)
            .unwrap()
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 1_048_576);
        bytes
    }
    fn current(client: &Client<LoopbackHttpTransport>, id: ObjectId) -> (Object, Vec<u8>) {
        let HttpObjectQueryResult::CurrentInline {
            canonical_object_bytes,
            object_version,
            ..
        } = client.query_object(id).unwrap()
        else {
            panic!("handoff object must be current inline");
        };
        let object: Object = objects::decode_object(&canonical_object_bytes).unwrap();
        assert_eq!(object.id, id);
        assert_eq!(object.version, object_version.get());
        assert_eq!(
            objects::encode_object(&object).unwrap(),
            canonical_object_bytes
        );
        (object, canonical_object_bytes)
    }

    let mode: String = required("CUSTODY_HANDOFF_MODE");
    let directory: PathBuf = required("CUSTODY_HANDOFF_DIR").into();
    let owners: [Address; 2] = ["CUSTODY_HANDOFF_A", "CUSTODY_HANDOFF_B"].map(|name: &str| {
        Address::new(crate::hex::decode_hex_32("handoff publisher", &required(name)).unwrap())
    });
    let fee_recipient: Address = LocalSigner::from_seed([0x7A; 32]).address();
    assert_ne!(owners[0], owners[1]);
    assert!(!owners.contains(&fee_recipient));
    let protocol: sunrise_edge_devnet::DevnetProtocolContext =
        sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("custody-whole-coin-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
    let context: PublicationContext = PublicationContext::new(
        protocol.chain_id().clone(),
        protocol.resolver().protocol_version(),
        protocol.epoch(),
    )
    .unwrap();
    let (manifest, metadata): (
        node_core::genesis::GenesisManifest,
        sunrise_edge_devnet::PaidGenesisActivationMetadata,
    ) = sunrise_edge_devnet::build_paid_genesis_manifest(
        protocol.resolver(),
        &context,
        &owners.map(|owner: Address| DevOwner::new(*owner.as_bytes())),
        DevOwner::new(*fee_recipient.as_bytes()),
    )
    .unwrap();
    assert_eq!(metadata.owner_coins.len(), 2);
    let target: ObjectId = metadata.owner_coins[0].spend_coin;
    let fee_ids: [ObjectId; 2] = [
        metadata.owner_coins[0].fee_coin,
        metadata.owner_coins[1].fee_coin,
    ];
    assert_ne!(fee_ids[0], fee_ids[1]);
    assert!(!fee_ids.contains(&target));
    let original: &Object = &manifest
        .objects
        .iter()
        .find(|row| row.object.id == target)
        .unwrap()
        .object;
    let original_fees: [&Object; 2] = fee_ids.map(|id: ObjectId| {
        &manifest
            .objects
            .iter()
            .find(|row| row.object.id == id)
            .unwrap()
            .object
    });
    assert_eq!(original.id, target);
    assert_eq!(original.version, 1);
    assert_eq!(original.owner, Owner::Address(owners[0]));
    assert_eq!(
        original.schema_version,
        public_standard_asset::SCHEMA_VERSION
    );
    assert_eq!(
        public_standard_asset::coin_amount(&original.data).unwrap(),
        sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
    );
    for (index, fee) in original_fees.iter().enumerate() {
        assert_eq!(fee.id, fee_ids[index]);
        assert_eq!(fee.owner, Owner::Address(owners[index]));
        assert_eq!(fee.version, 1);
        assert_eq!(fee.type_hash, original.type_hash);
        assert_eq!(fee.schema_version, public_standard_asset::SCHEMA_VERSION);
        assert_eq!(
            public_standard_asset::coin_amount(&fee.data).unwrap(),
            sunrise_edge_devnet::DEVNET_PAID_FEE_COIN_BALANCE
        );
    }
    match mode.as_str() {
        "generate" => {
            let digest: sunrise_edge_client::Digest32 =
                node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                    .unwrap();
            let exports: [(&str, Vec<u8>); 4] = [
                (
                    "genesis.bin",
                    node_core::genesis::encode_genesis_manifest(&manifest).unwrap(),
                ),
                ("coin-v1.bin", objects::encode_object(original).unwrap()),
                (
                    "fee-a.bin",
                    objects::encode_object(original_fees[0]).unwrap(),
                ),
                (
                    "fee-b.bin",
                    objects::encode_object(original_fees[1]).unwrap(),
                ),
            ];
            for (name, bytes) in exports {
                super::write_review_preimage(&directory.join(name), &bytes).unwrap();
            }
            println!(
                "{{\"mode\":\"generate\",\"digest\":\"{}\",\"coin\":\"{target}\",\"fee_a\":\"{}\",\"fee_b\":\"{}\",\"owner_a\":\"{}\",\"owner_b\":\"{}\"}}",
                crate::hex::encode_hex(&digest.bytes()),
                fee_ids[0],
                fee_ids[1],
                owners[0],
                owners[1]
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
                owners[0].to_string(),
                "--dev-owner".to_owned(),
                owners[1].to_string(),
                "--fee-recipient".to_owned(),
                fee_recipient.to_string(),
                "--max-concurrent".to_owned(),
                "4".to_owned(),
            ])
            .unwrap();
            let boot: sunrise_edge_devnet::DevnetBoot =
                sunrise_edge_devnet::boot_local_store(&config).unwrap();
            let fence: runtime::WriterFenceGeneration = boot.boot_generation();
            let operation = |id: u8| -> runtime::DurableOperationContext {
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
            let activation: sunrise_edge_devnet::PaidContractActivation =
                sunrise_edge_devnet::install_paid_contracts(
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
            let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener: tokio::net::TcpListener =
                    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                println!("{{\"address\":\"{}\"}}", listener.local_addr().unwrap());
                std::io::stdout().flush().unwrap();
                let stopped: PathBuf = directory.join("stop-native");
                let stop_signal: PathBuf = stopped.clone();
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
                    "handoff requires explicit bounded completion"
                );
            });
        }
        "after-a" | "after-b" => {
            let endpoint: SocketAddr = required("CUSTODY_HANDOFF_ENDPOINT").parse().unwrap();
            let transport: LoopbackHttpTransport = LoopbackHttpTransport::new(
                endpoint,
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
                std::num::NonZeroUsize::new(16384).unwrap(),
                std::num::NonZeroUsize::new(1_048_576).unwrap(),
            )
            .unwrap();
            let client: Client<LoopbackHttpTransport> = Client::new(transport);
            let stage: usize = if mode == "after-a" { 1 } else { 2 };
            assert_eq!(
                read(&directory.join("genesis.bin")),
                node_core::genesis::encode_genesis_manifest(&manifest).unwrap()
            );
            let (live, live_bytes): (Object, Vec<u8>) = current(&client, target);
            assert_eq!(live.owner, Owner::Address(owners[stage % 2]));
            assert_eq!(live.version, u64::try_from(stage).unwrap() + 1);
            assert_eq!(live.type_hash, original.type_hash);
            assert_eq!(live.schema_version, original.schema_version);
            assert_eq!(live.data, original.data);
            assert_eq!(
                public_standard_asset::coin_amount(&live.data).unwrap(),
                sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
            );
            assert_eq!(client.query_next_nonce(owners[0]).unwrap().next_nonce(), 1);
            assert_eq!(
                client.query_next_nonce(owners[1]).unwrap().next_nonce(),
                u64::try_from(stage - 1).unwrap()
            );
            let mut observed: BTreeSet<ObjectId> = [
                target,
                fee_ids[0],
                fee_ids[1],
                metadata.owner_coins[1].spend_coin,
            ]
            .into_iter()
            .collect();
            let mut accepted: Vec<(SignedPaidIntent, Vec<u8>, Vec<u8>)> = Vec::with_capacity(stage);
            for index in 0..stage {
                let tag: &str = if index == 0 { "a" } else { "b" };
                let signed_bytes: Vec<u8> = read(&directory.join(format!("{tag}-submission.bin")));
                assert_eq!(
                    read(&directory.join(format!("{tag}-offline.bin"))),
                    signed_bytes
                );
                let signed: SignedPaidIntent =
                    sunrise_edge_client::decode_signed_paid_intent(&signed_bytes).unwrap();
                let authenticated: execution::paid_execution::AuthenticatedPaidIntent =
                    sunrise_edge_client::authenticate_paid_intent(
                        protocol.resolver(),
                        &context,
                        &signed_bytes,
                    )
                    .unwrap();
                assert_eq!(
                    sunrise_edge_client::encode_signed_paid_intent(&signed).unwrap(),
                    signed_bytes
                );
                assert_eq!(signed.intent.context, context);
                assert_eq!(signed.intent.sender, *owners[index].as_bytes());
                assert_eq!(
                    signed.intent.request_id,
                    [if index == 0 { 0xb1 } else { 0xb2 }; 32]
                );
                assert_eq!(signed.intent.nonce, 0);
                assert_eq!(signed.intent.consent.source.id, fee_ids[index]);
                assert_eq!(signed.intent.consent.source.version, 1);
                assert_eq!(
                    signed.intent.consent.access,
                    sunrise_edge_client::ReservationAccessKind::Write
                );
                assert_eq!(
                    signed.intent.consent.refund_recipient,
                    *owners[index].as_bytes()
                );
                assert_eq!(signed.intent.consent.max_fee.get(), 1_000_000);
                assert_eq!(signed.intent.gas_limit, 200_000);
                let PaidApplication::Call(call) = &signed.intent.application else {
                    panic!("handoff requires paid Call");
                };
                assert_eq!(call.context, context);
                assert_eq!(call.sender, *owners[index].as_bytes());
                assert_eq!(call.nonce, 0);
                assert_eq!(call.request_id, signed.intent.request_id);
                assert_eq!(call.gas_limit, 200_000);
                assert_eq!(
                    call.type_arguments,
                    vec![public_standard_asset::asset_type_argument(
                        &metadata.definition_id
                    )]
                );
                assert_eq!(call.code, manifest.fee_policy.code);
                assert_eq!(call.instance, manifest.fee_policy.instance);
                assert_eq!(call.entrypoint, "transfer");
                assert_eq!(
                    call.arguments,
                    public_standard_asset::transfer_arguments(owners[1 - index].as_bytes())
                        .unwrap()
                );
                assert_eq!(call.access.entries.len(), 1);
                assert_eq!(call.access.entries[0].object_ref.id, target);
                assert_eq!(
                    call.access.entries[0].object_ref.version,
                    u64::try_from(index).unwrap() + 1
                );
                assert_eq!(
                    call.access.entries[0].mode,
                    sunrise_edge_client::AccessMode::Write
                );
                let result_bytes: Vec<u8> = read(&directory.join(format!("{tag}-result.bin")));
                let result: PaidExecutionResult =
                    sunrise_edge_client::decode_paid_execution_result(&result_bytes).unwrap();
                assert_eq!(
                    sunrise_edge_client::encode_paid_execution_result(&result).unwrap(),
                    result_bytes
                );
                assert_eq!(result.kind, sunrise_edge_client::PaidResultKind::Call);
                let sunrise_edge_client::PaidResultTarget::Instance(record) = &result.target else {
                    panic!("paid Call instance receipt");
                };
                assert_eq!(
                    execution::local_execution::instance_target(protocol.resolver(), record)
                        .unwrap(),
                    manifest.fee_policy.instance
                );
                assert_eq!(result.status, PaidExecutionStatus::Success);
                assert_eq!(result.request_id, signed.intent.request_id);
                assert_eq!(
                    result.effects.tx_hash,
                    sunrise_edge_client::paid_invocation_digest(protocol.resolver(), &signed)
                        .unwrap()
                );
                let charged: &PaidChargedOutcome = result.charged.as_ref().unwrap();
                assert!(charged.actual.get() > 0);
                let base_policy: execution::local_execution::LocalExecutionPolicy =
                    execution::local_execution::LocalExecutionPolicy::generic_object_results(
                        context.clone(),
                    );
                let admission: fees::reservation::Admission =
                    execution::paid_execution::quote_paid_intent(
                        &authenticated,
                        protocol.resolver(),
                        &base_policy,
                        &manifest.fee_policy,
                    )
                    .unwrap();
                let settlement: fees::reservation::Settlement =
                    admission.settle(charged.application_gas_units).unwrap();
                assert_eq!(charged.reserved, admission.reserved());
                assert_eq!(charged.actual, settlement.actual);
                assert_eq!(charged.refund, settlement.refund);
                assert_eq!(
                    charged
                        .actual
                        .get()
                        .checked_add(charged.refund.get())
                        .unwrap(),
                    charged.reserved.get()
                );
                let expected_bytes: Vec<u8> = if index + 1 == stage {
                    live_bytes.clone()
                } else {
                    read(&directory.join("coin-v2.bin"))
                };
                let effects: Vec<&ObjectEffect> = result.effects.object_effects.iter()
                    .filter(|effect: &&ObjectEffect| matches!(effect, ObjectEffect::Mutated { new_object, .. } if new_object.id==target)).collect();
                let [
                    ObjectEffect::Mutated {
                        previous_version,
                        new_object,
                    },
                ] = effects.as_slice()
                else {
                    panic!("one exact handoff mutation");
                };
                assert_eq!(*previous_version, u64::try_from(index).unwrap() + 1);
                assert_eq!(new_object.id, target);
                assert_eq!(new_object.version, u64::try_from(index).unwrap() + 2);
                assert_eq!(new_object.owner, Owner::Address(owners[1 - index]));
                assert_eq!(new_object.type_hash, original.type_hash);
                assert_eq!(new_object.schema_version, original.schema_version);
                assert_eq!(new_object.data, original.data);
                assert_eq!(objects::encode_object(new_object).unwrap(), expected_bytes);
                let input_bytes: Vec<u8> = if index == 0 {
                    objects::encode_object(original).unwrap()
                } else {
                    read(&directory.join("coin-v2.bin"))
                };
                assert_eq!(
                    call.access.entries[0].object_ref.digest,
                    protocol
                        .resolver()
                        .hash_for_purpose(
                            Epoch::new(0),
                            protocol_types::HashPurpose::Object,
                            &input_bytes
                        )
                        .unwrap()
                );
                assert_eq!(
                    signed.intent.consent.source.digest,
                    protocol
                        .resolver()
                        .hash_for_purpose(
                            Epoch::new(0),
                            protocol_types::HashPurpose::Object,
                            &objects::encode_object(original_fees[index]).unwrap()
                        )
                        .unwrap()
                );
                let (fee, fee_bytes): (Object, Vec<u8>) = current(&client, fee_ids[index]);
                assert_eq!(fee.owner, Owner::Address(owners[index]));
                assert_eq!(fee.type_hash, original_fees[index].type_hash);
                assert_eq!(fee.schema_version, original_fees[index].schema_version);
                assert_eq!(fee.version, 2);
                assert_eq!(
                    public_standard_asset::coin_amount(&fee.data).unwrap(),
                    sunrise_edge_devnet::DEVNET_PAID_FEE_COIN_BALANCE
                        .checked_sub(charged.reserved.get())
                        .unwrap()
                );
                if stage == 1 {
                    super::write_review_preimage(&directory.join("a-fee-after.bin"), &fee_bytes)
                        .unwrap();
                } else if index == 0 {
                    assert_eq!(read(&directory.join("a-fee-after.bin")), fee_bytes);
                }
                let allowed_fee_ids: BTreeSet<ObjectId> = [
                    Some(fee_ids[index]),
                    Some(charged.fee_output.id),
                    Some(charged.reservation),
                    charged.refund_output.as_ref().map(|output| output.id),
                ]
                .into_iter()
                .flatten()
                .collect();
                assert!(!allowed_fee_ids.contains(&target));
                let mut application_ids: BTreeSet<ObjectId> = BTreeSet::new();
                let mut effect_ids: BTreeSet<ObjectId> = BTreeSet::new();
                for effect in &result.effects.object_effects {
                    let id: ObjectId = match effect {
                        ObjectEffect::Created(object) => object.id,
                        ObjectEffect::Mutated { new_object, .. } => new_object.id,
                        ObjectEffect::Deleted { id, .. } => *id,
                    };
                    assert!(effect_ids.insert(id));
                    if !allowed_fee_ids.contains(&id) {
                        application_ids.insert(id);
                    }
                    if id != target {
                        match effect {
                            ObjectEffect::Created(object)
                            | ObjectEffect::Mutated {
                                new_object: object, ..
                            } => assert_eq!(
                                current(&client, id).1,
                                objects::encode_object(object).unwrap()
                            ),
                            ObjectEffect::Deleted { version, .. } => {
                                assert!(matches!(client.query_object(id).unwrap(),
                                HttpObjectQueryResult::Tombstoned { last_object_version, .. } if last_object_version.get()==*version))
                            }
                        }
                    }
                }
                let expected_application_ids: BTreeSet<ObjectId> = [target].into_iter().collect();
                assert_eq!(application_ids, expected_application_ids);
                for (output, expected_owner, amount) in [
                    (
                        Some(&charged.fee_output),
                        fee_recipient,
                        charged.actual.get(),
                    ),
                    (
                        charged.refund_output.as_ref(),
                        owners[index],
                        charged.refund.get(),
                    ),
                ] {
                    if let Some(reference) = output {
                        let (object, bytes): (Object, Vec<u8>) = current(&client, reference.id);
                        assert_eq!(object.version, reference.version);
                        assert_eq!(object.owner, Owner::Address(expected_owner));
                        assert_eq!(object.type_hash, original_fees[index].type_hash);
                        assert_eq!(object.schema_version, original_fees[index].schema_version);
                        assert_eq!(
                            public_standard_asset::coin_amount(&object.data).unwrap(),
                            amount
                        );
                        assert_eq!(
                            reference.digest,
                            protocol
                                .resolver()
                                .hash_for_purpose(
                                    Epoch::new(0),
                                    protocol_types::HashPurpose::Object,
                                    &bytes
                                )
                                .unwrap()
                        );
                    } else {
                        assert_eq!(amount, 0);
                    }
                }
                // Reserve and settle create and consume this object in one invocation,
                // so it has neither a durable object effect nor a durable object head.
                assert!(!effect_ids.contains(&charged.reservation));
                let reservation_query: HttpObjectQueryResult =
                    client.query_object(charged.reservation).unwrap();
                assert_eq!(
                    reservation_query,
                    HttpObjectQueryResult::Absent {
                        object_id: charged.reservation,
                    }
                );
                for effect in &result.effects.object_effects {
                    observed.insert(match effect {
                        ObjectEffect::Created(object) => object.id,
                        ObjectEffect::Mutated { new_object, .. } => new_object.id,
                        ObjectEffect::Deleted { id, .. } => *id,
                    });
                }
                let request: RequestId = RequestId::new(signed.intent.request_id).unwrap();
                let receipt: sunrise_edge_client::HttpReceiptQueryResult =
                    client.query_receipt(request).unwrap();
                assert!(
                    matches!(&receipt, sunrise_edge_client::HttpReceiptQueryResult::Present { request_id, event_digest, .. }
                    if *request_id==request && *event_digest==result.effects.tx_hash)
                );
                let receipt_bytes: Vec<u8> = receipt.encode().unwrap();
                let receipt_path: PathBuf = directory.join(format!("{tag}-receipt.bin"));
                if stage == 1 || index == 1 {
                    super::write_review_preimage(&receipt_path, &receipt_bytes).unwrap();
                } else {
                    assert_eq!(read(&receipt_path), receipt_bytes);
                }
                accepted.push((signed, result_bytes, receipt_bytes));
            }
            // B's independent fee and untouched spend Coin are genuine genesis funding.
            if stage == 1 {
                assert_eq!(
                    current(&client, fee_ids[1]).1,
                    objects::encode_object(original_fees[1]).unwrap()
                );
            }
            let untouched: &Object = &manifest
                .objects
                .iter()
                .find(|row| row.object.id == metadata.owner_coins[1].spend_coin)
                .unwrap()
                .object;
            assert_eq!(
                current(&client, untouched.id).1,
                objects::encode_object(untouched).unwrap()
            );
            let before: Vec<(ObjectId, Vec<u8>)> = observed
                .iter()
                .map(|id: &ObjectId| (*id, client.query_object(*id).unwrap().encode().unwrap()))
                .collect();
            for (signed, result_bytes, receipt_bytes) in &accepted {
                let replay: PaidExecutionResult = client
                    .submit_paid_execution(signed, protocol.resolver())
                    .unwrap();
                assert_eq!(
                    sunrise_edge_client::encode_paid_execution_result(&replay).unwrap(),
                    *result_bytes
                );
                assert_eq!(
                    client
                        .query_receipt(RequestId::new(signed.intent.request_id).unwrap())
                        .unwrap()
                        .encode()
                        .unwrap(),
                    *receipt_bytes
                );
            }
            for (id, bytes) in before {
                assert_eq!(client.query_object(id).unwrap().encode().unwrap(), bytes);
            }
            assert_eq!(client.query_next_nonce(owners[0]).unwrap().next_nonce(), 1);
            assert_eq!(
                client.query_next_nonce(owners[1]).unwrap().next_nonce(),
                u64::try_from(stage - 1).unwrap()
            );
            super::write_review_preimage(
                &directory.join(if stage == 1 {
                    "coin-v2.bin"
                } else {
                    "coin-v3.bin"
                }),
                &live_bytes,
            )
            .unwrap();
            println!(
                "{{\"mode\":\"{mode}\",\"verified\":true,\"version\":{},\"owner\":\"{}\",\"nonce_a\":1,\"nonce_b\":{},\"replay_count\":{stage},\"paid_effects\":true,\"separate_fee\":true}}",
                live.version,
                owners[stage % 2],
                stage - 1
            );
        }
        _ => panic!("unknown handoff fixture mode"),
    }
}
