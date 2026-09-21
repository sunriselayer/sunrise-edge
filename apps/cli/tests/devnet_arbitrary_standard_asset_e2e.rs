//! Real SQLite -> native HTTP -> CLI coverage for DR-0128 arbitrary Standard Asset creation.

mod common;

use common::{
    TestDirectory, application_created_object, current_coin_amount, decode_result, devnet_config,
    operation, test_directory, transport, write_seed,
};

use execution::{
    ObjectEffect,
    call::InstanceTarget,
    local_execution::{InstanceRecord, decode_instance_record, instance_target},
    paid_execution::{
        PaidExecutionResult, PaidExecutionStatus, PaidFeePolicy, SignedPaidIntent,
        decode_signed_paid_intent,
    },
    publication::PublicationContext,
};
use objects::{Object, ObjectId, Owner, decode_object};
use protocol_types::{AtomicityDomainId, HashPurpose, HashSuiteId, SignatureSchemeId};
use public_standard_asset::{
    SCHEMA_VERSION, coin_amount, definition_body, definition_type_tag, treasury_cap_type_tag,
    treasury_supply,
};
use runtime::{DurableReadError, WriterFenceGeneration};
use std::{ffi::OsString, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use sunrise_edge_client::{
    Client, ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, ExpectedProtocolContext,
    HttpObjectQueryResult, HttpReceiptQueryResult, LocalSigner, LoopbackHttpTransport, RequestId,
    package_types::{ScopedTypeTag, verify_scoped_type_id},
};
use sunrise_edge_devnet::{
    DevnetBoot, DevnetConfig, DevnetProtocolContext, DevnetSeedError, PaidContractActivation,
    boot_local_store, build_devnet_protocol_context, compose_devnet_router,
    genesis::DEVNET_DOMAIN_BYTES, install_paid_contracts, paid_genesis_authority,
    verify_or_seed_protocol_context,
};

const CHAIN_ID: &str = "cli-arbitrary-standard-asset";
const EPOCH: u64 = 9;
const GAS_LIMIT: u64 = 200_000;
const MAX_FEE: u64 = 1_000_000;

fn hex_32(bytes: &[u8; 32]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arbitrary_standard_asset_creation_lifecycle_and_fencing() {
    let directory: TestDirectory = test_directory("arbitrary-asset");
    let seed_path: PathBuf = directory.0.join("owner.seed");
    write_seed(&seed_path, 7);
    let owner: LocalSigner = LocalSigner::from_seed([7; 32]);
    let recipient: LocalSigner = LocalSigner::from_seed([9; 32]);
    let config: DevnetConfig = devnet_config(&directory.0, &owner, &recipient, CHAIN_ID, EPOCH);
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap();

    let boot: DevnetBoot = boot_local_store(&config).unwrap();
    let first_generation: WriterFenceGeneration = boot.boot_generation();
    let protocol: DevnetProtocolContext =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    verify_or_seed_protocol_context(
        boot.store(),
        protocol.resolver(),
        config.epoch(),
        first_generation,
        &operation(first_generation, 1),
        true,
    )
    .unwrap();
    let publication: PublicationContext = PublicationContext::new(
        config.chain_id().clone(),
        protocol.resolver().protocol_version(),
        config.epoch(),
    )
    .unwrap();
    let activation: PaidContractActivation = install_paid_contracts(
        boot.store(),
        &operation(first_generation, 2),
        domain,
        protocol.resolver(),
        &publication,
        config.dev_owners(),
        config.fee_recipient(),
    )
    .unwrap();
    assert!(matches!(
        activation.outcome,
        node_core::genesis::GenesisInstallOutcome::FreshInstall { .. }
    ));
    let initial_fee: ObjectId = activation.metadata.owner_coins[0].fee_coin;
    let genesis_spend: ObjectId = activation.metadata.owner_coins[0].spend_coin;
    let genesis_cap: ObjectId = activation.metadata.treasury_cap_id;
    let fee_policy: PaidFeePolicy = activation.fee_policy.clone();
    let paid =
        native_http::PaidExecutionComposition::new(activation.base_policy, activation.fee_policy);
    let (store, blobs) = boot.into_parts();
    let router = compose_devnet_router(
        Arc::new(store),
        Arc::new(blobs),
        protocol.clone(),
        first_generation,
        4,
        2,
        paid,
    )
    .unwrap();
    let listener: tokio::net::TcpListener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_address: SocketAddr = listener.local_addr().unwrap();
    let (first_stop, first_shutdown): (
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) = tokio::sync::oneshot::channel::<()>();
    let first_server = tokio::spawn(native_http::serve_with_policy(
        listener,
        router,
        native_http::NativeHttpServePolicy::default(),
        async {
            let _ignored: Result<(), tokio::sync::oneshot::error::RecvError> = first_shutdown.await;
        },
    ));
    let initial_client: Client<LoopbackHttpTransport> = Client::new(transport(first_address));
    let initial_spend_amount: u64 =
        current_coin_amount(&initial_client.query_object(genesis_spend).unwrap());
    let initial_fee_amount: u64 =
        current_coin_amount(&initial_client.query_object(initial_fee).unwrap());
    assert_eq!(
        initial_spend_amount,
        sunrise_edge_devnet::DEVNET_PAID_SPEND_COIN_BALANCE
    );
    assert_eq!(
        initial_fee_amount,
        sunrise_edge_devnet::DEVNET_PAID_FEE_COIN_BALANCE
    );

    let second_asset_seed: [u8; 32] = [0x22; 32];
    let creation_request_id_bytes: [u8; 32] = [0x31; 32];
    let creation_request_id: RequestId = RequestId::new(creation_request_id_bytes).unwrap();
    let instance_ref_path: PathBuf = directory.0.join("second_asset.instance");

    let path: PathBuf = directory.0.clone();
    let seed_path_clone: PathBuf = seed_path.clone();
    let creation_owner: LocalSigner = owner.clone();
    let creation_protocol: DevnetProtocolContext = protocol.clone();
    let creation_config: DevnetConfig = config.clone();
    let creation_fee_policy: PaidFeePolicy = fee_policy.clone();

    // 1. Create arbitrary second Standard Asset with create-asset
    let (creation_result, second_asset_id, second_cap_id): (
        PaidExecutionResult,
        ObjectId,
        ObjectId,
    ) = tokio::task::spawn_blocking(move || {
        let common_args =
            |action: &str, nonce: u64, req_id: &[u8; 32], fee: ObjectId| -> Vec<String> {
                let name: String = format!("{nonce}-{action}");
                vec![
                    action.to_owned(),
                    "--endpoint".into(),
                    first_address.to_string(),
                    "--expected-chain-id".into(),
                    CHAIN_ID.into(),
                    "--expected-protocol-version".into(),
                    "7".into(),
                    "--expected-epoch".into(),
                    EPOCH.to_string(),
                    "--expected-hash-suite-id".into(),
                    "1".into(),
                    "--expected-domain".into(),
                    domain.to_string(),
                    "--seed-file".into(),
                    seed_path_clone.display().to_string(),
                    "--fee-source".into(),
                    fee.to_string(),
                    "--max-fee".into(),
                    MAX_FEE.to_string(),
                    "--gas-limit".into(),
                    GAS_LIMIT.to_string(),
                    "--request-id".into(),
                    hex_32(req_id),
                    "--nonce".into(),
                    nonce.to_string(),
                    "--result-out".into(),
                    path.join(format!("{name}.result")).display().to_string(),
                    "--submission-out".into(),
                    path.join(format!("{name}.signed")).display().to_string(),
                ]
            };

        let mut create_args: Vec<String> =
            common_args("create-asset", 0, &creation_request_id_bytes, initial_fee);
        create_args.extend([
            "--instance-seed".into(),
            hex_32(&second_asset_seed),
            "--instance-ref-out".into(),
            path.join("second_asset.instance").display().to_string(),
        ]);
        sunrise_edge_cli::run(create_args.into_iter().map(OsString::from)).unwrap();
        let result: PaidExecutionResult = decode_result(&path.join("0-create-asset.result"));
        assert_eq!(result.status, PaidExecutionStatus::Success);

        // 2. Decode canonical instance ref and independently identify Definition and zero-supply TreasuryCap
        let instance_ref_bytes: Vec<u8> = fs::read(path.join("second_asset.instance")).unwrap();
        let second_instance_record: InstanceRecord =
            decode_instance_record(&instance_ref_bytes).unwrap();
        assert_eq!(
            second_instance_record.creator,
            *creation_owner.address().as_bytes()
        );
        assert_eq!(second_instance_record.seed, second_asset_seed);
        assert_eq!(second_instance_record.code, creation_fee_policy.code);
        assert_eq!(
            second_instance_record.initializer,
            public_standard_asset::INITIALIZER
        );
        assert_eq!(second_instance_record.revision, 1);
        assert_eq!(second_instance_record.context.chain_id().as_str(), CHAIN_ID);

        let charged = result.charged.as_ref().unwrap();
        let fee_id: ObjectId = charged.fee_output.id;
        let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|val| val.id);
        let created_objects: Vec<&Object> = result
            .effects
            .object_effects
            .iter()
            .filter_map(|effect: &ObjectEffect| match effect {
                ObjectEffect::Created(object)
                    if object.id != fee_id && Some(object.id) != refund_id =>
                {
                    Some(object)
                }
                _ => None,
            })
            .collect();
        assert_eq!(created_objects.len(), 2);

        let definition_tag: ScopedTypeTag =
            definition_type_tag(creation_fee_policy.code.origin()).unwrap();
        let definition: &Object = created_objects
            .iter()
            .copied()
            .find(|object: &&Object| {
                verify_scoped_type_id(
                    creation_protocol.resolver(),
                    &object.type_hash,
                    creation_config.epoch(),
                    &definition_tag,
                )
                .unwrap_or(false)
            })
            .expect("asset Definition present in created objects");
        let second_asset_id: ObjectId = definition.id;

        let cap_tag: ScopedTypeTag =
            treasury_cap_type_tag(creation_fee_policy.code.origin(), &second_asset_id).unwrap();
        let cap: &Object = created_objects
            .iter()
            .copied()
            .find(|object: &&Object| {
                verify_scoped_type_id(
                    creation_protocol.resolver(),
                    &object.type_hash,
                    creation_config.epoch(),
                    &cap_tag,
                )
                .unwrap_or(false)
            })
            .expect("TreasuryCap present in created objects");
        let second_cap_id: ObjectId = cap.id;

        assert_ne!(definition.id, cap.id);
        assert_eq!(definition.version, 1);
        assert_eq!(cap.version, 1);
        assert_eq!(definition.owner, Owner::Address(creation_owner.address()));
        assert_eq!(cap.owner, Owner::Address(creation_owner.address()));
        assert_eq!(definition.schema_version, SCHEMA_VERSION);
        assert_eq!(cap.schema_version, SCHEMA_VERSION);
        assert_eq!(definition.data, definition_body().unwrap());
        assert_eq!(treasury_supply(&cap.data).unwrap(), 0);

        (result, second_asset_id, second_cap_id)
    })
    .await
    .unwrap();

    // 3. Prove instance differs from the fee instance while code is identical
    let second_instance_record: InstanceRecord =
        decode_instance_record(&fs::read(&instance_ref_path).unwrap()).unwrap();
    assert_eq!(second_instance_record.code, fee_policy.code);
    let second_instance_target: InstanceTarget =
        instance_target(protocol.resolver(), &second_instance_record).unwrap();
    assert_ne!(second_instance_target, fee_policy.instance);

    let genesis_instance_seed: [u8; 32] = protocol
        .resolver()
        .hash_for_purpose(
            config.epoch(),
            HashPurpose::ProtocolConfig,
            b"sunrise.devnet.public-standard-asset.instance.v1",
        )
        .unwrap()
        .bytes();
    assert_ne!(second_instance_record.seed, genesis_instance_seed);
    assert_ne!(second_instance_record.creator, paid_genesis_authority());

    // 4. Prove same-boot exact creation replay does not reapply state/fees/nonce
    let signed_creation: SignedPaidIntent =
        decode_signed_paid_intent(&fs::read(directory.0.join("0-create-asset.signed")).unwrap())
            .unwrap();

    let creation_charge = creation_result.charged.as_ref().unwrap();
    let mut tracked_same_boot: Vec<ObjectId> = vec![
        genesis_spend,
        initial_fee,
        second_asset_id,
        second_cap_id,
        creation_charge.fee_output.id,
    ];
    if let Some(refund) = &creation_charge.refund_output {
        tracked_same_boot.push(refund.id);
    }
    let objects_before_same_boot: Vec<HttpObjectQueryResult> = tracked_same_boot
        .iter()
        .map(|id: &ObjectId| initial_client.query_object(*id).unwrap())
        .collect();
    let nonce_before_same_boot: u64 = initial_client
        .query_next_nonce(owner.address())
        .unwrap()
        .next_nonce();
    assert_eq!(nonce_before_same_boot, 1);
    let receipt_before_same_boot: HttpReceiptQueryResult =
        initial_client.query_receipt(creation_request_id).unwrap();

    let same_boot_replay_result: PaidExecutionResult = initial_client
        .submit_paid_execution(&signed_creation, protocol.resolver())
        .unwrap();
    assert_eq!(same_boot_replay_result, creation_result);

    let objects_after_same_boot: Vec<HttpObjectQueryResult> = tracked_same_boot
        .iter()
        .map(|id: &ObjectId| initial_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(objects_after_same_boot, objects_before_same_boot);
    assert_eq!(
        initial_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        nonce_before_same_boot
    );
    assert_eq!(
        initial_client.query_receipt(creation_request_id).unwrap(),
        receipt_before_same_boot
    );

    // 5. Reject substituting genesis TreasuryCap under new asset selection before nonce use,
    //    and 6. Mint and transfer the new asset via explicit --asset/--instance-ref
    let path_clone: PathBuf = directory.0.clone();
    let seed_path_clone2: PathBuf = seed_path.clone();
    let owner_address_clone: String = owner.address().to_string();
    let recipient_address_clone: String = recipient.address().to_string();

    let (mint_result, minted_coin, transfer_result): (
        PaidExecutionResult,
        ObjectId,
        PaidExecutionResult,
    ) = tokio::task::spawn_blocking(move || {
        let common_args =
            |action: &str, nonce: u64, req_id: &[u8; 32], fee: ObjectId| -> Vec<String> {
                let name: String = format!("{nonce}-{action}");
                vec![
                    action.to_owned(),
                    "--endpoint".into(),
                    first_address.to_string(),
                    "--expected-chain-id".into(),
                    CHAIN_ID.into(),
                    "--expected-protocol-version".into(),
                    "7".into(),
                    "--expected-epoch".into(),
                    EPOCH.to_string(),
                    "--expected-hash-suite-id".into(),
                    "1".into(),
                    "--expected-domain".into(),
                    domain.to_string(),
                    "--seed-file".into(),
                    seed_path_clone2.display().to_string(),
                    "--fee-source".into(),
                    fee.to_string(),
                    "--max-fee".into(),
                    MAX_FEE.to_string(),
                    "--gas-limit".into(),
                    GAS_LIMIT.to_string(),
                    "--request-id".into(),
                    hex_32(req_id),
                    "--nonce".into(),
                    nonce.to_string(),
                    "--result-out".into(),
                    path_clone
                        .join(format!("{name}.result"))
                        .display()
                        .to_string(),
                    "--submission-out".into(),
                    path_clone
                        .join(format!("{name}.signed"))
                        .display()
                        .to_string(),
                ]
            };

        // Reject substituting the genesis TreasuryCap under the new asset selection
        let mut invalid_cap_args: Vec<String> = common_args("mint", 1, &[0x50; 32], initial_fee);
        invalid_cap_args.extend([
            "--asset".into(),
            second_asset_id.to_string(),
            "--instance-ref".into(),
            path_clone
                .join("second_asset.instance")
                .display()
                .to_string(),
            "--treasury-cap".into(),
            genesis_cap.to_string(),
            "--amount".into(),
            "10".into(),
            "--recipient".into(),
            owner_address_clone.clone(),
        ]);
        let invalid_cap_error =
            sunrise_edge_cli::run(invalid_cap_args.into_iter().map(OsString::from)).unwrap_err();
        assert!(
            invalid_cap_error
                .to_string()
                .contains("--treasury-cap owner, schema, or nominal type mismatch")
        );
        assert!(!path_clone.join("1-mint.signed").exists());

        // Reject substituting a genesis Coin under the same new-asset selection.
        let mut invalid_coin_args: Vec<String> =
            common_args("transfer", 1, &[0x51; 32], initial_fee);
        invalid_coin_args.extend([
            "--asset".into(),
            second_asset_id.to_string(),
            "--instance-ref".into(),
            path_clone
                .join("second_asset.instance")
                .display()
                .to_string(),
            "--coin".into(),
            genesis_spend.to_string(),
            "--recipient".into(),
            recipient_address_clone.clone(),
        ]);
        let invalid_coin_error =
            sunrise_edge_cli::run(invalid_coin_args.into_iter().map(OsString::from)).unwrap_err();
        assert!(
            invalid_coin_error
                .to_string()
                .contains("--coin owner, schema, or nominal type mismatch")
        );
        assert!(!path_clone.join("1-transfer.signed").exists());

        // Mint new asset via explicit --asset / --instance-ref
        let mut mint_args: Vec<String> = common_args("mint", 1, &[0x33; 32], initial_fee);
        mint_args.extend([
            "--asset".into(),
            second_asset_id.to_string(),
            "--instance-ref".into(),
            path_clone
                .join("second_asset.instance")
                .display()
                .to_string(),
            "--treasury-cap".into(),
            second_cap_id.to_string(),
            "--amount".into(),
            "50".into(),
            "--recipient".into(),
            owner_address_clone,
        ]);
        sunrise_edge_cli::run(mint_args.into_iter().map(OsString::from)).unwrap();
        let mint_res: PaidExecutionResult = decode_result(&path_clone.join("1-mint.result"));
        assert_eq!(mint_res.status, PaidExecutionStatus::Success);
        let minted: ObjectId = application_created_object(&mint_res);

        // Transfer new asset via explicit --asset / --instance-ref
        let mut transfer_args: Vec<String> = common_args("transfer", 2, &[0x34; 32], initial_fee);
        transfer_args.extend([
            "--asset".into(),
            second_asset_id.to_string(),
            "--instance-ref".into(),
            path_clone
                .join("second_asset.instance")
                .display()
                .to_string(),
            "--coin".into(),
            minted.to_string(),
            "--recipient".into(),
            recipient_address_clone,
        ]);
        sunrise_edge_cli::run(transfer_args.into_iter().map(OsString::from)).unwrap();
        let transfer_res: PaidExecutionResult =
            decode_result(&path_clone.join("2-transfer.result"));
        assert_eq!(transfer_res.status, PaidExecutionStatus::Success);

        (mint_res, minted, transfer_res)
    })
    .await
    .unwrap();

    // Verify minted and transferred coin state
    assert!(transfer_result.effects.object_effects.iter().any(
        |effect: &ObjectEffect| {
            matches!(effect, ObjectEffect::Mutated { new_object, .. } if new_object.id == minted_coin)
        }
    ));
    let coin_query: HttpObjectQueryResult = initial_client.query_object(minted_coin).unwrap();
    let HttpObjectQueryResult::CurrentInline {
        canonical_object_bytes: coin_bytes,
        ..
    } = coin_query
    else {
        panic!("expected current inline coin");
    };
    let coin_obj: Object = decode_object(&coin_bytes).unwrap();
    assert_eq!(coin_obj.owner, Owner::Address(recipient.address()));
    assert_eq!(coin_amount(&coin_obj.data).unwrap(), 50);

    let cap_query: HttpObjectQueryResult = initial_client.query_object(second_cap_id).unwrap();
    let HttpObjectQueryResult::CurrentInline {
        canonical_object_bytes: cap_bytes,
        ..
    } = cap_query
    else {
        panic!("expected current inline cap");
    };
    let cap_obj: Object = decode_object(&cap_bytes).unwrap();
    assert_eq!(treasury_supply(&cap_obj.data).unwrap(), 50);

    assert_eq!(
        initial_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        3
    );

    let mut settlement_coin_ids: Vec<ObjectId> = Vec::new();
    for res in [&creation_result, &mint_result, &transfer_result] {
        if let Some(charged) = &res.charged {
            settlement_coin_ids.push(charged.fee_output.id);
            if let Some(refund) = &charged.refund_output {
                settlement_coin_ids.push(refund.id);
            }
        }
    }
    let mut tracked_ids: Vec<ObjectId> = vec![
        genesis_spend,
        initial_fee,
        second_asset_id,
        second_cap_id,
        minted_coin,
    ];
    tracked_ids.extend(&settlement_coin_ids);
    tracked_ids.sort_unstable();
    tracked_ids.dedup();

    let objects_before_restart: Vec<HttpObjectQueryResult> = tracked_ids
        .iter()
        .map(|id: &ObjectId| initial_client.query_object(*id).unwrap())
        .collect();

    let _ignored: Result<(), ()> = first_stop.send(());
    first_server.await.unwrap().unwrap();

    // 7. Prove exact stale writer-generation fencing after restart
    let reopened: DevnetBoot = boot_local_store(&config).unwrap();
    let second_generation: WriterFenceGeneration = reopened.boot_generation();
    assert!(second_generation.get() > first_generation.get());
    let second_protocol: DevnetProtocolContext =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    verify_or_seed_protocol_context(
        reopened.store(),
        second_protocol.resolver(),
        config.epoch(),
        second_generation,
        &operation(second_generation, 1),
        false,
    )
    .unwrap();

    let stale_marker_verification: Result<(), DevnetSeedError> = verify_or_seed_protocol_context(
        reopened.store(),
        second_protocol.resolver(),
        config.epoch(),
        first_generation,
        &operation(first_generation, 3),
        false,
    );
    assert!(matches!(
        stale_marker_verification,
        Err(DevnetSeedError::Read(DurableReadError::WriterFenced {
            active_generation,
        })) if active_generation == second_generation
    ));

    let second_publication: PublicationContext = PublicationContext::new(
        config.chain_id().clone(),
        second_protocol.resolver().protocol_version(),
        config.epoch(),
    )
    .unwrap();
    let second_activation: PaidContractActivation = install_paid_contracts(
        reopened.store(),
        &operation(second_generation, 2),
        domain,
        second_protocol.resolver(),
        &second_publication,
        config.dev_owners(),
        config.fee_recipient(),
    )
    .unwrap();
    assert!(matches!(
        second_activation.outcome,
        node_core::genesis::GenesisInstallOutcome::VerifiedExisting { .. }
    ));
    assert_eq!(
        second_activation.metadata.owner_coins[0].fee_coin,
        initial_fee
    );
    assert_eq!(
        second_activation.metadata.owner_coins[0].spend_coin,
        genesis_spend
    );
    assert_eq!(second_activation.metadata.treasury_cap_id, genesis_cap);

    let second_paid = native_http::PaidExecutionComposition::new(
        second_activation.base_policy,
        second_activation.fee_policy,
    );
    let (second_store, second_blobs) = reopened.into_parts();
    let second_router = compose_devnet_router(
        Arc::new(second_store),
        Arc::new(second_blobs),
        second_protocol.clone(),
        second_generation,
        4,
        2,
        second_paid,
    )
    .unwrap();
    let second_listener: tokio::net::TcpListener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_address: SocketAddr = second_listener.local_addr().unwrap();
    let (second_stop, second_shutdown): (
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) = tokio::sync::oneshot::channel::<()>();
    let second_server = tokio::spawn(native_http::serve_with_policy(
        second_listener,
        second_router,
        native_http::NativeHttpServePolicy::default(),
        async {
            let _ignored: Result<(), tokio::sync::oneshot::error::RecvError> =
                second_shutdown.await;
        },
    ));
    let second_client: Client<LoopbackHttpTransport> = Client::new(transport(second_address));

    let objects_after_restart: Vec<HttpObjectQueryResult> = tracked_ids
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(objects_after_restart, objects_before_restart);
    assert_eq!(
        second_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        3
    );

    // 8. Prove post-close/reopen exact creation replay does not reapply state/fees/nonce
    let creation_receipt_before: HttpReceiptQueryResult =
        second_client.query_receipt(creation_request_id).unwrap();
    let reopen_replay_result: PaidExecutionResult = second_client
        .submit_paid_execution(&signed_creation, second_protocol.resolver())
        .unwrap();
    assert_eq!(reopen_replay_result, creation_result);

    let objects_after_reopen_replay: Vec<HttpObjectQueryResult> = tracked_ids
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(objects_after_reopen_replay, objects_before_restart);
    assert_eq!(
        second_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        3
    );
    assert_eq!(
        second_client.query_receipt(creation_request_id).unwrap(),
        creation_receipt_before
    );

    // 9. Prove a different create-asset signed under the same request ID leaves both
    //    instance records, tracked object query bytes, creation/mint/transfer receipts,
    //    and nonce unchanged
    let mint_request_id: RequestId = RequestId::new([0x33; 32]).unwrap();
    let transfer_request_id: RequestId = RequestId::new([0x34; 32]).unwrap();
    let mint_receipt_before: HttpReceiptQueryResult =
        second_client.query_receipt(mint_request_id).unwrap();
    let transfer_receipt_before: HttpReceiptQueryResult =
        second_client.query_receipt(transfer_request_id).unwrap();

    let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
        config.chain_id().clone(),
        second_protocol.resolver().protocol_version(),
        config.epoch(),
        HashSuiteId::new(1),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        domain,
    )
    .unwrap();

    let genesis_instance_record_before: Option<InstanceRecord> = second_client
        .query_instance(
            paid_genesis_authority(),
            genesis_instance_seed,
            second_protocol.resolver(),
            &expected,
        )
        .unwrap();
    assert!(genesis_instance_record_before.is_some());

    let second_instance_record_before: Option<InstanceRecord> = second_client
        .query_instance(
            *owner.address().as_bytes(),
            second_asset_seed,
            second_protocol.resolver(),
            &expected,
        )
        .unwrap();
    assert_eq!(
        second_instance_record_before,
        Some(second_instance_record.clone())
    );

    let conflicting_seed: [u8; 32] = [0x99; 32];
    let conflicting_instance_before: Option<InstanceRecord> = second_client
        .query_instance(
            *owner.address().as_bytes(),
            conflicting_seed,
            second_protocol.resolver(),
            &expected,
        )
        .unwrap();
    assert_eq!(conflicting_instance_before, None);

    let conflict_path: PathBuf = directory.0.clone();
    let conflict_endpoint: String = second_address.to_string();
    let conflict: Result<(), String> = tokio::task::spawn_blocking(move || {
        sunrise_edge_cli::run(
            vec![
                "create-asset".to_owned(),
                "--endpoint".into(),
                conflict_endpoint,
                "--expected-chain-id".into(),
                CHAIN_ID.into(),
                "--expected-protocol-version".into(),
                "7".into(),
                "--expected-epoch".into(),
                EPOCH.to_string(),
                "--expected-hash-suite-id".into(),
                "1".into(),
                "--expected-domain".into(),
                domain.to_string(),
                "--seed-file".into(),
                conflict_path.join("owner.seed").display().to_string(),
                "--fee-source".into(),
                initial_fee.to_string(),
                "--max-fee".into(),
                MAX_FEE.to_string(),
                "--gas-limit".into(),
                GAS_LIMIT.to_string(),
                "--request-id".into(),
                hex_32(&creation_request_id_bytes),
                "--nonce".into(),
                "3".into(),
                "--instance-seed".into(),
                hex_32(&conflicting_seed),
                "--instance-ref-out".into(),
                conflict_path
                    .join("conflict.instance")
                    .display()
                    .to_string(),
                "--result-out".into(),
                conflict_path.join("conflict.result").display().to_string(),
                "--submission-out".into(),
                conflict_path.join("conflict.signed").display().to_string(),
            ]
            .into_iter()
            .map(OsString::from),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .unwrap();
    let conflict_error: String = conflict.unwrap_err();
    assert!(conflict_error.contains("state-or-context-conflict"));

    let genesis_instance_record_after: Option<InstanceRecord> = second_client
        .query_instance(
            paid_genesis_authority(),
            genesis_instance_seed,
            second_protocol.resolver(),
            &expected,
        )
        .unwrap();
    assert_eq!(
        genesis_instance_record_after,
        genesis_instance_record_before
    );

    let second_instance_record_after: Option<InstanceRecord> = second_client
        .query_instance(
            *owner.address().as_bytes(),
            second_asset_seed,
            second_protocol.resolver(),
            &expected,
        )
        .unwrap();
    assert_eq!(second_instance_record_after, second_instance_record_before);

    let conflicting_instance_after: Option<InstanceRecord> = second_client
        .query_instance(
            *owner.address().as_bytes(),
            conflicting_seed,
            second_protocol.resolver(),
            &expected,
        )
        .unwrap();
    assert_eq!(conflicting_instance_after, None);

    let objects_after_conflict: Vec<HttpObjectQueryResult> = tracked_ids
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(objects_after_conflict, objects_before_restart);

    assert_eq!(
        second_client.query_receipt(creation_request_id).unwrap(),
        creation_receipt_before
    );
    assert_eq!(
        second_client.query_receipt(mint_request_id).unwrap(),
        mint_receipt_before
    );
    assert_eq!(
        second_client.query_receipt(transfer_request_id).unwrap(),
        transfer_receipt_before
    );

    assert_eq!(
        second_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        3
    );

    let _ignored: Result<(), ()> = second_stop.send(());
    second_server.await.unwrap().unwrap();
}
