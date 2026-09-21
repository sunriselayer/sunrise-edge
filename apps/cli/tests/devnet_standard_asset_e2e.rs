//! Real SQLite -> native HTTP -> CLI coverage for every public Standard Asset verb.

mod common;

use common::{
    TestDirectory, application_created_object, current_coin_amount, decode_result, devnet_config,
    operation, test_directory, transport, write_seed,
};

use execution::{
    ObjectEffect,
    paid_execution::{PaidExecutionResult, PaidExecutionStatus, decode_signed_paid_intent},
    publication::PublicationContext,
};
use fees::{Amount, reservation::ReservationPricer};
use protocol_types::AtomicityDomainId;
use runtime::DurableReadError;
use std::{ffi::OsString, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use sunrise_edge_client::{
    Client, HttpObjectQueryResult, LocalSigner, LoopbackHttpTransport, ObjectId, RequestId,
};
use sunrise_edge_devnet::{
    DevnetConfig, DevnetSeedError, boot_local_store, build_devnet_protocol_context,
    compose_devnet_router, genesis::DEVNET_DOMAIN_BYTES, install_paid_contracts,
    verify_or_seed_protocol_context,
};

const CHAIN_ID: &str = "cli-public-standard-asset";
const EPOCH: u64 = 9;
const GAS_LIMIT: u64 = 200_000;
const MAX_FEE: u64 = 1_000_000;

struct OperationOutcome {
    split_coin: ObjectId,
    minted_coin: ObjectId,
    fee_source: ObjectId,
    split_actual: u64,
    split_refund: (ObjectId, u64),
    separate_source_actual: u64,
    separate_refunds: Vec<(ObjectId, u64)>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_asset_cli_five_operations_and_state_survive_sqlite_restart() {
    let directory: TestDirectory = test_directory("public-asset");
    let seed_path: PathBuf = directory.0.join("owner.seed");
    write_seed(&seed_path, 7);
    let owner: LocalSigner = LocalSigner::from_seed([7; 32]);
    let recipient: LocalSigner = LocalSigner::from_seed([9; 32]);
    let config: DevnetConfig = devnet_config(&directory.0, &owner, &recipient, CHAIN_ID, EPOCH);
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap();

    let boot = boot_local_store(&config).unwrap();
    let first_generation = boot.boot_generation();
    let protocol =
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
    let publication = PublicationContext::new(
        config.chain_id().clone(),
        protocol.resolver().protocol_version(),
        config.epoch(),
    )
    .unwrap();
    let activation = install_paid_contracts(
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
    let spend: ObjectId = activation.metadata.owner_coins[0].spend_coin;
    let cap: ObjectId = activation.metadata.treasury_cap_id;
    let fee_policy = activation.fee_policy.clone();
    let paid =
        native_http::PaidExecutionComposition::new(activation.base_policy, activation.fee_policy);
    let (store, blobs) = boot.into_parts();
    let router = compose_devnet_router(
        Arc::new(store),
        Arc::new(blobs),
        protocol,
        first_generation,
        4,
        2,
        paid,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_address: SocketAddr = listener.local_addr().unwrap();
    let (first_stop, first_shutdown) = tokio::sync::oneshot::channel::<()>();
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
        current_coin_amount(&initial_client.query_object(spend).unwrap());
    let initial_fee_amount: u64 =
        current_coin_amount(&initial_client.query_object(initial_fee).unwrap());

    let path: PathBuf = directory.0.clone();
    let owner_address: String = owner.address().to_string();
    let recipient_address: String = recipient.address().to_string();
    let operation_outcome = tokio::task::spawn_blocking(move || {
        let pricer: ReservationPricer = ReservationPricer::new(
            fee_policy.gas_schedule.clone(),
            fee_policy.conversion_divisor,
            fee_policy.reserve_allowance,
            fee_policy.settle_allowance,
        )
        .unwrap();
        let fee_source: ObjectId = initial_fee;
        let common_values = |action: &str,
                             nonce: u64,
                             request_byte: u8,
                             fee: ObjectId|
         -> Vec<String> {
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
                path.join("owner.seed").display().to_string(),
                "--fee-source".into(),
                fee.to_string(),
                "--max-fee".into(),
                MAX_FEE.to_string(),
                "--gas-limit".into(),
                GAS_LIMIT.to_string(),
                "--request-id".into(),
                format!("{request_byte:02x}").repeat(32),
                "--nonce".into(),
                nonce.to_string(),
                "--result-out".into(),
                path.join(format!("{name}.result")).display().to_string(),
                "--submission-out".into(),
                path.join(format!("{name}.signed")).display().to_string(),
            ]
        };
        let invoke = |action: &str,
                      nonce: u64,
                      request_byte: u8,
                      fee: ObjectId,
                      operation_flags: Vec<String>|
         -> PaidExecutionResult {
            let mut values: Vec<String> = common_values(action, nonce, request_byte, fee);
            values.extend(operation_flags);
            sunrise_edge_cli::run(values.into_iter().map(OsString::from)).unwrap();
            let name: String = format!("{nonce}-{action}");
            let result_path: PathBuf = path.join(format!("{name}.result"));
            let result: PaidExecutionResult = decode_result(&result_path);
            assert_eq!(result.status, PaidExecutionStatus::Success);
            let charged = result.charged.as_ref().unwrap();
            let expected = pricer
                .admit(GAS_LIMIT, Amount::new(MAX_FEE))
                .unwrap()
                .settle(charged.application_gas_units)
                .unwrap();
            assert_eq!(charged.actual, expected.actual);
            assert_eq!(charged.refund, expected.refund);
            assert!(charged.actual.get() > 0);
            result
        };

        let mut invalid_cap_alias: Vec<String> = common_values("mint", 0, 0x40, fee_source);
        invalid_cap_alias.extend([
            "--treasury-cap".into(),
            fee_source.to_string(),
            "--amount".into(),
            "1".into(),
            "--recipient".into(),
            owner_address.clone(),
        ]);
        let invalid_cap_error =
            sunrise_edge_cli::run(invalid_cap_alias.into_iter().map(OsString::from)).unwrap_err();
        assert!(
            invalid_cap_error
                .to_string()
                .contains("owner, schema, or nominal type mismatch")
        );

        let split_result: PaidExecutionResult = invoke(
            "split",
            0,
            0x41,
            spend,
            vec![
                "--coin".into(),
                spend.to_string(),
                "--amount".into(),
                "100".into(),
                "--recipient".into(),
                owner_address.clone(),
            ],
        );
        assert_eq!(
            split_result
                .effects
                .object_effects
                .iter()
                .filter(|effect: &&ObjectEffect| {
                    matches!(effect, ObjectEffect::Mutated { new_object, .. } if new_object.id == spend)
                })
                .count(),
            1
        );
        let split_coin: ObjectId = application_created_object(&split_result);
        let merge_result: PaidExecutionResult = invoke(
            "merge",
            1,
            0x42,
            fee_source,
            vec![
                "--into".into(),
                spend.to_string(),
                "--from".into(),
                split_coin.to_string(),
            ],
        );
        assert!(merge_result.effects.object_effects.iter().any(
            |effect: &ObjectEffect| matches!(effect, ObjectEffect::Deleted { id, .. } if *id == split_coin)
        ));
        let mint_result: PaidExecutionResult = invoke(
            "mint",
            2,
            0x43,
            fee_source,
            vec![
                "--treasury-cap".into(),
                cap.to_string(),
                "--amount".into(),
                "25".into(),
                "--recipient".into(),
                owner_address,
            ],
        );
        let minted_coin: ObjectId = application_created_object(&mint_result);
        let burn_result: PaidExecutionResult = invoke(
            "burn",
            3,
            0x44,
            fee_source,
            vec![
                "--treasury-cap".into(),
                cap.to_string(),
                "--coin".into(),
                minted_coin.to_string(),
            ],
        );
        assert!(burn_result.effects.object_effects.iter().any(
            |effect: &ObjectEffect| matches!(effect, ObjectEffect::Deleted { id, .. } if *id == minted_coin)
        ));
        let transfer_result: PaidExecutionResult = invoke(
            "transfer",
            4,
            0x45,
            fee_source,
            vec![
                "--coin".into(),
                spend.to_string(),
                "--recipient".into(),
                recipient_address,
            ],
        );
        assert!(transfer_result.effects.object_effects.iter().any(
            |effect: &ObjectEffect| matches!(effect, ObjectEffect::Mutated { new_object, .. } if new_object.id == spend)
        ));
        let split_charge = split_result.charged.as_ref().unwrap();
        let split_actual: u64 = split_charge.actual.get();
        let split_refund: (ObjectId, u64) = (
            split_charge.refund_output.as_ref().unwrap().id,
            split_charge.refund.get(),
        );
        let separate_results: [&PaidExecutionResult; 4] = [
            &merge_result,
            &mint_result,
            &burn_result,
            &transfer_result,
        ];
        let separate_source_actual: u64 = separate_results
            .iter()
            .copied()
            .map(|result: &PaidExecutionResult| result.charged.as_ref().unwrap().actual.get())
            .sum();
        let separate_refunds: Vec<(ObjectId, u64)> = separate_results
            .iter()
            .copied()
            .map(|result: &PaidExecutionResult| {
                let charged = result.charged.as_ref().unwrap();
                (
                    charged.refund_output.as_ref().unwrap().id,
                    charged.refund.get(),
                )
            })
            .collect();
        OperationOutcome {
            split_coin,
            minted_coin,
            fee_source,
            split_actual,
            split_refund,
            separate_source_actual,
            separate_refunds,
        }
    })
    .await
    .unwrap();
    let split_coin: ObjectId = operation_outcome.split_coin;
    let minted_coin: ObjectId = operation_outcome.minted_coin;
    let final_fee: ObjectId = operation_outcome.fee_source;
    let split_actual: u64 = operation_outcome.split_actual;
    let split_refund: (ObjectId, u64) = operation_outcome.split_refund;
    let separate_source_actual: u64 = operation_outcome.separate_source_actual;
    let separate_refunds: Vec<(ObjectId, u64)> = operation_outcome.separate_refunds;

    let first_client: Client<LoopbackHttpTransport> = Client::new(transport(first_address));
    let tracked: [ObjectId; 5] = [spend, split_coin, minted_coin, cap, final_fee];
    let before_restart: Vec<HttpObjectQueryResult> = tracked
        .iter()
        .map(|id: &ObjectId| first_client.query_object(*id).unwrap())
        .collect();
    assert!(matches!(
        before_restart[0],
        HttpObjectQueryResult::CurrentInline { .. }
    ));
    assert!(matches!(
        before_restart[1],
        HttpObjectQueryResult::Tombstoned { .. }
    ));
    assert!(matches!(
        before_restart[2],
        HttpObjectQueryResult::Tombstoned { .. }
    ));
    let split_refund_amount: u64 = current_coin_amount(
        &first_client
            .query_object(split_refund.0)
            .expect("split refund Coin query"),
    );
    assert_eq!(split_refund_amount, split_refund.1);
    assert_eq!(
        current_coin_amount(&before_restart[0]) + split_refund_amount,
        initial_spend_amount - split_actual
    );
    let queried_separate_refunds: u64 = separate_refunds
        .iter()
        .map(|(id, expected_amount): &(ObjectId, u64)| {
            let actual: u64 = current_coin_amount(
                &first_client
                    .query_object(*id)
                    .expect("separate-source refund Coin query"),
            );
            assert_eq!(actual, *expected_amount);
            actual
        })
        .sum();
    assert_eq!(
        current_coin_amount(&before_restart[4]) + queried_separate_refunds,
        initial_fee_amount - separate_source_actual
    );
    assert_eq!(
        first_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        5
    );
    let _ignored: Result<(), ()> = first_stop.send(());
    first_server.await.unwrap().unwrap();

    let reopened = boot_local_store(&config).unwrap();
    let second_generation = reopened.boot_generation();
    assert!(second_generation.get() > first_generation.get());
    let second_protocol =
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
    let stale_marker_verification = verify_or_seed_protocol_context(
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
    let second_publication = PublicationContext::new(
        config.chain_id().clone(),
        second_protocol.resolver().protocol_version(),
        config.epoch(),
    )
    .unwrap();
    let second_activation = install_paid_contracts(
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
    assert_eq!(second_activation.metadata.owner_coins[0].spend_coin, spend);
    assert_eq!(second_activation.metadata.treasury_cap_id, cap);
    let second_resolver = second_protocol.resolver().clone();
    let second_paid = native_http::PaidExecutionComposition::new(
        second_activation.base_policy,
        second_activation.fee_policy,
    );
    let (second_store, second_blobs) = reopened.into_parts();
    let second_router = compose_devnet_router(
        Arc::new(second_store),
        Arc::new(second_blobs),
        second_protocol,
        second_generation,
        4,
        2,
        second_paid,
    )
    .unwrap();
    let second_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_address: SocketAddr = second_listener.local_addr().unwrap();
    let (second_stop, second_shutdown) = tokio::sync::oneshot::channel::<()>();
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
    let after_restart: Vec<HttpObjectQueryResult> = tracked
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(after_restart, before_restart);
    assert_eq!(
        second_client
            .query_next_nonce(owner.address())
            .unwrap()
            .next_nonce(),
        5
    );

    let transfer_result: PaidExecutionResult =
        decode_result(&directory.0.join("4-transfer.result"));
    let signed_transfer =
        decode_signed_paid_intent(&fs::read(directory.0.join("4-transfer.signed")).unwrap())
            .unwrap();
    let replay_before: Vec<HttpObjectQueryResult> = tracked
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    let replay_nonce_before = second_client.query_next_nonce(owner.address()).unwrap();
    let reused_request_id: RequestId = RequestId::new([0x45; 32]).unwrap();
    let replay_receipt_before = second_client.query_receipt(reused_request_id).unwrap();
    let replay_result = second_client
        .submit_paid_execution(&signed_transfer, &second_resolver)
        .unwrap();
    assert_eq!(replay_result, transfer_result);
    let replay_after: Vec<HttpObjectQueryResult> = tracked
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(replay_after, replay_before);
    assert_eq!(
        second_client.query_next_nonce(owner.address()).unwrap(),
        replay_nonce_before
    );
    assert_eq!(
        second_client.query_receipt(reused_request_id).unwrap(),
        replay_receipt_before
    );

    let conflict_path: PathBuf = directory.0.clone();
    let conflict_endpoint: String = second_address.to_string();
    let conflict_owner: String = owner.address().to_string();
    let conflict = tokio::task::spawn_blocking(move || {
        sunrise_edge_cli::run(
            vec![
                "transfer".to_owned(),
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
                "45".repeat(32),
                "--nonce".into(),
                "5".into(),
                "--coin".into(),
                initial_fee.to_string(),
                "--recipient".into(),
                conflict_owner,
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
    let conflict_after: Vec<HttpObjectQueryResult> = tracked
        .iter()
        .map(|id: &ObjectId| second_client.query_object(*id).unwrap())
        .collect();
    assert_eq!(conflict_after, replay_before);
    assert_eq!(
        second_client.query_next_nonce(owner.address()).unwrap(),
        replay_nonce_before
    );
    assert_eq!(
        second_client.query_receipt(reused_request_id).unwrap(),
        replay_receipt_before
    );
    let _ignored: Result<(), ()> = second_stop.send(());
    second_server.await.unwrap().unwrap();
}
