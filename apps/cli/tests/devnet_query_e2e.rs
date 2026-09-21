//! Real loopback TCP E2E: `sunrise_edge_cli::run` against the composed
//! local devnet router, exactly as a user would invoke the `sunrise-edge-cli`
//! binary.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use execution::publication::PublicationContext;
use protocol_types::AtomicityDomainId;
use runtime::{DurableOperationContext, StorageCorrelationId, StorageDeadline};
use sunrise_edge_devnet::{
    DevnetConfig, boot_local_store, build_devnet_protocol_context, compose_devnet_router,
    genesis::DEVNET_DOMAIN_BYTES, install_paid_contracts, verify_or_seed_protocol_context,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-cli-e2e-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_context_and_next_nonce_commands_reach_the_real_devnet_router_over_tcp() {
    let dev_owner = sunrise_edge_client::LocalSigner::from_seed([0x33; 32]).address();
    let fee_recipient = sunrise_edge_client::LocalSigner::from_seed([0x44; 32]).address();
    let directory = TestDirectory::new();
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("cli-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("9"),
        OsString::from("--dev-owner"),
        OsString::from(dev_owner.to_string()),
        OsString::from("--fee-recipient"),
        OsString::from(fee_recipient.to_string()),
        OsString::from("--max-concurrent"),
        OsString::from("4"),
    ])
    .unwrap();
    let boot = boot_local_store(&config).unwrap();
    let generation = boot.boot_generation();
    let object_store_was_empty = boot.store().object_store_is_empty().unwrap();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap();
    let operation = |sequence: u8| -> DurableOperationContext {
        let correlation_byte: u8 = sequence.checked_add(1).unwrap();
        DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([correlation_byte; 16]).unwrap(),
        )
    };
    verify_or_seed_protocol_context(
        boot.store(),
        protocol_context.resolver(),
        config.epoch(),
        generation,
        &operation(0),
        object_store_was_empty,
    )
    .unwrap();
    let publication_context = PublicationContext::new(
        config.chain_id().clone(),
        protocol_context.resolver().protocol_version(),
        config.epoch(),
    )
    .unwrap();
    let activation = install_paid_contracts(
        boot.store(),
        &operation(1),
        domain,
        protocol_context.resolver(),
        &publication_context,
        config.dev_owners(),
        config.fee_recipient(),
    )
    .unwrap();
    let paid_execution =
        native_http::PaidExecutionComposition::new(activation.base_policy, activation.fee_policy);
    let (structured_store, blob_store) = boot.into_parts();
    let router = compose_devnet_router(
        Arc::new(structured_store),
        Arc::new(blob_store),
        protocol_context,
        generation,
        config.max_concurrent(),
        2,
        paid_execution,
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
    tokio::task::spawn_blocking(move || {
        sunrise_edge_cli::run(vec![
            OsString::from("context"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
        ])
        .expect("context command should succeed against the real devnet router");

        sunrise_edge_cli::run(vec![
            OsString::from("next-nonce"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--sender"),
            OsString::from("44".repeat(32)),
        ])
        .expect("next-nonce command should succeed against the real devnet router");

        sunrise_edge_cli::run(vec![
            OsString::from("object"),
            OsString::from("--endpoint"),
            OsString::from(&endpoint),
            OsString::from("--object-id"),
            OsString::from("45".repeat(32)),
        ])
        .expect("object command should succeed against the real devnet router");
    })
    .await
    .unwrap();

    server.abort();
    let _ignored = server.await;
}
