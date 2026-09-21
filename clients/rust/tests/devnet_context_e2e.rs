//! Real TCP E2E from `sunrise-edge-client` through the native HTTP adapter
//! into the composed local devnet query surface.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use execution::publication::PublicationContext;
use protocol_types::AtomicityDomainId;
use runtime::{DurableOperationContext, StorageCorrelationId, StorageDeadline};
use sunrise_edge_client::{
    Address, Client, HttpObjectQueryResult, HttpReceiptQueryResult, LocalSigner,
    LoopbackHttpTransport, ObjectId, RequestId,
};
use sunrise_edge_devnet::{
    DevnetConfig, boot_local_store, build_devnet_protocol_context, compose_devnet_router,
    genesis::DEVNET_DOMAIN_BYTES, install_paid_contracts, verify_or_seed_protocol_context,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence: u64 = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "sunrise-edge-client-e2e-{}-{sequence}",
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
async fn client_queries_all_four_routes_from_the_real_devnet_router_over_tcp() {
    let dev_owner = LocalSigner::from_seed([0x22; 32]).address();
    let fee_recipient = LocalSigner::from_seed([0x33; 32]).address();
    let directory = TestDirectory::new();
    let config = DevnetConfig::parse_from(vec![
        OsString::from("--data-dir"),
        directory.0.as_os_str().to_owned(),
        OsString::from("--listen"),
        OsString::from("127.0.0.1:7400"),
        OsString::from("--chain-id"),
        OsString::from("client-e2e-devnet"),
        OsString::from("--epoch"),
        OsString::from("7"),
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
    // Matches production boot equivalence (`main.rs`): the fail-closed
    // protocol-context marker is verified or seeded before paid genesis.
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

    let result = tokio::task::spawn_blocking(move || {
        let transport = LoopbackHttpTransport::new(
            address,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(1024 * 1024).unwrap(),
        )
        .unwrap();
        let client = Client::new(transport);
        let context = client.query_context().unwrap();

        let object_id = ObjectId::new([0x41; 32]);
        assert_eq!(
            client.query_object(object_id).unwrap(),
            HttpObjectQueryResult::Absent { object_id }
        );

        let request_id = RequestId::new([0x42; 32]).unwrap();
        assert_eq!(
            client.query_receipt(request_id).unwrap(),
            HttpReceiptQueryResult::Absent { request_id }
        );

        let sender = Address::new([0x43; 32]);
        let nonce = client.query_next_nonce(sender).unwrap();
        assert_eq!(nonce.sender(), sender);
        assert_eq!(nonce.epoch().get(), 7);
        assert_eq!(nonce.next_nonce(), 0);
        context
    })
    .await
    .unwrap();

    server.abort();
    let _ignored = server.await;

    assert_eq!(result.chain_id().as_str(), "client-e2e-devnet");
    assert_eq!(result.epoch().get(), 7);
    assert!(!result.protocol_config_bytes().is_empty());
}
