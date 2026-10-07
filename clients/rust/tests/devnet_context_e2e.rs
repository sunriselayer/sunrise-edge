//! Real TCP E2E from `sunrise-edge-client` through the native HTTP adapter
//! into the composed local devnet query surface.

#[path = "support/certified_relay_process.rs"]
mod certified_relay_process;
#[path = "support/disposable_tls.rs"]
mod disposable_tls;

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
    Address, Client, HttpContextQueryResult, HttpNextNonceQueryResult, HttpObjectQueryResult,
    HttpReceiptQueryResult, LocalSigner, LoopbackHttpTransport, ObjectId, RemoteTlsHttpTransport,
    RequestId,
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

        // Second leg: the same real native listener, reached through the
        // actual certified Vercel constructor and a test-owned TLS relay,
        // rather than the loopback transport above. Both Node spawn/stdio
        // and this blocking TLS exchange stay on this blocking thread; a
        // panic here drops `relay`, which kills and waits for its child.
        let identity: disposable_tls::DisposableTlsIdentity =
            disposable_tls::issue_identity("relay.test");
        let relay_script: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/support/native-certified-relay-server.mjs");
        let (mut relay, relay_addr): (certified_relay_process::OwnedServer, SocketAddr) =
            certified_relay_process::start(
                &relay_script,
                &identity.leaf.pem(),
                &identity.key.serialize_pem(),
                Some(address.port()),
            );
        let relay_transport: RemoteTlsHttpTransport = RemoteTlsHttpTransport::new(
            relay_addr,
            "relay.test",
            &identity.ca_der,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(1024 * 1024).unwrap(),
        )
        .unwrap();
        let relay_client: Client<RemoteTlsHttpTransport> = Client::new(relay_transport);

        let relayed_context: HttpContextQueryResult = relay_client.query_context().unwrap();
        assert_eq!(relayed_context.chain_id().as_str(), "client-e2e-devnet");
        assert_eq!(relayed_context.epoch().get(), 7);
        assert!(!relayed_context.protocol_config_bytes().is_empty());

        let relayed_object_id: ObjectId = ObjectId::new([0x41; 32]);
        assert_eq!(
            relay_client.query_object(relayed_object_id).unwrap(),
            HttpObjectQueryResult::Absent {
                object_id: relayed_object_id
            }
        );

        let relayed_request_id: RequestId = RequestId::new([0x42; 32]).unwrap();
        assert_eq!(
            relay_client.query_receipt(relayed_request_id).unwrap(),
            HttpReceiptQueryResult::Absent {
                request_id: relayed_request_id
            }
        );

        let relayed_sender: Address = Address::new([0x43; 32]);
        let relayed_nonce: HttpNextNonceQueryResult =
            relay_client.query_next_nonce(relayed_sender).unwrap();
        assert_eq!(relayed_nonce.sender(), relayed_sender);
        assert_eq!(relayed_nonce.epoch().get(), 7);
        assert_eq!(relayed_nonce.next_nonce(), 0);

        let relayed_object_line: String = format!("CHUNKED GET /v1/objects/{}", "41".repeat(32));
        let relayed_receipt_line: String = format!("CHUNKED GET /v1/receipts/{}", "42".repeat(32));
        let relayed_nonce_line: String =
            format!("CHUNKED GET /v1/senders/{}/next-nonce", "43".repeat(32));
        relay.stop(&[
            "CHUNKED GET /v1/context",
            &relayed_object_line,
            &relayed_receipt_line,
            &relayed_nonce_line,
        ]);

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
