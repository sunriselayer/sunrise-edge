//! Real local TLS interoperability with the actual certified Vercel constructor.
//! The HTTP/Fetch bridge is test-owned, not a deployed Vercel runtime or quorum.

#[path = "support/certified_relay_process.rs"]
mod certified_relay_process;
#[path = "support/disposable_tls.rs"]
mod disposable_tls;

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sunrise_edge_client::{
    Method, RemoteTlsHttpTransport, Transport, TransportError, WireRequest, WireResponse,
};

fn start(
    identity: &disposable_tls::DisposableTlsIdentity,
) -> (certified_relay_process::OwnedServer, SocketAddr) {
    let fixture: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/certified-relay-server.mjs");
    certified_relay_process::start(
        &fixture,
        &identity.leaf.pem(),
        &identity.key.serialize_pem(),
        None,
    )
}

fn request(method: Method, path: &str) -> WireRequest {
    WireRequest {
        method,
        path: path.to_owned(),
        content_type: (method == Method::Post).then_some("application/vnd.sunrise-edge.node-event"),
        body: if method == Method::Post {
            vec![1, 2]
        } else {
            Vec::new()
        },
        deadline: Some(Instant::now() + Duration::from_secs(5)),
    }
}

#[test]
fn pinned_node_certified_https_get_post_empty_and_late_failure() {
    let identity: disposable_tls::DisposableTlsIdentity =
        disposable_tls::issue_identity("relay.test");
    let (mut server, addr): (certified_relay_process::OwnedServer, SocketAddr) = start(&identity);
    let transport: RemoteTlsHttpTransport = RemoteTlsHttpTransport::new(
        addr,
        "relay.test",
        &identity.ca_der,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(1),
        NonZeroUsize::new(8192).unwrap(),
        NonZeroUsize::new(8192).unwrap(),
    )
    .unwrap();
    let query: WireResponse = transport
        .send(&request(Method::Get, "/v1/context"))
        .unwrap();
    assert_eq!(query.status, 200);
    assert_eq!(
        query.content_type.as_deref(),
        Some("application/vnd.sunrise-edge.query-result")
    );
    assert_eq!(query.body, b"query-bytes");
    let submitted: WireResponse = transport
        .send(&request(Method::Post, "/v1/fastvote/prepare"))
        .unwrap();
    assert_eq!(submitted.status, 200);
    assert_eq!(
        submitted.content_type.as_deref(),
        Some("application/vnd.sunrise-edge.node-result")
    );
    assert_eq!(submitted.body, b"submission-bytes");
    let empty: WireResponse = transport
        .send(&request(Method::Post, "/v1/fastvote/drain/signer-page"))
        .unwrap();
    assert_eq!(empty.status, 204);
    assert!(empty.content_type.is_none());
    assert!(empty.body.is_empty());
    let late: Result<WireResponse, TransportError> = transport.send(&request(
        Method::Get,
        &format!("/v1/objects/{}", "ee".repeat(32)),
    ));
    assert!(
        matches!(
            &late,
            Err(TransportError::TruncatedChunkedResponse | TransportError::TrailingResponseBytes)
        ) || matches!(&late, Err(TransportError::Read(error)) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "a late stream failure must never become Ok: {late:?}"
    );
    server.stop(&[
        "CHUNKED GET /v1/context",
        "CHUNKED POST /v1/fastvote/prepare",
        "EMPTY POST /v1/fastvote/drain/signer-page",
        &format!("RESET GET /v1/objects/{}", "ee".repeat(32)),
    ]);
}
