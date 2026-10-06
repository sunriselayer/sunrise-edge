//! Real local TLS interoperability with the actual certified Vercel constructor.
//! The HTTP/Fetch bridge is test-owned, not a deployed Vercel runtime or quorum.

#[path = "support/disposable_tls.rs"]
mod disposable_tls;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use sunrise_edge_client::{
    Method, RemoteTlsHttpTransport, Transport, TransportError, WireRequest, WireResponse,
};

struct OwnedServer {
    child: Child,
    output: Receiver<String>,
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl OwnedServer {
    fn line(&self) -> String {
        self.output
            .recv_timeout(Duration::from_secs(15))
            .expect("bounded local fixture output")
    }

    fn stop(&mut self) {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"STOP\n")
            .unwrap();
        assert_eq!(self.line(), "CHUNKED GET /v1/context");
        assert_eq!(self.line(), "CHUNKED POST /v1/fastvote/prepare");
        assert_eq!(self.line(), "EMPTY POST /v1/fastvote/drain/signer-page");
        assert_eq!(
            self.line(),
            format!("RESET GET /v1/objects/{}", "ee".repeat(32))
        );
        assert_eq!(self.line(), "DONE");
        let end: Instant = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "actual pinned Node fixture must succeed");
                break;
            }
            assert!(Instant::now() < end, "owned Node process must terminate");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn start(identity: &disposable_tls::DisposableTlsIdentity) -> (OwnedServer, SocketAddr) {
    let fixture: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/certified-relay-server.mjs");
    let child: Child = Command::new("node")
        .arg("--experimental-strip-types")
        .arg(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Node 22.20.0 is a mandatory owning-test prerequisite, never skipped");
    let (sender, output): (mpsc::SyncSender<String>, Receiver<String>) = mpsc::sync_channel(8);
    let mut server: OwnedServer = OwnedServer { child, output };
    let stdout: std::process::ChildStdout = server.child.stdout.take().unwrap();
    thread::spawn(move || {
        // A fixed total cap bounds even an accidentally noisy child; no log
        // output includes the disposable private key delivered through stdin.
        let mut reader: BufReader<std::io::Take<std::process::ChildStdout>> =
            BufReader::new(stdout.take(8192));
        loop {
            let mut line: String = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if sender.send(line.trim_end().to_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let pem_escape = |value: &str| -> String { value.replace('\\', "\\\\").replace('\n', "\\n") };
    let configuration: String = format!(
        "{{\"cert\":\"{}\",\"key\":\"{}\"}}\n",
        pem_escape(&identity.leaf_pem),
        pem_escape(&identity.key_pem)
    );
    server
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(configuration.as_bytes())
        .unwrap();
    let ready: String = server.line();
    let port: u16 = ready
        .strip_prefix("READY ")
        .expect("closed fixture startup record")
        .parse()
        .unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    (server, addr)
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
    let _rustls_inputs: (&[u8], &[u8]) = (&identity.leaf_der, &identity.key_der);
    let (mut server, addr): (OwnedServer, SocketAddr) = start(&identity);
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
    server.stop();
}
