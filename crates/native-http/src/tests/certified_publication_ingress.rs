//! Collector admission only: a probe is not a valid publication or import.
use crate::{
    FASTVOTE_PUBLICATION_RETAIN_PATH, MAX_HTTP_EVENT_BODY_BYTES, NativeHttpObservations,
    NativeHttpServePolicy, NativeHttpSnapshot, request_body_limit, serve_with_stream_upgrade_observed,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{Method, Response, StatusCode, Uri, header},
    routing::any,
};
use consensus::bundle::MAX_ENCODED_BUNDLE_BYTES;
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::oneshot,
    task::{JoinError, JoinHandle},
    time::{error::Elapsed, timeout},
};

const VALIDATOR_SELECTOR: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CHUNK_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 4 * 1024;
const MAX_PROBE_RESPONSE_BYTES: usize = 1_024;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_RESPONSE_BODY: &[u8] = b"collected";

fn drain_import_path(selector: &str) -> String {
    node_wire::FASTVOTE_DRAIN_IMPORT_PATH.replace("{validator_id}", selector)
}

#[test]
fn certified_publication_is_default_off_and_independent_of_local_flags() {
    let drain_path: String = drain_import_path(VALIDATOR_SELECTOR);
    let policies: [NativeHttpServePolicy; 3] = [
        NativeHttpServePolicy::default(),
        NativeHttpServePolicy::new(3, 700, 500, 1_500, 1_800).unwrap(),
        NativeHttpServePolicy::default()
            .with_certified_publication(true)
            .with_certified_publication(false),
    ];
    assert_eq!(
        MAX_HTTP_EVENT_BODY_BYTES,
        node_core::MAX_NODE_PAYLOAD_BYTES + 512,
    );
    for policy in policies {
        for path in [FASTVOTE_PUBLICATION_RETAIN_PATH, drain_path.as_str()] {
            assert_eq!(
                request_body_limit(policy, &Method::POST, path),
                MAX_HTTP_EVENT_BODY_BYTES,
            );
        }
        let local_flags: [(bool, bool); 4] =
            [(false, false), (true, false), (false, true), (true, true)];
        for (publication, execution) in local_flags {
            let base: NativeHttpServePolicy = policy
                .with_local_publication(publication)
                .with_local_execution(execution);
            let enabled: NativeHttpServePolicy = base.with_certified_publication(true);
            assert_eq!(enabled.with_certified_publication(false), base);
            assert_eq!(enabled.max_connections(), base.max_connections());
            let publication_limit: usize = if publication {
                execution::publication::MAX_PUBLICATION_SUBMISSION_BYTES
            } else {
                MAX_HTTP_EVENT_BODY_BYTES
            };
            let execution_limit: usize = if execution {
                execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES
            } else {
                MAX_HTTP_EVENT_BODY_BYTES
            };
            for selected in [base, enabled] {
                assert_eq!(
                    request_body_limit(
                        selected,
                        &Method::POST,
                        crate::publication::PUBLICATION_PATH,
                    ),
                    publication_limit,
                );
                assert_eq!(
                    request_body_limit(
                        selected,
                        &Method::POST,
                        crate::local_execution::EXECUTION_PATH,
                    ),
                    execution_limit,
                );
                for path in [
                    crate::publication::PUBLICATION_PATH,
                    crate::local_execution::EXECUTION_PATH,
                ] {
                    assert_eq!(
                        request_body_limit(selected, &Method::GET, path),
                        MAX_HTTP_EVENT_BODY_BYTES,
                    );
                }
            }
        }
    }
}

#[test]
fn certified_publication_selects_only_exact_post_raw_paths() {
    let policy: NativeHttpServePolicy =
        NativeHttpServePolicy::default().with_certified_publication(true);
    let drain_path: String = drain_import_path(VALIDATOR_SELECTOR);
    for path in [FASTVOTE_PUBLICATION_RETAIN_PATH, drain_path.as_str()] {
        assert_eq!(
            request_body_limit(policy, &Method::POST, path),
            MAX_ENCODED_BUNDLE_BYTES,
        );
        let uri: Uri = format!("{path}?fixture=present").parse::<Uri>().unwrap();
        assert_eq!(
            request_body_limit(policy, &Method::POST, uri.path()),
            MAX_ENCODED_BUNDLE_BYTES,
        );
        let methods: [Method; 8] = [
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::CONNECT,
            Method::TRACE,
        ];
        for method in methods {
            assert_eq!(
                request_body_limit(policy, &method, path),
                MAX_HTTP_EVENT_BODY_BYTES,
            );
        }
    }
    let malformed_paths: Vec<String> = vec![
        format!("{FASTVOTE_PUBLICATION_RETAIN_PATH}/"),
        format!("{FASTVOTE_PUBLICATION_RETAIN_PATH}/extra"),
        format!("{FASTVOTE_PUBLICATION_RETAIN_PATH}-extra"),
        "/v1/fastvote/publications/%72etain".to_owned(),
        "/v1/Fastvote/publications/retain".to_owned(),
        format!(" {FASTVOTE_PUBLICATION_RETAIN_PATH}"),
        format!("{drain_path}/"),
        format!("{drain_path}/extra"),
        format!("/extra{drain_path}"),
        drain_import_path(&"a".repeat(63)),
        drain_import_path(&"a".repeat(65)),
        drain_import_path(&"A".repeat(64)),
        drain_import_path(&"g".repeat(64)),
        drain_import_path(&"á".repeat(32)),
        drain_import_path(&format!("%61{}", "a".repeat(63))),
        drain_import_path(&format!("{}/{}", "a".repeat(32), "a".repeat(32))),
        drain_import_path(&format!(" {VALIDATOR_SELECTOR}")),
        drain_import_path(&format!("{VALIDATOR_SELECTOR} ")),
        "/v1/fastvote/drain/import/".to_owned(),
        node_wire::FASTVOTE_DRAIN_IMPORT_PATH.to_owned(),
    ];
    for path in malformed_paths {
        assert_eq!(
            request_body_limit(policy, &Method::POST, &path),
            MAX_HTTP_EVENT_BODY_BYTES,
            "raw path must not acquire the bundle bound: {path:?}",
        );
    }
    let sibling_paths: Vec<&str> = vec![
        crate::NODE_EVENT_PATH,
        crate::LIVENESS_PATH,
        crate::QUERY_CONTEXT_PATH,
        crate::QUERY_OBJECT_PATH,
        crate::QUERY_RECEIPT_PATH,
        crate::QUERY_NEXT_NONCE_PATH,
        crate::FASTVOTE_PREPARE_PATH,
        crate::FASTVOTE_CERTIFICATES_PATH,
        crate::FASTVOTE_PUBLICATION_SOURCE_PATH,
        crate::FASTVOTE_PUBLISHED_APPLY_PATH,
        crate::FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
        crate::FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
        node_wire::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
        node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
        node_wire::FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
        node_wire::FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
        node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
        node_wire::FASTVOTE_DRAIN_APPLY_PATH,
        node_wire::ORDERED_HISTORY_SUMMARY_PATH,
        node_wire::ORDERED_HISTORY_HEIGHT_PATH,
        node_wire::ORDERED_HISTORY_COMPONENT_PATH,
        node_wire::FEE_CLAIM_PREPARE_PATH,
        node_wire::ordered_economics::ORDERED_ECONOMICS_PROPOSE_PATH,
        node_wire::ordered_economics::ORDERED_ECONOMICS_PROPOSAL_PATH,
        node_wire::ordered_economics::ORDERED_ECONOMICS_CERTIFICATE_PATH,
        node_wire::ordered_economics::ORDERED_ECONOMICS_OBSERVE_PATH,
        node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH,
        node_wire::ordered_economics::ORDERED_ECONOMICS_TICK_PATH,
        crate::publication::PUBLICATION_PATH,
        crate::local_execution::EXECUTION_PATH,
        "/unrelated",
    ];
    for path in sibling_paths {
        assert_eq!(
            request_body_limit(policy, &Method::POST, path),
            MAX_HTTP_EVENT_BODY_BYTES,
        );
    }
}

#[derive(Clone, Default)]
struct CollectorProbe {
    calls: Arc<AtomicUsize>,
    received_bytes: Arc<AtomicUsize>,
}

async fn receive_probe(State(probe): State<CollectorProbe>, body: Bytes) -> Response<Body> {
    probe.received_bytes.store(body.len(), Ordering::SeqCst);
    probe.calls.fetch_add(1, Ordering::SeqCst);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_LENGTH, PROBE_RESPONSE_BODY.len())
        .body(Body::from(PROBE_RESPONSE_BODY))
        .unwrap()
}

async fn write_chunked_body(writer: &mut OwnedWriteHalf, body_bytes: usize) -> io::Result<()> {
    let chunk: [u8; CHUNK_BYTES] = [0x5a; CHUNK_BYTES];
    let mut remaining: usize = body_bytes;
    while remaining > 0 {
        let count: usize = remaining.min(CHUNK_BYTES);
        let chunk_header: String = format!("{count:x}\r\n");
        writer.write_all(chunk_header.as_bytes()).await?;
        writer.write_all(&chunk[..count]).await?;
        writer.write_all(b"\r\n").await?;
        remaining -= count;
    }
    writer.write_all(b"0\r\n\r\n").await
}

async fn read_bounded_response(reader: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    let mut response: Vec<u8> = Vec::with_capacity(256);
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() == MAX_RESPONSE_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probe response headers exceeded bound",
            ));
        }
        let byte: u8 = reader.read_u8().await?;
        response.push(byte);
    }
    let headers: &str = std::str::from_utf8(&response)
        .map_err(|error: std::str::Utf8Error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let length_text: &str = headers
        .split("\r\n")
        .filter_map(|line: &str| line.split_once(':'))
        .find(|(name, _): &(&str, &str)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value): (&str, &str)| value.trim())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "probe response omitted content length")
        })?;
    let length: usize = length_text
        .parse::<usize>()
        .map_err(|error: std::num::ParseIntError| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if length > MAX_PROBE_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe response body exceeded bound",
        ));
    }
    let mut body: Vec<u8> = vec![0; length];
    reader.read_exact(&mut body).await?;
    response.extend_from_slice(&body);
    Ok(response)
}

struct ChunkedExchange {
    response: Vec<u8>,
    write: io::Result<()>,
}

async fn chunked_exchange(
    address: SocketAddr,
    method: &Method,
    path: &str,
    body_bytes: usize,
) -> io::Result<ChunkedExchange> {
    let mut stream: TcpStream = TcpStream::connect(address).await?;
    let headers: String = format!(
        concat!(
            "{method} {path} HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Connection: close\r\n\r\n",
        ),
        method = method,
        path = path,
    );
    stream.write_all(headers.as_bytes()).await?;
    let (mut reader, mut writer): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
    // Read concurrently with fixed-size writes: an early refusal must not wait
    // for an unbounded write or require a half-close. The whole exchange shares
    // one outer deadline; a chunk never refreshes it.
    let (write, response): (io::Result<()>, io::Result<Vec<u8>>) = tokio::join!(
        write_chunked_body(&mut writer, body_bytes),
        read_bounded_response(&mut reader),
    );
    Ok(ChunkedExchange {
        response: response?,
        write,
    })
}

async fn require_collector_exchange(
    policy: NativeHttpServePolicy,
    method: Method,
    path: &str,
    body_bytes: usize,
    dispatched: bool,
) {
    let probe: CollectorProbe = CollectorProbe::default();
    let app: Router = Router::new()
        .route(FASTVOTE_PUBLICATION_RETAIN_PATH, any(receive_probe))
        .route(node_wire::FASTVOTE_DRAIN_IMPORT_PATH, any(receive_probe))
        .fallback(receive_probe)
        // A plain Bytes extractor otherwise defaults to 2 MiB. This explicit
        // test-only ceiling makes the outer collector the measured owner.
        .layer(DefaultBodyLimit::max(MAX_ENCODED_BUNDLE_BYTES))
        .with_state(probe.clone());
    let observations: NativeHttpObservations = NativeHttpObservations::default();
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let (stop_send, stop_receive): (oneshot::Sender<()>, oneshot::Receiver<()>) =
        oneshot::channel();
    let mut server: JoinHandle<io::Result<()>> = tokio::spawn(serve_with_stream_upgrade_observed(
        listener,
        app,
        policy,
        |stream: TcpStream| async move { Ok::<TcpStream, io::Error>(stream) },
        async move {
            let _stopped: Result<(), oneshot::error::RecvError> = stop_receive.await;
        },
        observations.clone(),
    ));
    let exchange: Result<io::Result<ChunkedExchange>, Elapsed> =
        timeout(
            EXCHANGE_TIMEOUT,
            chunked_exchange(address, &method, path, body_bytes),
        )
        .await;
    // Always stop/join the owned listener before checking a failed exchange.
    let shutdown_sent: Result<(), ()> = stop_send.send(());
    let completion: Result<Result<io::Result<()>, JoinError>, Elapsed> =
        timeout(CLEANUP_TIMEOUT, &mut server).await;
    if completion.is_err() {
        server.abort();
        let _aborted: Result<io::Result<()>, JoinError> = server.await;
    }
    shutdown_sent.expect("collector probe server must accept shutdown");
    completion
        .expect("collector probe server must stop within cleanup deadline")
        .expect("collector probe server must not panic")
        .expect("collector probe server must return cleanly");
    let result: ChunkedExchange = exchange
        .expect("one bounded chunked exchange must complete")
        .expect("chunked exchange must return a complete bounded response");
    let snapshot: NativeHttpSnapshot = observations.snapshot();
    assert_eq!(snapshot.connections_admitted, 1);
    assert_eq!(snapshot.connections_refused, 0);
    assert_eq!(snapshot.input_timeouts, 0);
    assert_eq!(snapshot.output_timeouts, 0);
    if dispatched {
        result
            .write
            .expect("an admitted request must send its complete chunked body");
        assert!(result.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(result.response.ends_with(PROBE_RESPONSE_BODY));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.received_bytes.load(Ordering::SeqCst), body_bytes);
        assert_eq!(snapshot.requests_dispatched, 1);
        assert_eq!(snapshot.requests_refused, 0);
    } else {
        // A size refusal may close before the writer sends its terminator.
        // Its write result is not the oracle: require actual 413 and zero work.
        assert!(result.response.starts_with(b"HTTP/1.1 413"));
        assert!(result.response.ends_with(b"body-rejected"));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.received_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot.requests_dispatched, 0);
        assert_eq!(snapshot.requests_refused, 1);
    }
}

#[tokio::test]
async fn native_tcp_collector_enforces_default_and_bundle_boundaries_for_both_routes() {
    let default: NativeHttpServePolicy = NativeHttpServePolicy::default();
    let enabled: NativeHttpServePolicy = default.with_certified_publication(true);
    let drain_path: String = drain_import_path(VALIDATOR_SELECTOR);
    for path in [FASTVOTE_PUBLICATION_RETAIN_PATH, drain_path.as_str()] {
        require_collector_exchange(
            default, Method::POST, path, MAX_HTTP_EVENT_BODY_BYTES, true,
        )
        .await;
        require_collector_exchange(
            default, Method::POST, path, MAX_HTTP_EVENT_BODY_BYTES + 1, false,
        )
        .await;
        require_collector_exchange(
            enabled, Method::POST, path, MAX_HTTP_EVENT_BODY_BYTES + 1, true,
        )
        .await;
        require_collector_exchange(
            enabled, Method::POST, path, MAX_ENCODED_BUNDLE_BYTES, true,
        )
        .await;
        require_collector_exchange(
            enabled, Method::POST, path, MAX_ENCODED_BUNDLE_BYTES + 1, false,
        )
        .await;
    }
}

#[tokio::test]
async fn native_tcp_collector_keeps_unrelated_methods_and_raw_paths_at_default_bound() {
    let policy: NativeHttpServePolicy =
        NativeHttpServePolicy::default().with_certified_publication(true);
    let trailing_slash: String = format!("{FASTVOTE_PUBLICATION_RETAIN_PATH}/");
    let percent_selector: String = drain_import_path(&format!("%61{}", "a".repeat(63)));
    for path in [
        crate::NODE_EVENT_PATH,
        trailing_slash.as_str(),
        percent_selector.as_str(),
    ] {
        require_collector_exchange(
            policy, Method::POST, path, MAX_HTTP_EVENT_BODY_BYTES + 1, false,
        )
        .await;
    }
    require_collector_exchange(
        policy,
        Method::GET,
        FASTVOTE_PUBLICATION_RETAIN_PATH,
        MAX_HTTP_EVENT_BODY_BYTES + 1,
        false,
    )
    .await;
}
