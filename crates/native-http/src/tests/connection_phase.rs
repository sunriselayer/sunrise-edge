//! Actual one-request TCP phase checks: completed input does not become slow
//! request input merely because application work has not produced a response.
use crate::{NativeHttpServePolicy, serve_with_policy};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{Method, Response, StatusCode, header},
    routing::get,
};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::{JoinError, JoinHandle},
    time::{error::Elapsed, sleep, timeout},
};

const REQUEST_IDLE_MILLIS: u64 = 100;
const APPLICATION_DELAY: Duration = Duration::from_millis(750);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_BODY: &[u8] = b"complete delayed application response";
const PATH: &str = "/completed-request-delayed-application";

#[derive(Clone)]
struct ApplicationProbe {
    started: Arc<Notify>,
    observed_body: Arc<Mutex<Option<Vec<u8>>>>,
}

async fn delayed_application(State(probe): State<ApplicationProbe>, body: Bytes) -> Response<Body> {
    *probe.observed_body.lock().unwrap() = Some(body.to_vec());
    probe.started.notify_one();
    // No network input is needed after this point. The dispatch owner already
    // collected the complete bounded request before invoking this real router.
    sleep(APPLICATION_DELAY).await;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, RESPONSE_BODY.len())
        .body(Body::from(RESPONSE_BODY))
        .unwrap()
}

async fn require_complete_delayed_response(method: Method, request_body: &[u8]) {
    let policy: NativeHttpServePolicy =
        NativeHttpServePolicy::new(1, 2_000, REQUEST_IDLE_MILLIS, 2_000, 2_000).unwrap();
    assert!(APPLICATION_DELAY > Duration::from_millis(REQUEST_IDLE_MILLIS * 5));
    assert!(APPLICATION_DELAY < Duration::from_millis(2_000));
    let probe: ApplicationProbe = ApplicationProbe {
        started: Arc::new(Notify::new()),
        observed_body: Arc::new(Mutex::new(None)),
    };
    let app: Router = Router::new()
        .route(PATH, get(delayed_application).post(delayed_application))
        .with_state(probe.clone());
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let (shutdown_sender, shutdown_receiver): (oneshot::Sender<()>, oneshot::Receiver<()>) =
        oneshot::channel();
    let mut server: JoinHandle<io::Result<()>> =
        tokio::spawn(serve_with_policy(listener, app, policy, async move {
            let _received: Result<(), oneshot::error::RecvError> = shutdown_receiver.await;
        }));

    // Capture failures as a result so the owned server is shut down before any
    // assertion. Do not half-close, drip input, retry or extend policy timers.
    let exchange: Result<Vec<u8>, String> = async {
        let mut stream: TcpStream = timeout(EXCHANGE_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|error: Elapsed| format!("connect deadline: {error}"))?
            .map_err(|error: io::Error| format!("connect: {error}"))?;
        let mut request: Vec<u8> = format!(
            "{method} {PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            request_body.len()
        )
        .into_bytes();
        request.extend_from_slice(request_body);
        timeout(EXCHANGE_TIMEOUT, stream.write_all(&request))
            .await
            .map_err(|error: Elapsed| format!("complete request write deadline: {error}"))?
            .map_err(|error: io::Error| format!("complete request write: {error}"))?;
        timeout(EXCHANGE_TIMEOUT, probe.started.notified())
            .await
            .map_err(|error: Elapsed| format!("completed request never reached handler: {error}"))?;
        let mut response: Vec<u8> = Vec::new();
        timeout(EXCHANGE_TIMEOUT, stream.read_to_end(&mut response))
            .await
            .map_err(|error: Elapsed| format!("response completion deadline: {error}"))?
            .map_err(|error: io::Error| format!("response read: {error}"))?;
        Ok(response)
    }
    .await;

    let shutdown_sent: Result<(), ()> = shutdown_sender.send(());
    let completion: Result<Result<io::Result<()>, JoinError>, Elapsed> =
        timeout(EXCHANGE_TIMEOUT, &mut server).await;
    if completion.is_err() {
        server.abort();
        let _aborted: Result<io::Result<()>, JoinError> = server.await;
    }
    shutdown_sent.expect("owned phase-test server must accept shutdown");
    completion
        .expect("owned phase-test server must stop within the cleanup deadline")
        .expect("owned phase-test server must not panic")
        .expect("owned phase-test server must return cleanly");
    assert_eq!(
        probe.observed_body.lock().unwrap().as_deref(),
        Some(request_body),
        "the real handler must receive the complete {method} body before waiting"
    );

    let response: Vec<u8> = exchange.unwrap_or_else(|error: String| {
        panic!("complete {method} request lost its delayed response: {error}")
    });
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "complete {method} request must retain its delayed 200 response, got {:?}",
        String::from_utf8_lossy(&response)
    );
    let headers_end: usize = response
        .windows(4)
        .position(|window: &[u8]| window == b"\r\n\r\n")
        .expect("delayed 200 response must have complete headers");
    let headers: &str = std::str::from_utf8(&response[..headers_end]).unwrap();
    let content_length: usize = headers
        .split("\r\n")
        .filter_map(|line: &str| line.split_once(':'))
        .find(|(name, _): &(&str, &str)| name.eq_ignore_ascii_case("content-length"))
        .expect("delayed response must declare its exact body length")
        .1
        .trim()
        .parse::<usize>()
        .unwrap();
    assert_eq!(content_length, RESPONSE_BODY.len());
    assert_eq!(&response[headers_end + 4..], RESPONSE_BODY);
}

#[tokio::test]
async fn complete_get_survives_application_wait_longer_than_request_read_idle() {
    require_complete_delayed_response(Method::GET, b"").await;
}

#[tokio::test]
async fn complete_post_survives_application_wait_longer_than_request_read_idle() {
    require_complete_delayed_response(Method::POST, b"the entire POST request body").await;
}
