//! Genuine encrypted IO through the one Native connection owner. Private
//! counters describe transport/router entry, not protocol signing authority.
use crate::{
    NativeBlockingExecutor, NativeBlockingPolicy, NativeHttpServePolicy, publication,
    serve_with_stream_upgrade,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    routing::get,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig,
    client::Resumption,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
    server::NoServerSessionStorage,
};
use std::{
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};

const BOUND: Duration = Duration::from_secs(5);

struct ObservedFlush<S> {
    io: S,
    wrote: bool,
    empty_flushes: Arc<AtomicUsize>,
}
impl<S: AsyncRead + Unpin> AsyncRead for ObservedFlush<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedFlush<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result: Poll<io::Result<usize>> = Pin::new(&mut this.io).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            this.wrote = true;
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result: Poll<io::Result<()>> = Pin::new(&mut this.io).poll_flush(cx);
        if !this.wrote && matches!(result, Poll::Ready(Ok(()))) {
            this.empty_flushes.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

struct Server {
    address: SocketAddr,
    connector: TlsConnector,
    attempts: Arc<AtomicUsize>,
    empty_flushes: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Server {
    async fn start(app: Router, policy: NativeHttpServePolicy, handshake: Duration) -> Self {
        let leaf: rcgen::CertifiedKey<rcgen::KeyPair> =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let mut config: ServerConfig =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(leaf.signing_key.serialize_der()).into(),
                )
                .unwrap();
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        let acceptor: TlsAcceptor = TlsAcceptor::from(Arc::new(config));
        let mut roots: RootCertStore = RootCertStore::empty();
        roots.add(leaf.cert.der().clone()).unwrap();
        let mut client: ClientConfig =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        client.resumption = Resumption::disabled();
        let connector: TlsConnector = TlsConnector::from(Arc::new(client));
        let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let attempts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let empty_flushes: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let upgrade_attempts: Arc<AtomicUsize> = Arc::clone(&attempts);
        let upgrade_flushes: Arc<AtomicUsize> = Arc::clone(&empty_flushes);
        let (sender, receiver): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();
        let task: JoinHandle<io::Result<()>> = tokio::spawn(serve_with_stream_upgrade(
            listener,
            app,
            policy,
            move |stream: TcpStream| {
                upgrade_attempts.fetch_add(1, Ordering::SeqCst);
                let acceptor: TlsAcceptor = acceptor.clone();
                let empty_flushes: Arc<AtomicUsize> = Arc::clone(&upgrade_flushes);
                async move {
                    let io: tokio_rustls::server::TlsStream<TcpStream> =
                        timeout(handshake, acceptor.accept(stream))
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "test handshake deadline")
                            })??;
                    Ok::<ObservedFlush<_>, io::Error>(ObservedFlush {
                        io,
                        wrote: false,
                        empty_flushes,
                    })
                }
            },
            async move {
                let _received = receiver.await;
            },
        ));
        Self {
            address,
            connector,
            attempts,
            empty_flushes,
            shutdown: Some(sender),
            task: Some(task),
        }
    }
    async fn connect(&self) -> io::Result<TlsStream<TcpStream>> {
        let stream: TcpStream = TcpStream::connect(self.address).await?;
        self.connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
    }
    async fn request(&self, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
        timeout(BOUND, async {
            let mut tls: TlsStream<TcpStream> = self.connect().await.unwrap();
            let mut bytes: Vec<u8> = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
            bytes.extend_from_slice(body);
            tls.write_all(&bytes).await.unwrap();
            tls.flush().await.unwrap();
            let mut received: Vec<u8> = Vec::new();
            tls.read_to_end(&mut received).await.unwrap();
            received
        }).await.unwrap()
    }
    async fn stop(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        let result: io::Result<()> = timeout(BOUND, self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        result.unwrap();
        drop(self.task.take());
    }
}
async fn wait_count(counter: &AtomicUsize, expected: usize) {
    timeout(BOUND, async {
        while counter.load(Ordering::SeqCst) < expected {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
fn policy() -> NativeHttpServePolicy {
    NativeHttpServePolicy::new(1, 2_000, 100, 2_000, 300).unwrap()
}

#[derive(Clone)]
struct Application {
    entered: Arc<AtomicUsize>,
    started: Arc<Notify>,
}
async fn delayed(State(probe): State<Application>, body: Bytes) -> Body {
    probe.entered.fetch_add(1, Ordering::SeqCst);
    probe.started.notify_one();
    sleep(Duration::from_millis(750)).await;
    let mut response: Vec<u8> = b"complete delayed:".to_vec();
    response.extend_from_slice(&body);
    Body::from(response)
}
#[tokio::test]
async fn real_tls_get_and_post_empty_flushes_do_not_time_admitted_application() {
    for (method, body) in [
        ("GET", b"".as_slice()),
        ("POST", b"complete POST".as_slice()),
    ] {
        let probe: Application = Application {
            entered: Arc::new(AtomicUsize::new(0)),
            started: Arc::new(Notify::new()),
        };
        let app: Router = Router::new()
            .route("/delayed", get(delayed).post(delayed))
            .with_state(probe.clone());
        let server: Server = Server::start(app, policy(), Duration::from_secs(1)).await;
        let received: Vec<u8> = {
            let request = server.request(method, "/delayed", body);
            tokio::pin!(request);
            tokio::select! {
            result = &mut request => panic!("request completed before admitted work: {result:?}"),
            () = probe.started.notified() => {
                wait_count(&server.empty_flushes, 1).await;
                request.await
            },
            }
        };
        assert!(received.starts_with(b"HTTP/1.1 200"));
        let mut expected: Vec<u8> = b"complete delayed:".to_vec();
        expected.extend_from_slice(body);
        assert!(received.ends_with(&expected));
        assert_eq!(probe.entered.load(Ordering::SeqCst), 1);
        server.stop().await;
    }
}
#[tokio::test]
async fn real_tls_handshake_capacity_close_recovery_and_shutdown() {
    let routes: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let counter: Arc<AtomicUsize> = Arc::clone(&routes);
    let app: Router = Router::new().route(
        "/ok",
        get(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { "actual route" }
        }),
    );
    let server: Server = Server::start(app.clone(), policy(), Duration::from_millis(600)).await;
    let mut pending: TcpStream = TcpStream::connect(server.address).await.unwrap();
    wait_count(&server.attempts, 1).await;
    assert!(timeout(BOUND, server.connect()).await.unwrap().is_err());
    assert_eq!(
        server.attempts.load(Ordering::SeqCst),
        1,
        "excess socket never upgrades"
    );
    assert_eq!(routes.load(Ordering::SeqCst), 0);
    let mut refused: Vec<u8> = Vec::new();
    timeout(BOUND, pending.read_to_end(&mut refused))
        .await
        .unwrap()
        .unwrap();
    drop(pending);
    let first: Vec<u8> = server.request("GET", "/ok", b"").await;
    assert!(first.ends_with(b"actual route"));
    assert_eq!(routes.load(Ordering::SeqCst), 1);

    let malformed_attempt: usize = server.attempts.load(Ordering::SeqCst) + 1;
    let mut malformed: TcpStream = TcpStream::connect(server.address).await.unwrap();
    wait_count(&server.attempts, malformed_attempt).await;
    assert_eq!(server.attempts.load(Ordering::SeqCst), malformed_attempt);
    malformed
        .write_all(b"GET /ok HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut alert: Vec<u8> = Vec::new();
    let _closed = timeout(BOUND, malformed.read_to_end(&mut alert))
        .await
        .unwrap();
    drop(malformed);
    let close_attempt: usize = server.attempts.load(Ordering::SeqCst) + 1;
    let mut close: TcpStream = TcpStream::connect(server.address).await.unwrap();
    wait_count(&server.attempts, close_attempt).await;
    assert_eq!(server.attempts.load(Ordering::SeqCst), close_attempt);
    let mut client: ClientConnection = ClientConnection::new(
        Arc::clone(server.connector.config()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello: Vec<u8> = Vec::new();
    client.write_tls(&mut hello).unwrap();
    assert!(!hello.is_empty());
    close.write_all(&hello).await.unwrap();
    close.shutdown().await.unwrap();
    let mut flight: Vec<u8> = Vec::new();
    let _closed = timeout(BOUND, close.read_to_end(&mut flight))
        .await
        .unwrap();
    drop(close);
    assert_eq!(
        routes.load(Ordering::SeqCst),
        1,
        "no HTTP follows malformed or ClientHello-close"
    );
    assert!(
        server
            .request("GET", "/ok", b"")
            .await
            .ends_with(b"actual route")
    );
    assert_eq!(routes.load(Ordering::SeqCst), 2);
    server.stop().await;
    // This handshake deadline outlasts stop's five-second bound, so a pass
    // requires shutdown cancellation, not merely natural handshake expiry.
    let shutting: Server = Server::start(app, policy(), Duration::from_secs(10)).await;
    let stalled: TcpStream = TcpStream::connect(shutting.address).await.unwrap();
    wait_count(&shutting.attempts, 1).await;
    shutting.stop().await;
    drop(stalled);
    assert_eq!(routes.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn slow_drip_handshake_cannot_extend_absolute_deadline() {
    let routes: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let counter: Arc<AtomicUsize> = Arc::clone(&routes);
    let app: Router = Router::new().route(
        "/ok",
        get(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { "ok" }
        }),
    );
    let server: Server = Server::start(app, policy(), Duration::from_millis(200)).await;
    let mut raw: TcpStream = TcpStream::connect(server.address).await.unwrap();
    wait_count(&server.attempts, 1).await;
    let mut client: ClientConnection = ClientConnection::new(
        Arc::clone(server.connector.config()),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello: Vec<u8> = Vec::new();
    client.write_tls(&mut hello).unwrap();
    assert!(hello.len() > 100);
    raw.write_all(&hello[..10]).await.unwrap();
    // An authentic, still incomplete ClientHello; progress cannot finish the
    // record, nor manufacture an early malformed-message failure oracle.
    for byte in &hello[10..16] {
        sleep(Duration::from_millis(50)).await;
        if raw.write_all(&[*byte]).await.is_err() {
            break;
        }
    }
    let mut closed: Vec<u8> = Vec::new();
    let _closed: io::Result<usize> = timeout(BOUND, raw.read_to_end(&mut closed)).await.unwrap();
    drop(raw);
    assert_eq!(routes.load(Ordering::SeqCst), 0);
    assert!(server.request("GET", "/ok", b"").await.ends_with(b"ok"));
    assert_eq!(routes.load(Ordering::SeqCst), 1);
    server.stop().await;
}
#[tokio::test]
async fn encrypted_output_backpressure_releases_the_connection_permit() {
    let routes: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let large: Arc<AtomicUsize> = Arc::clone(&routes);
    let small: Arc<AtomicUsize> = Arc::clone(&routes);
    let app: Router = Router::new()
        .route(
            "/large",
            get(move || {
                large.fetch_add(1, Ordering::SeqCst);
                async { Body::from(vec![0x67; 8 * 1024 * 1024]) }
            }),
        )
        .route(
            "/ok",
            get(move || {
                small.fetch_add(1, Ordering::SeqCst);
                async { "ok" }
            }),
        );
    let server: Server = Server::start(app, policy(), Duration::from_secs(1)).await;
    let mut blocked: TlsStream<TcpStream> =
        timeout(BOUND, server.connect()).await.unwrap().unwrap();
    blocked
        .write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    blocked.flush().await.unwrap();
    wait_count(&routes, 1).await;
    // Keep the actual TLS peer alive but do not consume encrypted response.
    sleep(Duration::from_millis(750)).await;
    assert!(server.request("GET", "/ok", b"").await.ends_with(b"ok"));
    assert_eq!(routes.load(Ordering::SeqCst), 2);
    drop(blocked);
    server.stop().await;
}

/// Failure cleanup releases the private test worker; it does not cancel a
/// production store operation or assert a commit/rollback result.
struct WorkerRelease(Arc<(Mutex<bool>, Condvar)>);
impl WorkerRelease {
    fn release(&self) {
        let (released, wake): &(Mutex<bool>, Condvar) = &self.0;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
}
impl Drop for WorkerRelease {
    fn drop(&mut self) {
        self.release();
    }
}

#[tokio::test]
async fn disconnected_tls_peer_does_not_release_started_blocking_work_capacity() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let released: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
    let release: WorkerRelease = WorkerRelease(Arc::clone(&released));
    let started: Arc<Notify> = Arc::new(Notify::new());
    let completed: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let probes: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let work_executor: NativeBlockingExecutor = executor.clone();
    let work_started: Arc<Notify> = Arc::clone(&started);
    let work_completed: Arc<AtomicUsize> = Arc::clone(&completed);
    let probe_executor: NativeBlockingExecutor = executor.clone();
    let probe_count: Arc<AtomicUsize> = Arc::clone(&probes);
    let app: Router = Router::new()
        .route(
            "/work",
            get(move || {
                let executor: NativeBlockingExecutor = work_executor.clone();
                let released: Arc<(Mutex<bool>, Condvar)> = Arc::clone(&released);
                let started: Arc<Notify> = Arc::clone(&work_started);
                let completed: Arc<AtomicUsize> = Arc::clone(&work_completed);
                async move {
                    publication::admitted(false, executor, move || {
                        started.notify_one();
                        let (released, wake): &(Mutex<bool>, Condvar) = &released;
                        let mut ready: std::sync::MutexGuard<'_, bool> = released.lock().unwrap();
                        while !*ready {
                            ready = wake.wait(ready).unwrap();
                        }
                        completed.fetch_add(1, Ordering::SeqCst);
                        axum::response::IntoResponse::into_response("completed worker")
                    })
                    .await
                }
            }),
        )
        .route(
            "/probe",
            get(move || {
                let executor: NativeBlockingExecutor = probe_executor.clone();
                let probes: Arc<AtomicUsize> = Arc::clone(&probe_count);
                async move {
                    publication::admitted(false, executor, move || {
                        probes.fetch_add(1, Ordering::SeqCst);
                        axum::response::IntoResponse::into_response("capacity recovered")
                    })
                    .await
                }
            }),
        );
    let policy: NativeHttpServePolicy =
        NativeHttpServePolicy::new(2, 2_000, 100, 2_000, 300).unwrap();
    let server: Server = Server::start(app, policy, Duration::from_secs(1)).await;
    let mut peer: TlsStream<TcpStream> = timeout(BOUND, server.connect()).await.unwrap().unwrap();
    peer.write_all(b"GET /work HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    peer.flush().await.unwrap();
    timeout(BOUND, started.notified()).await.unwrap();
    assert_eq!(
        executor.permits.available_permits(),
        0,
        "worker actually started before disconnect"
    );
    drop(peer);
    let overloaded: Vec<u8> = server.request("GET", "/probe", b"").await;
    assert!(overloaded.starts_with(b"HTTP/1.1 429"));
    assert!(overloaded.ends_with(b"blocking-capacity-exhausted"));
    assert_eq!(probes.load(Ordering::SeqCst), 0);
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    assert_eq!(executor.permits.available_permits(), 0);
    release.release();
    timeout(BOUND, async {
        while executor.permits.available_permits() != 1 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    let recovered: Vec<u8> = server.request("GET", "/probe", b"").await;
    assert!(recovered.starts_with(b"HTTP/1.1 200"));
    assert!(recovered.ends_with(b"capacity recovered"));
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    server.stop().await;
}
