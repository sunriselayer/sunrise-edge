use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::Notify};

#[tokio::test]
async fn already_ready_stop_precedes_accept_and_pending_upgrades_are_cancelled() {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: std::net::SocketAddr = listener.local_addr().unwrap();
    let connected: TcpStream = TcpStream::connect(address).await.unwrap();
    let observations: NativeHttpObservations = NativeHttpObservations::default();
    serve_with_stream_upgrade_observed(listener, Router::new(), NativeHttpServePolicy::default(),
        |stream: TcpStream| async move { Ok::<TcpStream, io::Error>(stream) },
        async {}, observations.clone()).await.unwrap();
    assert_eq!(observations.snapshot().connections_admitted, 0);
    drop(connected);
    let rebound: TcpListener = TcpListener::bind(address).await.unwrap();
    drop(rebound);

    struct UpgradeDrop(Arc<AtomicUsize>);
    impl Drop for UpgradeDrop {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: std::net::SocketAddr = listener.local_addr().unwrap();
    let entered: Arc<Notify> = Arc::new(Notify::new());
    let cancelled: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let upgrade_entered: Arc<Notify> = Arc::clone(&entered);
    let upgrade_cancelled: Arc<AtomicUsize> = Arc::clone(&cancelled);
    let (send, receive) = oneshot::channel::<()>();
    let observations: NativeHttpObservations = NativeHttpObservations::default();
    let server = tokio::spawn(serve_with_stream_upgrade_observed(listener, Router::new(),
        NativeHttpServePolicy::default(), move |stream: TcpStream| {
            let entered: Arc<Notify> = Arc::clone(&upgrade_entered);
            let cancelled: Arc<AtomicUsize> = Arc::clone(&upgrade_cancelled);
            async move {
                let _drop: UpgradeDrop = UpgradeDrop(cancelled);
                let _stream: TcpStream = stream;
                entered.notify_one();
                std::future::pending::<io::Result<TcpStream>>().await
            }
        }, async move { receive.await.unwrap(); }, observations.clone()));
    let connected: TcpStream = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(2), entered.notified()).await.unwrap();
    send.send(()).unwrap();
    timeout(Duration::from_secs(2), server).await.unwrap().unwrap().unwrap();
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(observations.snapshot().connections_admitted, 1);
    assert_eq!(observations.snapshot().upgrade_failures, 0);
    assert_eq!(observations.snapshot().upgrade_timeouts, 0);
    drop(connected);
    let _rebound: TcpListener = TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn observed_collector_refusal_and_dispatch_are_at_actual_branches() {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: std::net::SocketAddr = listener.local_addr().unwrap();
    let observations: NativeHttpObservations = NativeHttpObservations::default();
    let policy: NativeHttpServePolicy = NativeHttpServePolicy::new(2, 1_000, 80, 120, 1_000).unwrap();
    let (send, receive) = oneshot::channel::<()>();
    let server = tokio::spawn(serve_with_stream_upgrade_observed(listener,
        Router::new().route("/ok", get(|| async { "complete" })), policy,
        |stream: TcpStream| async move { Ok::<TcpStream, io::Error>(stream) },
        async move { receive.await.unwrap(); }, observations.clone()));
    let mut stream: TcpStream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"POST /private-id?secret=key HTTP/1.1\r\nHost: fixture\r\nContent-Length: 20\r\n\r\nx").await.unwrap();
    for _drip in 0..3 {
        sleep(Duration::from_millis(30)).await;
        if stream.write_all(b"x").await.is_err() { break; }
    }
    let mut refused: Vec<u8> = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut refused)).await.unwrap().unwrap();
    assert!(refused.starts_with(b"HTTP/1.1 408"));
    assert_eq!(observations.snapshot().requests_dispatched, 0);
    assert_eq!(observations.snapshot().requests_refused, 1);
    assert_eq!(observations.snapshot().input_timeouts, 1);
    let mut stream: TcpStream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"GET /ok HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut result: Vec<u8> = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut result)).await.unwrap().unwrap();
    assert!(result.ends_with(b"complete"));
    send.send(()).unwrap();
    timeout(Duration::from_secs(2), server).await.unwrap().unwrap().unwrap();
    assert_eq!(observations.snapshot().requests_dispatched, 1);
    let summary: String = observations.snapshot().termination_summary(NativeStopReason::Sigterm);
    for secret in ["private-id", "secret", "fixture", "key", "HTTP"] { assert!(!summary.contains(secret)); }
}

#[tokio::test]
async fn upgrade_task_failure_is_observed_at_owned_join() {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: std::net::SocketAddr = listener.local_addr().unwrap();
    let observations: NativeHttpObservations = NativeHttpObservations::default();
    let (send, receive) = oneshot::channel::<()>();
    let server = tokio::spawn(serve_with_stream_upgrade_observed(listener, Router::new(),
        NativeHttpServePolicy::default(), |_stream: TcpStream| async move {
            let _owned: TcpStream = _stream;
            std::future::poll_fn(|_context| -> Poll<io::Result<TcpStream>> {
                panic!("private connection task unwind control");
            }).await
        }, async move { receive.await.unwrap(); }, observations.clone()));
    let _connected: TcpStream = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while observations.snapshot().connection_task_failures == 0 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    send.send(()).unwrap();
    timeout(Duration::from_secs(2), server).await.unwrap().unwrap().unwrap();
    assert_eq!(observations.snapshot().connections_admitted, 1);
    assert_eq!(observations.snapshot().connection_task_failures, 1);
    assert_eq!(observations.snapshot().upgrade_failures, 0);
}

#[tokio::test]
async fn closed_admission_retains_shape_error_priority() {
    let executor: NativeBlockingExecutor = NativeBlockingExecutor::new(
        NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let observations: NativeHttpObservations = executor.observations();
    let app: Router = closed_event_router_with_executor(executor.clone());
    executor.close();
    let shape: Response = app.clone().oneshot(Request::post(NODE_EVENT_PATH)
        .body(Body::from(vec![1, 2, 3])).unwrap()).await.unwrap();
    assert_eq!(shape.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(observations.snapshot().blocking_closed, 0);
    let closed: Response = app.clone().oneshot(Request::post(NODE_EVENT_PATH)
        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
        .body(Body::from(vec![1, 2, 3])).unwrap()).await.unwrap();
    assert_eq!(closed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(to_bytes(closed.into_body(), 128).await.unwrap(), "blocking-admission-closed");
    assert_eq!(observations.snapshot().blocking_closed, 1);
    let health: Response = app.oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(health.status(), StatusCode::NO_CONTENT);
    executor.wait_drained().await;
}
