//! Distinct-UID transport for the existing recurring-successor router.
//! The worker retains the key, store, artifacts and fresh warrant. This module
//! carries complete bounded HTTP requests and responses, never signing frames.
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use canonical_encoding::MAX_CANONICAL_FRAME_BYTES;
use hashing::HashSuiteResolver;
use node_core::{genesis::VerifiedGenesisRoot, serving_authority::VerifiedSuccessorAuthority};
use protocol_types::ValidatorId;
use std::{
    future::Future,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    time::{Instant, timeout_at},
};
use tower::ServiceExt;

mod verification;

pub type Application = Router;

const PROFILE: &[u8; 8] = b"SCSV\0\0\0\x01";
// Hyper accepts at most 64 request headers within a 64 KiB read buffer.
// The private envelope retains that complete accepted surface.
const MAX_HEADERS: usize = 64;
const MAX_HEADER: usize = 64 * 1024;
const MAX_HEADER_TOTAL: usize = 64 * 1024;
const MAX_PATH: usize = 64 * 1024;
const MAX_FRAME: usize = MAX_CANONICAL_FRAME_BYTES + 2 * MAX_HEADER_TOTAL + MAX_PATH + 4096;
fn refused() -> io::Error {
    io::Error::other("successor custody refused")
}

/// Public, fixed startup identity; it never grants live serving authority.
#[derive(Clone, Copy)]
pub struct Identity {
    validator: ValidatorId,
    domain: protocol_types::AtomicityDomainId,
    genesis: [u8; 32],
    subject: [u8; 32],
}
impl Identity {
    pub fn new(
        validator: ValidatorId,
        domain: protocol_types::AtomicityDomainId,
        genesis: [u8; 32],
        subject: [u8; 32],
    ) -> Self {
        Self {
            validator,
            domain,
            genesis,
            subject,
        }
    }
    fn encode(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(128);
        bytes.extend_from_slice(self.validator.as_bytes());
        bytes.extend_from_slice(self.domain.as_bytes());
        bytes.extend_from_slice(&self.genesis);
        bytes.extend_from_slice(&self.subject);
        bytes
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let end: usize = self.offset.checked_add(count).ok_or_else(refused)?;
        let part: &'a [u8] = self.bytes.get(self.offset..end).ok_or_else(refused)?;
        self.offset = end;
        Ok(part)
    }
    fn field(&mut self, max: usize) -> io::Result<&'a [u8]> {
        let count: u32 = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| refused())?);
        let count: usize = usize::try_from(count).map_err(|_| refused())?;
        if count > max {
            return Err(refused());
        }
        self.take(count)
    }
    fn finish(self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(refused())
        }
    }
}
fn put(bytes: &mut Vec<u8>, value: &[u8], max: usize) -> io::Result<()> {
    if value.len() > max {
        return Err(refused());
    }
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value);
    Ok(())
}
fn decode_headers(cursor: &mut Cursor<'_>) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let count: usize = usize::from(cursor.take(1)?[0]);
    if count > MAX_HEADERS {
        return Err(refused());
    }
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(count);
    let mut total: usize = 0;
    for _ in 0..count {
        let name: Vec<u8> = cursor.field(MAX_HEADER)?.to_vec();
        let value: Vec<u8> = cursor.field(MAX_HEADER)?.to_vec();
        total = total
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(refused)?;
        if total > MAX_HEADER_TOTAL {
            return Err(refused());
        }
        HeaderName::from_bytes(&name).map_err(|_| refused())?;
        HeaderValue::from_bytes(&value).map_err(|_| refused())?;
        headers.push((name, value));
    }
    Ok(headers)
}
fn encode_headers(bytes: &mut Vec<u8>, headers: &[(Vec<u8>, Vec<u8>)]) -> io::Result<()> {
    if headers.len() > MAX_HEADERS {
        return Err(refused());
    }
    bytes.push(u8::try_from(headers.len()).map_err(|_| refused())?);
    let mut total: usize = 0;
    for (name, value) in headers {
        total = total
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(refused)?;
        if total > MAX_HEADER_TOTAL {
            return Err(refused());
        }
        put(bytes, name, MAX_HEADER)?;
        put(bytes, value, MAX_HEADER)?;
    }
    Ok(())
}
fn header_map(headers: &[(Vec<u8>, Vec<u8>)]) -> io::Result<HeaderMap> {
    let mut map: HeaderMap = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            HeaderName::from_bytes(name).map_err(|_| refused())?,
            HeaderValue::from_bytes(value).map_err(|_| refused())?,
        );
    }
    Ok(map)
}
fn header_pairs(headers: &HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect()
}

struct Input {
    method: Method,
    uri: Uri,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}
impl Input {
    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes: Vec<u8> = PROFILE.to_vec();
        bytes.push(if self.method == Method::GET {
            1
        } else if self.method == Method::POST {
            2
        } else {
            3
        });
        if bytes[8] == 3 {
            put(&mut bytes, self.method.as_str().as_bytes(), 16)?;
        }
        put(&mut bytes, self.uri.to_string().as_bytes(), MAX_PATH)?;
        encode_headers(&mut bytes, &self.headers)?;
        put(&mut bytes, &self.body, MAX_CANONICAL_FRAME_BYTES)?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(refused());
        }
        let mut cursor: Cursor<'_> = Cursor { bytes, offset: 0 };
        if cursor.take(PROFILE.len())? != PROFILE {
            return Err(refused());
        }
        let method: Method = match cursor.take(1)?[0] {
            1 => Method::GET,
            2 => Method::POST,
            3 => Method::from_bytes(cursor.field(16)?).map_err(|_| refused())?,
            _ => return Err(refused()),
        };
        let uri: Uri = std::str::from_utf8(cursor.field(MAX_PATH)?)
            .map_err(|_| refused())?
            .parse()
            .map_err(|_| refused())?;
        if !uri.path().starts_with('/') || uri.authority().is_some() {
            return Err(refused());
        }
        let headers: Vec<(Vec<u8>, Vec<u8>)> = decode_headers(&mut cursor)?;
        let body: Vec<u8> = cursor.field(MAX_CANONICAL_FRAME_BYTES)?.to_vec();
        cursor.finish()?;
        Ok(Self {
            method,
            uri,
            headers,
            body,
        })
    }
}

struct Output {
    status: StatusCode,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}
impl Output {
    fn encode(&self) -> io::Result<Vec<u8>> {
        let mut bytes: Vec<u8> = PROFILE.to_vec();
        bytes.extend_from_slice(&self.status.as_u16().to_be_bytes());
        encode_headers(&mut bytes, &self.headers)?;
        put(&mut bytes, &self.body, MAX_CANONICAL_FRAME_BYTES)?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_FRAME {
            return Err(refused());
        }
        let mut cursor: Cursor<'_> = Cursor { bytes, offset: 0 };
        if cursor.take(PROFILE.len())? != PROFILE {
            return Err(refused());
        }
        let status: StatusCode = StatusCode::from_u16(u16::from_be_bytes(
            cursor.take(2)?.try_into().map_err(|_| refused())?,
        ))
        .map_err(|_| refused())?;
        let headers: Vec<(Vec<u8>, Vec<u8>)> = decode_headers(&mut cursor)?;
        let body: Vec<u8> = cursor.field(MAX_CANONICAL_FRAME_BYTES)?.to_vec();
        cursor.finish()?;
        Ok(Self {
            status,
            headers,
            body,
        })
    }
    fn response(self) -> io::Result<Response> {
        let mut response: Response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = header_map(&self.headers)?;
        Ok(response)
    }
}

async fn execute(app: Router, input: Input) -> io::Result<Output> {
    let mut request: Request<Body> = Request::builder()
        .method(input.method)
        .uri(input.uri)
        .body(Body::from(input.body))
        .map_err(|_| refused())?;
    *request.headers_mut() = header_map(&input.headers)?;
    let response: Response = app.oneshot(request).await.map_err(|_| refused())?;
    let status: StatusCode = response.status();
    let headers: Vec<(Vec<u8>, Vec<u8>)> = header_pairs(response.headers());
    let body: Bytes = to_bytes(response.into_body(), MAX_CANONICAL_FRAME_BYTES)
        .await
        .map_err(|_| refused())?;
    Ok(Output {
        status,
        headers,
        body: body.to_vec(),
    })
}

/// A bounded authenticated socket dispatches exclusively through the real successor router.
#[allow(clippy::too_many_arguments)]
pub async fn serve_worker<F>(
    listener: UnixListener,
    app: Router,
    executor: crate::NativeBlockingExecutor,
    identity: Identity,
    frontend_uid: u32,
    max_connections: u64,
    max_requests: u64,
    request_timeout: Duration,
    end: Instant,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let mut connections: u64 = 0;
    let mut requests: u64 = 0;
    // One authenticated context preflight is required before the frontend
    // advertises readiness. The configured quota counts public requests.
    let request_limit: u64 = max_requests.checked_add(1).ok_or_else(refused)?;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        if connections >= max_connections || requests >= request_limit {
            // No more work can be admitted. Return immediately to the owner,
            // which closes admission and drains its blocking executor before
            // releasing the socket and fenced target.
            return Ok(());
        }
        let (mut stream, _) = tokio::select! {biased; ()=&mut shutdown=>return Ok(()), value=listener.accept()=>value?};
        connections = connections.checked_add(1).ok_or_else(refused)?;
        if crate::local_custody_transport::authenticate(&stream, frontend_uid, refused).is_err() {
            continue;
        }
        requests = requests.checked_add(1).ok_or_else(refused)?;
        let deadline: Instant = end.min(
            Instant::now()
                .checked_add(request_timeout)
                .ok_or_else(refused)?,
        );
        let work = async {
            let bytes: Vec<u8> =
                crate::local_custody_transport::read_frame(&mut stream, MAX_FRAME, refused).await?;
            let output: Output = execute(app.clone(), Input::decode(&bytes)?).await?;
            let mut bytes: Vec<u8> = identity.encode();
            bytes.extend_from_slice(&output.encode()?);
            crate::local_custody_transport::write_frame(&mut stream, &bytes, refused).await
        };
        let result: Result<io::Result<()>, tokio::time::error::Elapsed> = tokio::select! {biased; ()=&mut shutdown=>return Ok(()), result=timeout_at(deadline, work)=>result};
        match result {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                // A canceled router future may leave a tracked blocking job
                // completing an already admitted mutation. This worker is
                // serial: wait for that job to finish before accepting another
                // request under the same fence. The failed caller receives no
                // success bytes and can retry against retained state.
                tokio::select! {
                    biased;
                    ()=&mut shutdown=>return Ok(()),
                    ()=executor.wait_drained()=>{},
                }
            }
        }
    }
}

/// Keyless frontend. Public evidence is independently verified before construction.
pub struct Frontend {
    socket: PathBuf,
    worker_uid: u32,
    identity: Identity,
    evidence: verification::PublicEvidence,
    timeout: Duration,
    end: Instant,
    remaining: AtomicU64,
}
impl Frontend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket: PathBuf,
        worker_uid: u32,
        validator: ValidatorId,
        root: &VerifiedGenesisRoot,
        verified: &VerifiedSuccessorAuthority,
        resolver: HashSuiteResolver,
        query_config: protocol_config::ProtocolConfig,
        timeout: Duration,
        end: Instant,
        max_requests: u64,
    ) -> io::Result<Self> {
        let evidence: verification::PublicEvidence =
            verification::PublicEvidence::new(validator, root, verified, resolver, query_config)?;
        let identity: Identity = Identity::new(
            validator,
            verified.policy_inputs().domain(),
            root.digest().bytes(),
            verified.subject_digest().bytes(),
        );
        Ok(Self {
            socket,
            worker_uid,
            identity,
            evidence,
            timeout,
            end,
            remaining: AtomicU64::new(max_requests),
        })
    }
    async fn exchange(&self, input: &Input, public_request: bool) -> io::Result<Output> {
        if Instant::now() >= self.end {
            return Err(refused());
        }
        if public_request {
            self.remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left: u64| {
                    left.checked_sub(1)
                })
                .map_err(|_| refused())?;
        }
        let deadline: Instant = self.end.min(
            Instant::now()
                .checked_add(self.timeout)
                .ok_or_else(refused)?,
        );
        timeout_at(deadline, async {
            let mut stream: UnixStream = UnixStream::connect(&self.socket).await?;
            crate::local_custody_transport::authenticate(&stream, self.worker_uid, refused)?;
            crate::local_custody_transport::write_frame(&mut stream, &input.encode()?, refused)
                .await?;
            let bytes: Vec<u8> =
                crate::local_custody_transport::read_frame(&mut stream, MAX_FRAME + 128, refused)
                    .await?;
            if bytes.get(..128) != Some(self.identity.encode().as_slice()) {
                return Err(refused());
            }
            Output::decode(bytes.get(128..).ok_or_else(refused)?)
        })
        .await
        .map_err(|_| refused())?
    }
    pub async fn preflight(&self) -> io::Result<()> {
        let input: Input = Input {
            method: Method::GET,
            uri: node_wire::QUERY_CONTEXT_PATH
                .parse()
                .map_err(|_| refused())?,
            headers: Vec::new(),
            body: Vec::new(),
        };
        let output: Output = self.exchange(&input, false).await?;
        self.evidence.verify(&input, &output)
    }
}
async fn proxy(State(frontend): State<Arc<Frontend>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let body: Bytes = match to_bytes(body, MAX_CANONICAL_FRAME_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let input: Input = Input {
        method: parts.method,
        uri: parts.uri,
        headers: header_pairs(&parts.headers),
        body: body.to_vec(),
    };
    let output: Output = match frontend.exchange(&input, true).await {
        Ok(output) => output,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if frontend.evidence.verify(&input, &output).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    output
        .response()
        .unwrap_or_else(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())
}
pub fn frontend_router(frontend: Arc<Frontend>) -> Router {
    Router::new().fallback(any(proxy)).with_state(frontend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use std::{num::NonZeroUsize, os::unix::fs::MetadataExt, path::Path, sync::Mutex};
    use tokio::sync::oneshot;

    static NEXT: AtomicU64 = AtomicU64::new(1);
    type JobGate = (oneshot::Sender<()>, oneshot::Receiver<()>);
    type SharedJobGate = Arc<Mutex<Option<JobGate>>>;

    struct SocketPath(PathBuf);
    impl SocketPath {
        fn new() -> Self {
            let sequence: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
            let directory: PathBuf = std::env::temp_dir().join(format!(
                "sunrise-successor-custody-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            Self(directory.join("worker.sock"))
        }
        fn uid(&self) -> u32 {
            std::fs::metadata(&self.0).unwrap().uid()
        }
    }
    impl Drop for SocketPath {
        fn drop(&mut self) {
            let _removed: io::Result<()> = std::fs::remove_file(&self.0);
            let _removed: io::Result<()> =
                std::fs::remove_dir(self.0.parent().unwrap_or(Path::new("/nonexistent")));
        }
    }

    fn executor() -> crate::NativeBlockingExecutor {
        crate::NativeBlockingExecutor::new(crate::NativeBlockingPolicy::new(
            NonZeroUsize::new(2).unwrap(),
        ))
    }
    fn identity() -> Identity {
        Identity::new(
            ValidatorId::new([1; 32]),
            protocol_types::AtomicityDomainId::new([2; 32]).unwrap(),
            [3; 32],
            [4; 32],
        )
    }
    async fn send(path: &Path, route: &str) -> io::Result<Output> {
        let input: Input = Input {
            method: Method::GET,
            uri: route.parse().map_err(|_| refused())?,
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut stream: UnixStream = UnixStream::connect(path).await?;
        crate::local_custody_transport::write_frame(&mut stream, &input.encode()?, refused).await?;
        let bytes: Vec<u8> =
            crate::local_custody_transport::read_frame(&mut stream, MAX_FRAME + 128, refused)
                .await?;
        if bytes.get(..128) != Some(identity().encode().as_slice()) {
            return Err(refused());
        }
        Output::decode(bytes.get(128..).ok_or_else(refused)?)
    }

    #[tokio::test]
    async fn one_public_request_remains_after_context_preflight() {
        let path: SocketPath = SocketPath::new();
        let listener: UnixListener = UnixListener::bind(&path.0).unwrap();
        let app: Router = Router::new()
            .route("/context", get(|| async { "context" }))
            .route("/public", get(|| async { "public" }));
        let worker = tokio::spawn(serve_worker(
            listener,
            app,
            executor(),
            identity(),
            path.uid(),
            2,
            1,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(5),
            std::future::pending(),
        ));
        assert_eq!(send(&path.0, "/context").await.unwrap().body, b"context");
        assert_eq!(send(&path.0, "/public").await.unwrap().body, b"public");
        assert!(worker.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn lost_reply_after_committed_handler_keeps_worker_available() {
        let path: SocketPath = SocketPath::new();
        let listener: UnixListener = UnixListener::bind(&path.0).unwrap();
        let (committed_tx, committed_rx) = oneshot::channel::<()>();
        let signal: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(Some(committed_tx)));
        let app: Router = Router::new()
            .route(
                "/commit",
                post({
                    let signal: Arc<Mutex<Option<oneshot::Sender<()>>>> = Arc::clone(&signal);
                    move || async move {
                        if let Some(sender) = signal.lock().unwrap().take() {
                            let _sent = sender.send(());
                        }
                        "committed"
                    }
                }),
            )
            .route("/status", get(|| async { "retained" }));
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let worker = tokio::spawn(serve_worker(
            listener,
            app,
            executor(),
            identity(),
            path.uid(),
            4,
            2,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(5),
            async move {
                let _stopped = stop_rx.await;
            },
        ));
        let input: Input = Input {
            method: Method::POST,
            uri: "/commit".parse().unwrap(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut lost: UnixStream = UnixStream::connect(&path.0).await.unwrap();
        crate::local_custody_transport::write_frame(&mut lost, &input.encode().unwrap(), refused)
            .await
            .unwrap();
        drop(lost);
        committed_rx.await.unwrap();
        assert_eq!(send(&path.0, "/status").await.unwrap().body, b"retained");
        let _sent = stop_tx.send(());
        assert!(worker.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn timed_out_request_drains_admitted_job_before_next_request() {
        let path: SocketPath = SocketPath::new();
        let listener: UnixListener = UnixListener::bind(&path.0).unwrap();
        let executor: crate::NativeBlockingExecutor = executor();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let controls: SharedJobGate = Arc::new(Mutex::new(Some((started_tx, release_rx))));
        let app: Router = Router::new()
            .route(
                "/slow",
                get({
                    let controls = Arc::clone(&controls);
                    let executor = executor.clone();
                    move || async move {
                        let (started, release) = controls.lock().unwrap().take().unwrap();
                        let permit = executor.try_acquire().unwrap();
                        let job = tokio::task::spawn_blocking(move || {
                            let _permit = permit;
                            let _sent = started.send(());
                            let _released = release.blocking_recv();
                        });
                        job.await.unwrap();
                        "done"
                    }
                }),
            )
            .route("/next", get(|| async { "next" }));
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let worker = tokio::spawn(serve_worker(
            listener,
            app,
            executor,
            identity(),
            path.uid(),
            4,
            2,
            Duration::from_millis(50),
            Instant::now() + Duration::from_secs(5),
            async move {
                let _stopped = stop_rx.await;
            },
        ));
        let input: Input = Input {
            method: Method::GET,
            uri: "/slow".parse().unwrap(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut slow: UnixStream = UnixStream::connect(&path.0).await.unwrap();
        crate::local_custody_transport::write_frame(&mut slow, &input.encode().unwrap(), refused)
            .await
            .unwrap();
        started_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let next = tokio::spawn({
            let path = path.0.clone();
            async move { send(&path, "/next").await }
        });
        let mut next = next;
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut next)
                .await
                .is_err()
        );
        let _released = release_tx.send(());
        let response: Output = tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.body, b"next");
        let _sent = stop_tx.send(());
        assert!(worker.await.unwrap().is_ok());
    }
}
