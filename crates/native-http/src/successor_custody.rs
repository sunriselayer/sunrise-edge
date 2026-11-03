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
/// Smallest worker connection or request budget, and frontend request budget, that can still
/// serve public work. The frontend's startup preflight spends one of each at both ends.
pub const MIN_BUDGET: u64 = 2;
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
/// A failed, timed-out or abandoned delivery refuses only its own connection; the worker keeps
/// serving until a budget, the deadline or `shutdown` closes admission.
#[allow(clippy::too_many_arguments)]
pub async fn serve_worker<F>(
    listener: UnixListener,
    app: Router,
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
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        if connections >= max_connections || requests >= max_requests {
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
        // The delivery outcome is deliberately ignored. A frontend deadline, dropped
        // connection or malformed frame refuses only this connection. It never cancels
        // a started blocking operation, and it must not end the worker: the owner would
        // close the executor and a restart would claim the next writer fence, even if
        // the abandoned work already mutated storage. A lost reply reconciles through
        // the exact-request path, never through a transport retry.
        tokio::select! {biased; ()=&mut shutdown=>return Ok(()), _result=timeout_at(deadline, work)=>{}}
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
    async fn exchange(&self, input: &Input) -> io::Result<Output> {
        if Instant::now() >= self.end {
            return Err(refused());
        }
        self.remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left: u64| {
                left.checked_sub(1)
            })
            .map_err(|_| refused())?;
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
    /// A peer-authenticated context query before HTTP readiness. It spends one request at
    /// both ends, so it is refused before any IPC unless a public request would still fit.
    pub async fn preflight(&self) -> io::Result<()> {
        if self.remaining.load(Ordering::Relaxed) < MIN_BUDGET {
            return Err(refused());
        }
        let input: Input = Input {
            method: Method::GET,
            uri: node_wire::QUERY_CONTEXT_PATH
                .parse()
                .map_err(|_| refused())?,
            headers: Vec::new(),
            body: Vec::new(),
        };
        let output: Output = self.exchange(&input).await?;
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
    let output: Output = match frontend.exchange(&input).await {
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
    use tokio::io::AsyncWriteExt;

    struct SocketFixture {
        directory: PathBuf,
        path: PathBuf,
    }
    impl SocketFixture {
        fn new(label: &str) -> Self {
            let nonce: u128 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            // A short name keeps the socket path below the platform SUN_LEN limit.
            let name: String = format!("sc-{}-{label}-{nonce}", std::process::id());
            let directory: PathBuf = std::env::temp_dir().join(name);
            std::fs::create_dir(&directory).unwrap();
            let path: PathBuf = directory.join("w.sock");
            Self { directory, path }
        }
    }
    impl Drop for SocketFixture {
        fn drop(&mut self) {
            let _removed: io::Result<()> = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn identity() -> Identity {
        Identity::new(
            ValidatorId::new([1; 32]),
            protocol_types::AtomicityDomainId::new([2; 32]).unwrap(),
            [3; 32],
            [4; 32],
        )
    }

    fn probe() -> Input {
        Input {
            method: Method::GET,
            uri: Uri::from_static("/probe"),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn ok_router() -> Router {
        Router::new().fallback(|| async { StatusCode::OK })
    }

    fn own_uid() -> u32 {
        let (first, _second): (UnixStream, UnixStream) = UnixStream::pair().unwrap();
        first.peer_cred().unwrap().uid()
    }

    async fn within<T>(work: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), work)
            .await
            .unwrap()
    }

    async fn send(stream: &mut UnixStream, bytes: &[u8]) {
        let sent: io::Result<()> =
            crate::local_custody_transport::write_frame(stream, bytes, refused).await;
        sent.unwrap();
    }

    async fn receive(stream: &mut UnixStream) -> Vec<u8> {
        let received: io::Result<Vec<u8>> =
            crate::local_custody_transport::read_frame(stream, MAX_FRAME + 128, refused).await;
        received.unwrap()
    }

    /// One complete request; returns the status the worker's router answered with.
    async fn exchange_once(path: &std::path::Path) -> StatusCode {
        let mut stream: UnixStream = UnixStream::connect(path).await.unwrap();
        send(&mut stream, &probe().encode().unwrap()).await;
        let bytes: Vec<u8> = receive(&mut stream).await;
        assert_eq!(bytes.get(..128), Some(identity().encode().as_slice()));
        Output::decode(bytes.get(128..).unwrap()).unwrap().status
    }

    #[tokio::test]
    async fn abandoned_or_malformed_deliveries_do_not_end_the_worker() {
        let fixture: SocketFixture = SocketFixture::new("lost");
        let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
        let limit: Duration = Duration::from_secs(30);
        let end: Instant = Instant::now().checked_add(limit).unwrap();
        let server = serve_worker(
            listener,
            ok_router(),
            identity(),
            own_uid(),
            4,
            4,
            Duration::from_millis(300),
            end,
            std::future::pending::<()>(),
        );
        let client = async {
            // Sends nothing, so only the per-request deadline can end this delivery.
            let idle: UnixStream = UnixStream::connect(&fixture.path).await.unwrap();
            // Announces a frame, then disappears before sending it.
            let mut truncated: UnixStream = UnixStream::connect(&fixture.path).await.unwrap();
            truncated.write_u32(1024).await.unwrap();
            drop(truncated);
            // A complete frame that is not a request.
            let mut malformed: UnixStream = UnixStream::connect(&fixture.path).await.unwrap();
            send(&mut malformed, b"not a request").await;
            // The same worker still serves a genuine request afterwards.
            assert_eq!(exchange_once(&fixture.path).await, StatusCode::OK);
            drop(idle);
        };
        let (served, ()) = within(async { tokio::join!(server, client) }).await;
        served.unwrap();
    }

    #[tokio::test]
    async fn startup_preflight_spends_one_slot_of_each_worker_budget() {
        for budget in [1, MIN_BUDGET] {
            let fixture: SocketFixture = SocketFixture::new("budget");
            let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
            let limit: Duration = Duration::from_secs(30);
            let end: Instant = Instant::now().checked_add(limit).unwrap();
            let server = serve_worker(
                listener,
                ok_router(),
                identity(),
                own_uid(),
                budget,
                budget,
                Duration::from_secs(5),
                end,
                std::future::pending::<()>(),
            );
            // The first exchange stands for the frontend's startup preflight.
            let client = async {
                for _ in 0..budget {
                    assert_eq!(exchange_once(&fixture.path).await, StatusCode::OK);
                }
            };
            let (served, ()) = within(async { tokio::join!(server, client) }).await;
            served.unwrap();
            // A budget of one is spent by the preflight alone; both close admission.
            assert!(UnixStream::connect(&fixture.path).await.is_err());
        }
    }
}
