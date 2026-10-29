//! DR-0268 deployment-only certified FastVote custody transport.
//! Original HTTP operations enter the actual owning router; no signature frame,
//! database handle, caller-selected factory or authority warrant crosses IPC.
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use canonical_encoding::MAX_CANONICAL_FRAME_BYTES;
use consensus::{AvailabilityCertifier, FastPathCertifier, FrozenFrontierCertifier};
use execution::paid_execution::{MAX_PAID_FEE_POLICY_BYTES, MAX_SIGNED_PAID_INTENT_BYTES};
use hashing::HashSuiteResolver;
use node_wire::*;
use protocol_types::{AtomicityDomainId, ValidatorId};
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{Instant, timeout_at},
};
use tower::ServiceExt;

/// Existing complete router, with state retained only in the worker.
pub type Application = Router;
// Independent private profile. Neither ordered IPCv2 nor canonical protocol frames
// share this prefix. Version 1 includes both input and output profile separation.
const PROFILE: &[u8; 8] = b"SCFV\0\0\0\x01";
const MAX_HEADERS: usize = 64;
const MAX_HEADER: usize = 256;
const MAX_FRAME: usize = MAX_CANONICAL_FRAME_BYTES + 2 * MAX_HEADERS * (MAX_HEADER + 8) + 4096;
fn refused() -> io::Error {
    io::Error::other("certified FastVote custody refused")
}

/// Identity fixed by independently verified local configuration, never a warrant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    validator: ValidatorId,
    domain: AtomicityDomainId,
    genesis: [u8; 32],
}
impl Identity {
    /// Uses the actual role-local genesis, validator and logical domain pins.
    pub fn new(validator: ValidatorId, domain: AtomicityDomainId, genesis: [u8; 32]) -> Self {
        Self {
            validator,
            domain,
            genesis,
        }
    }
    fn encode(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(96);
        bytes.extend_from_slice(self.validator.as_bytes());
        bytes.extend_from_slice(self.domain.as_bytes());
        bytes.extend_from_slice(&self.genesis);
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Route {
    Prepare = 1,
    Apply = 2,
    Source = 3,
    Retain = 4,
    PublishedApply = 5,
    RetainedSource = 6,
    FrontierPage = 7,
    FrontierAdvance = 8,
    SignerPage = 9,
    MemberConfirm = 10,
    UnionAdvance = 11,
    SignerProgress = 12,
    DrainApply = 13,
    Import = 14,
    Context = 15,
    Object = 16,
    Receipt = 17,
    Nonce = 18,
    FeePolicy = 19,
    Publication = 20,
    Instance = 21,
    Live = 22,
}
struct Spec {
    path: &'static str,
    request: usize,
    response: usize,
    keys: &'static [&'static str],
}
impl Route {
    const ALL: [Self; 22] = [
        Self::Prepare,
        Self::Apply,
        Self::Source,
        Self::Retain,
        Self::PublishedApply,
        Self::RetainedSource,
        Self::FrontierPage,
        Self::FrontierAdvance,
        Self::SignerPage,
        Self::MemberConfirm,
        Self::UnionAdvance,
        Self::SignerProgress,
        Self::DrainApply,
        Self::Import,
        Self::Context,
        Self::Object,
        Self::Receipt,
        Self::Nonce,
        Self::FeePolicy,
        Self::Publication,
        Self::Instance,
        Self::Live,
    ];
    fn decode(code: u8) -> io::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|route: &Self| *route as u8 == code)
            .ok_or_else(refused)
    }
    fn method(self) -> Method {
        if (self as u8) >= 15 {
            Method::GET
        } else {
            Method::POST
        }
    }
    fn spec(self) -> Spec {
        let (path, request, response, keys): (&'static str, usize, usize, &'static [&'static str]) =
            match self {
                Self::Prepare => (
                    FASTVOTE_PREPARE_PATH,
                    MAX_SIGNED_PAID_INTENT_BYTES,
                    MAX_FASTVOTE_VOTE_BYTES,
                    &[],
                ),
                Self::Apply => (
                    FASTVOTE_CERTIFICATES_PATH,
                    MAX_FASTVOTE_APPLY_REQUEST_BYTES,
                    MAX_CANONICAL_FRAME_BYTES,
                    &[],
                ),
                Self::Source => (
                    FASTVOTE_PUBLICATION_SOURCE_PATH,
                    MAX_FASTVOTE_APPLY_REQUEST_BYTES,
                    consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
                    &[],
                ),
                Self::Retain => (
                    FASTVOTE_PUBLICATION_RETAIN_PATH,
                    consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
                    consensus::MAX_ENCODED_AVAILABILITY_VOTE_BYTES,
                    &[],
                ),
                Self::PublishedApply => (
                    FASTVOTE_PUBLISHED_APPLY_PATH,
                    MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES,
                    MAX_CANONICAL_FRAME_BYTES,
                    &[],
                ),
                Self::RetainedSource => (
                    FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
                    MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES,
                    consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
                    &[],
                ),
                Self::FrontierPage => (
                    FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
                    MAX_FRONTIER_PAGE_REQUEST_BYTES,
                    MAX_FRONTIER_PAGE_RESPONSE_BYTES,
                    &[],
                ),
                Self::FrontierAdvance => (
                    FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
                    1,
                    MAX_FRONTIER_VOTE_BYTES,
                    &[],
                ),
                Self::SignerPage => (
                    FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
                    MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES,
                    0,
                    &[],
                ),
                Self::MemberConfirm => (
                    FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
                    MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES,
                    0,
                    &[],
                ),
                Self::UnionAdvance => (
                    FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
                    MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES,
                    consensus::MAX_DRAIN_UNION_IDENTITY_BYTES,
                    &[],
                ),
                Self::SignerProgress => (
                    FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
                    MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES,
                    MAX_DRAIN_SIGNER_PROGRESS_RESPONSE_BYTES,
                    &[],
                ),
                Self::DrainApply => (
                    FASTVOTE_DRAIN_APPLY_PATH,
                    MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES,
                    MAX_CANONICAL_FRAME_BYTES,
                    &[],
                ),
                Self::Import => (
                    FASTVOTE_DRAIN_IMPORT_PATH,
                    consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
                    consensus::MAX_ENCODED_AVAILABILITY_IDENTITY_BYTES,
                    &["validator_id"],
                ),
                Self::Context => (QUERY_CONTEXT_PATH, 0, MAX_CANONICAL_FRAME_BYTES, &[]),
                Self::Object => (
                    QUERY_OBJECT_PATH,
                    0,
                    MAX_CANONICAL_FRAME_BYTES,
                    &["object_id"],
                ),
                Self::Receipt => (
                    QUERY_RECEIPT_PATH,
                    0,
                    MAX_CANONICAL_FRAME_BYTES,
                    &["request_id"],
                ),
                Self::Nonce => (
                    QUERY_NEXT_NONCE_PATH,
                    0,
                    MAX_CANONICAL_FRAME_BYTES,
                    &["sender"],
                ),
                Self::FeePolicy => (
                    crate::paid_execution::PAID_FEE_POLICY_PATH,
                    0,
                    MAX_PAID_FEE_POLICY_BYTES,
                    &[],
                ),
                Self::Publication => (
                    crate::publication::QUERY_PATH,
                    0,
                    execution::publication::MAX_PUBLICATION_QUERY_RESULT_BYTES,
                    &["publisher", "origin_seed"],
                ),
                Self::Instance => (
                    crate::local_execution::INSTANCE_PATH,
                    0,
                    MAX_CANONICAL_FRAME_BYTES,
                    &["creator", "seed"],
                ),
                Self::Live => (LIVENESS_PATH, 0, 0, &[]),
            };
        Spec {
            path,
            request,
            response,
            keys,
        }
    }
    fn path(self, selectors: &[[u8; 32]]) -> io::Result<String> {
        let spec: Spec = self.spec();
        if selectors.len() != spec.keys.len() {
            return Err(refused());
        }
        let mut path: String = spec.path.into();
        for (key, value) in spec.keys.iter().zip(selectors) {
            let encoded: String = value
                .iter()
                .map(|byte: &u8| format!("{byte:02x}"))
                .collect();
            path = path.replace(&format!("{{{key}}}"), &encoded);
        }
        Ok(path)
    }
    fn empty_success(self) -> bool {
        matches!(
            self,
            Self::Live
                | Self::FrontierAdvance
                | Self::SignerPage
                | Self::MemberConfirm
                | Self::UnionAdvance
        )
    }
    fn selector_error(self) -> &'static str {
        match self {
            Self::Import => "invalid-drain-validator",
            Self::Object => "invalid-object-id",
            Self::Receipt => "invalid-request-id",
            Self::Nonce => "invalid-sender",
            Self::Publication => "invalid-publication-selector",
            Self::Instance => "invalid-instance-selector",
            _ => "invalid-selector",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    route: Route,
    selectors: Vec<[u8; 32]>,
    content_type: Vec<Vec<u8>>,
    encoding: Vec<Vec<u8>>,
    body: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
struct Output {
    status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}
fn put(bytes: &mut Vec<u8>, value: &[u8], cap: usize) -> io::Result<()> {
    if value.len() > cap {
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
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end: usize = self.offset.checked_add(length).ok_or_else(refused)?;
        let result: &'a [u8] = self.bytes.get(self.offset..end).ok_or_else(refused)?;
        self.offset = end;
        Ok(result)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn field(&mut self, cap: usize) -> io::Result<&'a [u8]> {
        let length: usize = usize::try_from(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| refused())?,
        ))
        .map_err(|_| refused())?;
        if length > cap {
            return Err(refused());
        }
        self.take(length)
    }
    fn finish(self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(refused())
        }
    }
    fn values(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let count: usize = usize::from(self.byte()?);
        if count > MAX_HEADERS {
            return Err(refused());
        }
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.field(MAX_HEADER)?.to_vec());
        }
        Ok(values)
    }
}
fn put_values(bytes: &mut Vec<u8>, values: &[Vec<u8>]) -> io::Result<()> {
    if values.len() > MAX_HEADERS {
        return Err(refused());
    }
    bytes.push(u8::try_from(values.len()).map_err(|_| refused())?);
    for value in values {
        put(bytes, value, MAX_HEADER)?;
    }
    Ok(())
}
impl Input {
    fn encode(&self) -> io::Result<Vec<u8>> {
        self.route.path(&self.selectors)?;
        let mut bytes: Vec<u8> = PROFILE.to_vec();
        bytes.push(self.route as u8);
        for selector in &self.selectors {
            bytes.extend_from_slice(selector);
        }
        put_values(&mut bytes, &self.content_type)?;
        put_values(&mut bytes, &self.encoding)?;
        put(&mut bytes, &self.body, self.route.spec().request)?;
        if bytes.len() > MAX_FRAME {
            return Err(refused());
        }
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
        let route: Route = Route::decode(cursor.byte()?)?;
        let mut selectors: Vec<[u8; 32]> = Vec::with_capacity(route.spec().keys.len());
        for _ in route.spec().keys {
            selectors.push(cursor.take(32)?.try_into().map_err(|_| refused())?);
        }
        let content_type: Vec<Vec<u8>> = cursor.values()?;
        let encoding: Vec<Vec<u8>> = cursor.values()?;
        let body: Vec<u8> = cursor.field(route.spec().request)?.to_vec();
        cursor.finish()?;
        Ok(Self {
            route,
            selectors,
            content_type,
            encoding,
            body,
        })
    }
}
impl Output {
    fn encode(&self) -> io::Result<Vec<u8>> {
        StatusCode::from_u16(self.status).map_err(|_| refused())?;
        if self.headers.len() > MAX_HEADERS {
            return Err(refused());
        }
        let mut bytes: Vec<u8> = PROFILE.to_vec();
        bytes.extend_from_slice(&self.status.to_be_bytes());
        bytes.push(u8::try_from(self.headers.len()).map_err(|_| refused())?);
        for (name, value) in &self.headers {
            put(&mut bytes, name, MAX_HEADER)?;
            put(&mut bytes, value, MAX_HEADER)?;
        }
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
        let status: u16 = u16::from_be_bytes(cursor.take(2)?.try_into().map_err(|_| refused())?);
        StatusCode::from_u16(status).map_err(|_| refused())?;
        let count: usize = usize::from(cursor.byte()?);
        if count > MAX_HEADERS {
            return Err(refused());
        }
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(count);
        for _ in 0..count {
            headers.push((
                cursor.field(MAX_HEADER)?.to_vec(),
                cursor.field(MAX_HEADER)?.to_vec(),
            ));
        }
        let body: Vec<u8> = cursor.field(MAX_CANONICAL_FRAME_BYTES)?.to_vec();
        cursor.finish()?;
        let output: Self = Self {
            status,
            headers,
            body,
        };
        output.header_map()?;
        Ok(output)
    }
    fn header_map(&self) -> io::Result<HeaderMap> {
        let mut headers: HeaderMap = HeaderMap::new();
        for (name, value) in &self.headers {
            headers.append(
                HeaderName::from_bytes(name).map_err(|_| refused())?,
                HeaderValue::from_bytes(value).map_err(|_| refused())?,
            );
        }
        Ok(headers)
    }
    fn response(self) -> io::Result<Response> {
        let headers: HeaderMap = self.header_map()?;
        let mut response: Response = Response::new(Body::from(self.body));
        *response.status_mut() = StatusCode::from_u16(self.status).map_err(|_| refused())?;
        *response.headers_mut() = headers;
        Ok(response)
    }
}
async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let size: usize = usize::try_from(stream.read_u32().await?).map_err(|_| refused())?;
    if size == 0 || size > MAX_FRAME {
        return Err(refused());
    }
    let mut bytes: Vec<u8> = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    let mut trailing: [u8; 1] = [0];
    if stream.read(&mut trailing).await? != 0 {
        return Err(refused());
    }
    Ok(bytes)
}
async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(refused());
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| refused())?)
        .await?;
    stream.write_all(bytes).await?;
    stream.shutdown().await
}
fn authenticate(stream: &UnixStream, uid: u32) -> io::Result<()> {
    if stream.peer_cred()?.uid() != uid {
        return Err(refused());
    }
    Ok(())
}
async fn execute(app: Application, input: Input) -> io::Result<Output> {
    let route: Route = input.route;
    let mut request: Request<Body> = Request::builder()
        .method(route.method())
        .uri(route.path(&input.selectors)?)
        .body(Body::from(input.body))
        .map_err(|_| refused())?;
    for (name, values) in [
        (header::CONTENT_TYPE, input.content_type),
        (header::CONTENT_ENCODING, input.encoding),
    ] {
        for value in values {
            request.headers_mut().append(
                name.clone(),
                HeaderValue::from_bytes(&value).map_err(|_| refused())?,
            );
        }
    }
    let response: Response = app.oneshot(request).await.map_err(|_| refused())?;
    let status: u16 = response.status().as_u16();
    let headers: Vec<(Vec<u8>, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(name, value): (&HeaderName, &HeaderValue)| {
            (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec())
        })
        .collect();
    let cap: usize = if (200..300).contains(&status) {
        route.spec().response
    } else {
        MAX_CANONICAL_FRAME_BYTES
    };
    let body: Bytes = to_bytes(response.into_body(), cap)
        .await
        .map_err(|_| refused())?;
    Ok(Output {
        status,
        headers,
        body: body.to_vec(),
    })
}

/// Authenticated finite worker around the actual certified owning router.
/// A delivery timeout never rolls back blocking work; the process owner drains it.
#[allow(clippy::too_many_arguments)]
pub async fn serve_worker<F>(
    listener: UnixListener,
    app: Application,
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
    let mut listener: Option<UnixListener> = Some(listener);
    let mut connections: u64 = 0;
    let mut requests: u64 = 0;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        if connections >= max_connections || requests >= max_requests {
            listener = None;
        }
        let Some(active) = listener.as_ref() else {
            shutdown.await;
            return Ok(());
        };
        let (mut stream, _) =
            tokio::select! {biased;()=&mut shutdown=>return Ok(()),value=active.accept()=>value?};
        connections = connections.checked_add(1).ok_or_else(refused)?;
        if authenticate(&stream, frontend_uid).is_err() {
            continue;
        }
        requests = requests.checked_add(1).ok_or_else(refused)?;
        let deadline: Instant = end.min(
            Instant::now()
                .checked_add(request_timeout)
                .ok_or_else(refused)?,
        );
        let work = async {
            let bytes: Vec<u8> = read_frame(&mut stream).await?;
            let input: Input = Input::decode(&bytes)?;
            let output: Output = execute(app.clone(), input).await?;
            let mut bytes: Vec<u8> = identity.encode();
            bytes.extend_from_slice(&output.encode()?);
            write_frame(&mut stream, &bytes).await
        };
        tokio::select! {biased;()=&mut shutdown=>return Ok(()),_result=timeout_at(deadline,work)=>{}}
    }
}

/// Keyless frontend with locally authenticated public pins. Live state decisions
/// remain exclusively inside the actual worker/router on every request.
pub struct Frontend {
    socket: PathBuf,
    worker_uid: u32,
    identity: Identity,
    context: execution::publication::PublicationContext,
    resolver: HashSuiteResolver,
    query_config: protocol_config::ProtocolConfig,
    fast: FastPathCertifier,
    availability: AvailabilityCertifier,
    frontier: FrozenFrontierCertifier,
    timeout: Duration,
    end: Instant,
    remaining: AtomicU64,
    executor: crate::NativeBlockingExecutor,
}
impl Frontend {
    /// Constructs only from the frontend's independently verified original root.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket: PathBuf,
        worker_uid: u32,
        validator: ValidatorId,
        domain: AtomicityDomainId,
        root: &node_core::genesis::VerifiedGenesisRoot,
        resolver: HashSuiteResolver,
        query_config: protocol_config::ProtocolConfig,
        timeout: Duration,
        end: Instant,
        max_requests: u64,
        executor: crate::NativeBlockingExecutor,
    ) -> io::Result<Self> {
        let context: execution::publication::PublicationContext = root.genesis_context().clone();
        if !root.admission_profile().is_causal()
            || resolver.chain_id() != context.chain_id()
            || resolver.protocol_version() != context.protocol_version()
            || resolver.schedules() != root.genesis_resolver().schedules()
            || root.genesis_committee().get(validator).is_none()
        {
            return Err(refused());
        }
        let fast: FastPathCertifier = FastPathCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            root.genesis_committee().clone(),
        )
        .map_err(|_| refused())?;
        let availability: AvailabilityCertifier = AvailabilityCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            root.genesis_committee().clone(),
        )
        .map_err(|_| refused())?;
        let frontier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            root.genesis_committee().clone(),
        )
        .map_err(|_| refused())?;
        Ok(Self {
            socket,
            worker_uid,
            identity: Identity::new(validator, domain, root.digest().bytes()),
            context,
            resolver,
            query_config,
            fast,
            availability,
            frontier,
            timeout,
            end,
            remaining: AtomicU64::new(max_requests),
            executor,
        })
    }
    async fn exchange(&self, input: &Input) -> io::Result<Output> {
        if self.executor.stop_cancellation().is_cancelled() || Instant::now() >= self.end {
            return Err(refused());
        }
        self.remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left: u64| {
                left.checked_sub(1)
            })
            .map_err(|_| refused())?;
        let end: Instant = self.end.min(
            Instant::now()
                .checked_add(self.timeout)
                .ok_or_else(refused)?,
        );
        timeout_at(end, async {
            let mut stream: UnixStream = UnixStream::connect(&self.socket).await?;
            authenticate(&stream, self.worker_uid)?;
            write_frame(&mut stream, &input.encode()?).await?;
            let bytes: Vec<u8> = read_frame(&mut stream).await?;
            if bytes.get(..96) != Some(self.identity.encode().as_slice()) {
                return Err(refused());
            }
            Output::decode(bytes.get(96..).ok_or_else(refused)?)
        })
        .await
        .map_err(|_| refused())?
    }
    /// A real peer-authenticated bounded context query before HTTP readiness;
    /// this observation is never a cached live warrant for later operations.
    pub async fn preflight(self: &Arc<Self>) -> io::Result<()> {
        let input: Input = Input {
            route: Route::Context,
            selectors: Vec::new(),
            content_type: Vec::new(),
            encoding: Vec::new(),
            body: Vec::new(),
        };
        let output: Output = self.exchange(&input).await?;
        let frontend: Arc<Self> = Arc::clone(self);
        let response: Response =
            crate::publication::admitted(false, self.executor.clone(), move || {
                if output.status == 200
                    && frontend.verify(&input, &output).is_ok()
                    && HttpContextQueryResult::decode(&output.body).is_ok_and(
                        |context: HttpContextQueryResult| {
                            context.epoch() == frontend.context.epoch()
                        },
                    )
                {
                    StatusCode::OK.into_response()
                } else {
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
            })
            .await;
        if response.status() != StatusCode::OK {
            return Err(refused());
        }
        Ok(())
    }
}
fn unavailable() -> Response {
    crate::error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "certified-custody-unavailable",
    )
}
async fn forward(frontend: Arc<Frontend>, input: Input) -> Response {
    let output: Output = match frontend.exchange(&input).await {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };
    crate::publication::admitted(false, frontend.executor.clone(), move || {
        match frontend
            .verify(&input, &output)
            .and_then(|()| output.response())
        {
            Ok(response) => response,
            Err(_) => unavailable(),
        }
    })
    .await
}
fn header_values(headers: &HeaderMap, name: HeaderName) -> io::Result<Vec<Vec<u8>>> {
    let mut values: Vec<Vec<u8>> = Vec::new();
    for value in headers.get_all(name).iter() {
        if values.len() >= MAX_HEADERS || value.as_bytes().len() > MAX_HEADER {
            return Err(refused());
        }
        values.push(value.as_bytes().to_vec());
    }
    Ok(values)
}
async fn proxy(
    route: Route,
    State(frontend): State<Arc<Frontend>>,
    request: Request<Body>,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let parameters: Vec<String> = match route.spec().keys.len() {
        0 => Vec::new(),
        1 => match Path::<String>::from_request_parts(&mut parts, &()).await {
            Ok(Path(value)) => vec![value],
            Err(error) => return error.into_response(),
        },
        2 => match Path::<(String, String)>::from_request_parts(&mut parts, &()).await {
            Ok(Path((first, second))) => vec![first, second],
            Err(error) => return error.into_response(),
        },
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    // Path extraction precedes body extraction exactly as in the owning router.
    // GET handlers never inspect headers or poll the body.
    let (headers, extracted): (
        HeaderMap,
        Option<Result<Bytes, axum::extract::rejection::BytesRejection>>,
    ) = if route.method() == Method::GET {
        drop(body);
        (HeaderMap::new(), None)
    } else {
        let mut request: Request<Body> = Request::from_parts(parts, body);
        DefaultBodyLimit::max(route.spec().request).apply(&mut request);
        let headers: HeaderMap = request.headers().clone();
        let extracted: Result<Bytes, axum::extract::rejection::BytesRejection> =
            Bytes::from_request(request, &()).await;
        (headers, Some(extracted))
    };
    if route.method() == Method::POST
        && let Err(response) = crate::fastvote::custody_content_guard(&headers)
    {
        return response;
    }
    let mut selectors: Vec<[u8; 32]> = Vec::with_capacity(route.spec().keys.len());
    for parameter in &parameters {
        let Some(value) = crate::decode_hex64_selector(parameter) else {
            return crate::error_response(StatusCode::BAD_REQUEST, route.selector_error());
        };
        selectors.push(value);
    }
    if route == Route::Receipt && selectors.first() == Some(&[0; 32]) {
        return crate::error_response(StatusCode::BAD_REQUEST, route.selector_error());
    }
    if route == Route::Publication
        && abi::package_types::PackageOrigin::unverified(
            frontend.context.chain_id().clone(),
            selectors[0],
            selectors[1],
        )
        .is_err()
    {
        return crate::error_response(StatusCode::BAD_REQUEST, route.selector_error());
    }
    let body: Bytes = match extracted {
        None => Bytes::new(),
        Some(extracted) => match crate::fastvote::custody_body(extracted) {
            Ok(value) => value,
            Err(response) => return response,
        },
    };
    if route == Route::FrontierAdvance && !body.is_empty() {
        return crate::error_response(StatusCode::BAD_REQUEST, "frontier-advance-body-not-empty");
    }
    let (Ok(content_type), Ok(encoding)) = (
        header_values(&headers, header::CONTENT_TYPE),
        header_values(&headers, header::CONTENT_ENCODING),
    ) else {
        return crate::error_response(StatusCode::BAD_REQUEST, "certified-custody-header-bound");
    };
    forward(
        frontend,
        Input {
            route,
            selectors,
            content_type,
            encoding,
            body: body.to_vec(),
        },
    )
    .await
}
/// Exact current certified route/method table. Axum owns selector extraction,
/// automatic GET/HEAD behavior and method refusals, just as in the direct router.
pub fn frontend_router(frontend: Arc<Frontend>) -> Application {
    let mut router: Router<Arc<Frontend>> = Router::new();
    for route in Route::ALL {
        let spec: Spec = route.spec();
        let handler =
            move |state: State<Arc<Frontend>>, request: Request<Body>| proxy(route, state, request);
        router = router.route(
            spec.path,
            if route == Route::Live {
                get(crate::liveness)
            } else if route.method() == Method::GET {
                get(handler)
            } else {
                post(handler).layer(DefaultBodyLimit::max(spec.request))
            },
        );
    }
    router.with_state(frontend)
}
mod verification;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::assert_confirmed_round_trip;
