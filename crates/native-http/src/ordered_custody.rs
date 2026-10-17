//! DR-0264 deployment-only original ordered IPC. No signing-frame endpoint.
//! The worker dispatches the existing router and returns whole confirmed results.
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, FromRequest, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use consensus::{ConsensusMessage, Ed25519ConsensusVerifier, UnsupportedSignatureSchemeResponse};
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedEventOutput, OrderedProposal, OrderedStatus,
    decode_ordered_event_output, decode_ordered_proposal, decode_ordered_status,
};
use node_wire::{ordered_economics::*, ordered_history::*};
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

/// The existing router type, exposed without a new operator HTTP dependency.
pub type Application = Router;
/// Fixed local deployment identity, not a live warrant or caller assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    validator: ValidatorId,
    domain: AtomicityDomainId,
    genesis: [u8; 32],
}
impl Identity {
    /// Construct only from the role's locally verified startup pins.
    pub fn new(validator: ValidatorId, domain: AtomicityDomainId, genesis: [u8; 32]) -> Self {
        Self {
            validator,
            domain,
            genesis,
        }
    }
    fn bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(96);
        bytes.extend_from_slice(self.validator.as_bytes());
        bytes.extend_from_slice(self.domain.as_bytes());
        bytes.extend_from_slice(&self.genesis);
        bytes
    }
}
// Private deployment framing only: version 2 retains all header occurrences.
const VERSION: u8 = 2;
const MAX_HEADER: usize = 256;
const MAX_PARAMETER: usize = 64;
const MAX_HEADER_VALUES: usize = 64;
const MAX_REQUEST: usize =
    MAX_ORDERED_PROPOSAL_BYTES + 2 * (1 + MAX_HEADER_VALUES * (4 + MAX_HEADER)) + 1024;
const MAX_RESPONSE: usize = MAX_ORDERED_EVENT_OUTPUT_BYTES + 1024;

fn invalid() -> io::Error {
    io::Error::other("ordered custody refused")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Propose,
    Proposal,
    Certificate,
    Observe,
    Status,
    Outcome,
    Tick,
    Summary,
    Height,
    Component,
}
impl Route {
    fn code(self) -> u8 {
        match self {
            Self::Propose => 1,
            Self::Proposal => 2,
            Self::Certificate => 3,
            Self::Observe => 4,
            Self::Status => 5,
            Self::Outcome => 6,
            Self::Tick => 7,
            Self::Summary => 8,
            Self::Height => 9,
            Self::Component => 10,
        }
    }
    fn from_code(code: u8) -> io::Result<Self> {
        Ok(match code {
            1 => Self::Propose,
            2 => Self::Proposal,
            3 => Self::Certificate,
            4 => Self::Observe,
            5 => Self::Status,
            6 => Self::Outcome,
            7 => Self::Tick,
            8 => Self::Summary,
            9 => Self::Height,
            10 => Self::Component,
            _ => return Err(invalid()),
        })
    }
    fn method(self) -> Method {
        match self {
            Self::Status | Self::Outcome | Self::Summary => Method::GET,
            _ => Method::POST,
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Propose => MAX_ORDERED_PROPOSE_REQUEST_BYTES,
            Self::Proposal | Self::Observe => MAX_ORDERED_PROPOSAL_BYTES,
            Self::Certificate => MAX_ORDERED_CERTIFICATE_BYTES,
            Self::Height => MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES,
            Self::Component => MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES,
            Self::Tick | Self::Status | Self::Outcome | Self::Summary => 1,
        }
    }
    fn path(self, parameter: &str) -> io::Result<String> {
        if self == Self::Outcome {
            if parameter.len() != 64 || !parameter.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
            {
                return Err(invalid());
            }
            return Ok(format!(
                "{ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX}{parameter}"
            ));
        }
        if !parameter.is_empty() {
            return Err(invalid());
        }
        Ok(match self {
            Self::Propose => ORDERED_ECONOMICS_PROPOSE_PATH,
            Self::Proposal => ORDERED_ECONOMICS_PROPOSAL_PATH,
            Self::Certificate => ORDERED_ECONOMICS_CERTIFICATE_PATH,
            Self::Observe => ORDERED_ECONOMICS_OBSERVE_PATH,
            Self::Status => ORDERED_ECONOMICS_STATUS_PATH,
            Self::Tick => ORDERED_ECONOMICS_TICK_PATH,
            Self::Summary => ORDERED_HISTORY_SUMMARY_PATH,
            Self::Height => ORDERED_HISTORY_HEIGHT_PATH,
            Self::Component => ORDERED_HISTORY_COMPONENT_PATH,
            Self::Outcome => return Err(invalid()),
        }
        .into())
    }
    fn select(method: &Method, path: &str) -> io::Result<(Self, String)> {
        for code in 1..=10 {
            let route: Self = Self::from_code(code)?;
            if route == Self::Outcome {
                if let Some(parameter) = path.strip_prefix(ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX) {
                    route.path(parameter)?;
                    if *method == route.method() {
                        return Ok((route, parameter.into()));
                    }
                }
            } else if path == route.path("")? && *method == route.method() {
                return Ok((route, String::new()));
            }
        }
        Err(invalid())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    route: Route,
    parameter: String,
    content_type: Vec<Vec<u8>>,
    encoding: Vec<Vec<u8>>,
    body: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
struct Output {
    status: u16,
    content_type: Vec<u8>,
    body: Vec<u8>,
}

fn put(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> io::Result<()> {
    if bytes.len() > cap {
        return Err(invalid());
    }
    let length: u32 = u32::try_from(bytes.len()).map_err(|_| invalid())?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn put_headers(out: &mut Vec<u8>, values: &[Vec<u8>]) -> io::Result<()> {
    if values.len() > MAX_HEADER_VALUES {
        return Err(invalid());
    }
    out.push(u8::try_from(values.len()).map_err(|_| invalid())?);
    for bytes in values {
        put(out, bytes, MAX_HEADER)?;
    }
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> io::Result<&'a [u8]> {
        let end: usize = self.offset.checked_add(size).ok_or_else(invalid)?;
        let bytes: &'a [u8] = self.bytes.get(self.offset..end).ok_or_else(invalid)?;
        self.offset = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn field(&mut self, cap: usize) -> io::Result<&'a [u8]> {
        let size: u32 = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| invalid())?);
        let size: usize = usize::try_from(size).map_err(|_| invalid())?;
        if size > cap {
            return Err(invalid());
        }
        self.take(size)
    }
    fn finish(self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    fn headers(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let count: usize = usize::from(self.byte()?);
        if count > MAX_HEADER_VALUES {
            return Err(invalid());
        }
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.field(MAX_HEADER)?.to_vec());
        }
        Ok(values)
    }
}
impl Input {
    fn encode(&self) -> io::Result<Vec<u8>> {
        self.route.path(&self.parameter)?;
        let mut bytes: Vec<u8> = vec![VERSION, self.route.code()];
        put(&mut bytes, self.parameter.as_bytes(), MAX_PARAMETER)?;
        put_headers(&mut bytes, &self.content_type)?;
        put_headers(&mut bytes, &self.encoding)?;
        put(&mut bytes, &self.body, self.route.limit())?;
        if bytes.len() > MAX_REQUEST {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_REQUEST {
            return Err(invalid());
        }
        let mut input: Cursor<'_> = Cursor { bytes, offset: 0 };
        if input.byte()? != VERSION {
            return Err(invalid());
        }
        let route: Route = Route::from_code(input.byte()?)?;
        let parameter: String = std::str::from_utf8(input.field(MAX_PARAMETER)?)
            .map_err(|_| invalid())?
            .into();
        route.path(&parameter)?;
        let content_type: Vec<Vec<u8>> = input.headers()?;
        let encoding: Vec<Vec<u8>> = input.headers()?;
        let body: Vec<u8> = input.field(route.limit())?.to_vec();
        input.finish()?;
        Ok(Self {
            route,
            parameter,
            content_type,
            encoding,
            body,
        })
    }
}
impl Output {
    fn encode(&self) -> io::Result<Vec<u8>> {
        StatusCode::from_u16(self.status).map_err(|_| invalid())?;
        let mut bytes: Vec<u8> = vec![VERSION];
        bytes.extend_from_slice(&self.status.to_be_bytes());
        put(&mut bytes, &self.content_type, MAX_HEADER)?;
        put(&mut bytes, &self.body, MAX_ORDERED_EVENT_OUTPUT_BYTES)?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_RESPONSE {
            return Err(invalid());
        }
        let mut input: Cursor<'_> = Cursor { bytes, offset: 0 };
        if input.byte()? != VERSION {
            return Err(invalid());
        }
        let status: u16 = u16::from_be_bytes(input.take(2)?.try_into().map_err(|_| invalid())?);
        StatusCode::from_u16(status).map_err(|_| invalid())?;
        let content_type: Vec<u8> = input.field(MAX_HEADER)?.to_vec();
        let body: Vec<u8> = input.field(MAX_ORDERED_EVENT_OUTPUT_BYTES)?.to_vec();
        input.finish()?;
        Ok(Self {
            status,
            content_type,
            body,
        })
    }
    fn response(self) -> io::Result<Response> {
        let mut response: Response = Response::new(Body::from(self.body));
        *response.status_mut() = StatusCode::from_u16(self.status).map_err(|_| invalid())?;
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if !self.content_type.is_empty() {
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_bytes(&self.content_type).map_err(|_| invalid())?,
            );
        }
        Ok(response)
    }
}

async fn read_frame(stream: &mut UnixStream, cap: usize) -> io::Result<Vec<u8>> {
    let size: u32 = stream.read_u32().await?;
    let size: usize = usize::try_from(size).map_err(|_| invalid())?;
    if size == 0 || size > cap {
        return Err(invalid());
    }
    let mut bytes: Vec<u8> = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    let mut trailing: [u8; 1] = [0];
    if stream.read(&mut trailing).await? != 0 {
        return Err(invalid());
    }
    Ok(bytes)
}
async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| invalid())?)
        .await?;
    stream.write_all(bytes).await?;
    stream.shutdown().await
}
fn authenticate(stream: &UnixStream, expected: u32) -> io::Result<()> {
    if stream.peer_cred()?.uid() != expected {
        return Err(invalid());
    }
    Ok(())
}

async fn execute(app: Application, input: Input) -> io::Result<Output> {
    let mut request: Request<Body> = Request::builder()
        .method(input.route.method())
        .uri(input.route.path(&input.parameter)?)
        .body(Body::from(input.body))
        .map_err(|_| invalid())?;
    for (name, bytes) in [
        (header::CONTENT_TYPE, input.content_type),
        (header::CONTENT_ENCODING, input.encoding),
    ] {
        for bytes in bytes {
            request.headers_mut().append(
                name.clone(),
                HeaderValue::from_bytes(&bytes).map_err(|_| invalid())?,
            );
        }
    }
    let response: Response = app.oneshot(request).await.map_err(|_| invalid())?;
    let status: u16 = response.status().as_u16();
    let content_type: Vec<u8> = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map_or_else(Vec::new, |value: &HeaderValue| value.as_bytes().to_vec());
    if content_type.len() > MAX_HEADER {
        return Err(invalid());
    }
    let body: Bytes = to_bytes(response.into_body(), MAX_ORDERED_EVENT_OUTPUT_BYTES)
        .await
        .map_err(|_| invalid())?;
    Ok(Output {
        status,
        content_type,
        body: body.to_vec(),
    })
}

/// One authenticated local owner; all accepted work retains the existing router's
/// executor. Exhausting a limit closes admission, then waits for shutdown.
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
        let (mut stream, _) = tokio::select! { biased; ()=&mut shutdown=>return Ok(()), accepted=active.accept()=>accepted? };
        connections = connections.checked_add(1).ok_or_else(invalid)?;
        // Authenticate before reading even the outer length, not only decoding.
        if authenticate(&stream, frontend_uid).is_err() {
            continue;
        }
        requests = requests.checked_add(1).ok_or_else(invalid)?;
        let deadline: Instant = end.min(
            Instant::now()
                .checked_add(request_timeout)
                .ok_or_else(invalid)?,
        );
        let work = async {
            let bytes: Vec<u8> = read_frame(&mut stream, MAX_REQUEST).await?;
            let input: Input = Input::decode(&bytes)?;
            let output: Output = execute(app.clone(), input).await?;
            let mut bytes: Vec<u8> = identity.bytes();
            bytes.extend_from_slice(&output.encode()?);
            write_frame(&mut stream, &bytes).await
        };
        // Cancelling delivery never cancels a started blocking operation. Its
        // existing executor is separately closed/drained by the process owner.
        tokio::select! { biased; ()=&mut shutdown=>return Ok(()), _result=timeout_at(deadline,work)=>{} }
    }
}

/// Fixed frontend trust/configuration. It owns no store or validator key.
pub struct Frontend {
    socket: PathBuf,
    worker_uid: u32,
    validator: ValidatorId,
    identity: Identity,
    policy: OrderedEconomicsPolicy,
    timeout: Duration,
    end: Instant,
    remaining: AtomicU64,
    executor: crate::NativeBlockingExecutor,
}
impl Frontend {
    /// All values are locally fixed before listening; request input selects none.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket: PathBuf,
        worker_uid: u32,
        validator: ValidatorId,
        policy: OrderedEconomicsPolicy,
        timeout: Duration,
        end: Instant,
        max_requests: u64,
        executor: crate::NativeBlockingExecutor,
    ) -> Self {
        let identity: Identity =
            Identity::new(validator, policy.domain(), policy.genesis_digest().bytes());
        Self {
            socket,
            worker_uid,
            validator,
            policy,
            timeout,
            end,
            remaining: AtomicU64::new(max_requests),
            executor,
            identity,
        }
    }
    #[cfg(test)]
    pub(crate) fn remaining_requests(&self) -> u64 {
        self.remaining.load(Ordering::Relaxed)
    }
    async fn exchange(&self, input: Input) -> io::Result<Output> {
        if self.executor.stop_cancellation().is_cancelled() || Instant::now() >= self.end {
            return Err(invalid());
        }
        self.remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left: u64| {
                left.checked_sub(1)
            })
            .map_err(|_| invalid())?;
        let end: Instant = self.end.min(
            Instant::now()
                .checked_add(self.timeout)
                .ok_or_else(invalid)?,
        );
        timeout_at(end, async {
            let mut stream: UnixStream = UnixStream::connect(&self.socket).await?;
            authenticate(&stream, self.worker_uid)?;
            write_frame(&mut stream, &input.encode()?).await?;
            let bytes: Vec<u8> = read_frame(&mut stream, MAX_RESPONSE).await?;
            if bytes.get(..96) != Some(self.identity.bytes().as_slice()) {
                return Err(invalid());
            }
            let output: Output = Output::decode(bytes.get(96..).ok_or_else(invalid)?)?;
            Ok(output)
        })
        .await
        .map_err(|_| invalid())?
    }
    fn verify(&self, route: Route, output: &Output) -> io::Result<()> {
        if output.status != 200 {
            if (200..300).contains(&output.status)
                && !(route == Route::Outcome
                    && output.status == 204
                    && output.content_type.is_empty()
                    && output.body.is_empty())
            {
                return Err(invalid());
            }
            return Ok(());
        }
        let media: &[u8] = &output.content_type;
        let valid_media: bool = match route {
            Route::Propose => {
                media == ORDERED_PROPOSAL_MEDIA_TYPE.as_bytes()
                    || media == ORDERED_EVENT_OUTPUT_MEDIA_TYPE.as_bytes()
            }
            Route::Proposal | Route::Certificate | Route::Observe | Route::Tick => {
                media == ORDERED_EVENT_OUTPUT_MEDIA_TYPE.as_bytes()
            }
            Route::Status => media == ORDERED_STATUS_MEDIA_TYPE.as_bytes(),
            Route::Outcome => media == ORDERED_OUTCOME_MEDIA_TYPE.as_bytes(),
            Route::Summary | Route::Height | Route::Component => {
                media == node_wire::NODE_RESULT_MEDIA_TYPE.as_bytes()
            }
        };
        if !valid_media {
            return Err(invalid());
        }
        let verifier: Ed25519ConsensusVerifier =
            Ed25519ConsensusVerifier::new(UnsupportedSignatureSchemeResponse::InvalidSignature);
        if output.content_type == ORDERED_PROPOSAL_MEDIA_TYPE.as_bytes() {
            let proposal: OrderedProposal =
                decode_ordered_proposal(&output.body).map_err(|_| invalid())?;
            if proposal.proposal.leader != self.validator {
                return Err(invalid());
            }
            self.policy
                .engine()
                .verify_proposal(&proposal.proposal, &verifier)
                .map_err(|_| invalid())?;
        } else if output.content_type == ORDERED_EVENT_OUTPUT_MEDIA_TYPE.as_bytes() {
            let event: OrderedEventOutput =
                decode_ordered_event_output(&output.body).map_err(|_| invalid())?;
            for message in &event.messages {
                match message {
                    ConsensusMessage::Proposal(proposal) => {
                        if proposal.leader != self.validator {
                            return Err(invalid());
                        }
                        self.policy
                            .engine()
                            .verify_proposal(proposal, &verifier)
                            .map_err(|_| invalid())?;
                    }
                    ConsensusMessage::Vote(vote) => {
                        if vote.validator != self.validator {
                            return Err(invalid());
                        }
                        self.policy
                            .engine()
                            .verify_vote(vote, &verifier)
                            .map_err(|_| invalid())?;
                    }
                    ConsensusMessage::Certificate(certificate) => self
                        .policy
                        .engine()
                        .verify_certificate(certificate, &verifier)
                        .map_err(|_| invalid())?,
                }
            }
        } else if output.content_type == ORDERED_STATUS_MEDIA_TYPE.as_bytes() {
            let status: OrderedStatus =
                decode_ordered_status(&output.body).map_err(|_| invalid())?;
            self.policy
                .engine()
                .verify_certificate(&status.high_qc, &verifier)
                .map_err(|_| invalid())?;
        }
        Ok(())
    }
    /// A peer-authenticated existing status read before HTTP readiness. It is
    /// not a cached live warrant for later requests.
    pub async fn preflight(self: &Arc<Self>) -> io::Result<()> {
        let output: Output = self
            .exchange(Input {
                route: Route::Status,
                parameter: String::new(),
                content_type: Vec::new(),
                encoding: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        if output.status != 200 || output.content_type != ORDERED_STATUS_MEDIA_TYPE.as_bytes() {
            return Err(invalid());
        }
        let frontend: Arc<Self> = Arc::clone(self);
        let response: Response =
            crate::publication::admitted(false, self.executor.clone(), move || {
                if frontend.verify(Route::Status, &output).is_ok() {
                    StatusCode::OK.into_response()
                } else {
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
            })
            .await;
        if response.status() != StatusCode::OK {
            return Err(invalid());
        }
        Ok(())
    }
}

async fn proxy(State(frontend): State<Arc<Frontend>>, request: Request<Body>) -> Response {
    // Existing handlers ignore query fields. The closed route, not a query,
    // determines which original operation the worker receives.
    if request.method() == Method::GET
        && let Some(selector) = request
            .uri()
            .path()
            .strip_prefix(ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX)
        && !selector.is_empty()
        && !selector.contains('/')
        && let Err(response) = crate::ordered_economics::decode_ordered_outcome_selector(selector)
    {
        return response;
    }
    let selected: io::Result<(Route, String)> =
        Route::select(request.method(), request.uri().path());
    let Ok((route, parameter)) = selected else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if matches!(route, Route::Status | Route::Outcome) {
        // State-only and State+Path original handlers never poll the request
        // body or inspect these headers. Drop them without touching either.
        drop(request);
        return forward(
            frontend,
            Input {
                route,
                parameter,
                content_type: Vec::new(),
                encoding: Vec::new(),
                body: Vec::new(),
            },
        )
        .await;
    }
    // The original handlers collect their bounded body before inspecting
    // duplicate encoding. Reuse their preflight and extraction order locally:
    // refused requests must never connect to the worker or consume its budget.
    let duplicates: bool = request
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .nth(1)
        .is_some();
    if duplicates {
        let mut request: Request<Body> = request;
        let limit: usize = match route {
            Route::Summary | Route::Height | Route::Component => route.limit(),
            _ => MAX_ORDERED_PROPOSAL_BYTES,
        };
        DefaultBodyLimit::max(limit).apply(&mut request);
        let headers: HeaderMap = request.headers().clone();
        let path: String = request.uri().path().into();
        let body = Bytes::from_request(request, &()).await;
        return crate::ordered_economics::duplicate_encoding_refusal(&headers, body, &path);
    }
    let headers: &HeaderMap = request.headers();
    let field = |name: axum::http::header::HeaderName| -> io::Result<Vec<Vec<u8>>> {
        let mut values: Vec<Vec<u8>> = Vec::new();
        for value in headers.get_all(name).iter() {
            if values.len() >= MAX_HEADER_VALUES || value.as_bytes().len() > MAX_HEADER {
                return Err(invalid());
            }
            values.push(value.as_bytes().to_vec());
        }
        Ok(values)
    };
    let (Ok(content_type), Ok(encoding)) =
        (field(header::CONTENT_TYPE), field(header::CONTENT_ENCODING))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let body: Bytes = match to_bytes(request.into_body(), route.limit()).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    forward(
        frontend,
        Input {
            route,
            parameter,
            content_type,
            encoding,
            body: body.to_vec(),
        },
    )
    .await
}

async fn forward(frontend: Arc<Frontend>, input: Input) -> Response {
    let route: Route = input.route;
    let exchange: io::Result<Output> = frontend.exchange(input).await;
    let failure = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
            "ordered-custody-unavailable",
        )
            .into_response()
    };
    let Ok(output) = exchange else {
        return failure();
    };
    crate::publication::admitted(false, frontend.executor.clone(), move || {
        match frontend
            .verify(route, &output)
            .and_then(|()| output.response())
        {
            Ok(response) => response,
            Err(_) => failure(),
        }
    })
    .await
}
/// Closed ordered-only forwarding router. No raw frame or generic path proxy.
pub fn frontend_router(frontend: Arc<Frontend>) -> Application {
    Router::new()
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_REQUEST))
        .with_state(frontend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{ConsensusEngine, ConsensusEvent, ConsensusSigner};
    use ed25519_zebra::{SigningKey, VerificationKey};
    use execution::publication::PublicationContext;
    use hashing::HashSuiteResolver;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
        SignatureSchemeId,
    };
    use validator_set::{ValidatorInfo, ValidatorSet};

    struct RealSigner {
        key: SigningKey,
    }
    impl ConsensusSigner for RealSigner {
        fn validator_id(&self) -> ValidatorId {
            ValidatorId::new(VerificationKey::from(&self.key).into())
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
            let bytes: [u8; 64] = self.key.sign(frame).into();
            Ok(bytes.to_vec())
        }
    }
    fn verification_fixture() -> (Frontend, RealSigner) {
        let signer: RealSigner = RealSigner {
            key: SigningKey::from([0x29; 32]),
        };
        let validator: ValidatorId = signer.validator_id();
        let chain: ChainId = ChainId::new("ordered-custody-test").unwrap();
        let version: ProtocolVersion = ProtocolVersion::new(3);
        let epoch: Epoch = Epoch::new(0);
        let domain: AtomicityDomainId = AtomicityDomainId::new([0x2a; 32]).unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain.clone(),
            version,
            vec![HashSuiteSchedule {
                activation_epoch: epoch,
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let set: ValidatorSet = ValidatorSet::new(
            epoch,
            vec![ValidatorInfo {
                id: validator,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: validator.as_bytes().to_vec(),
            }],
        )
        .unwrap();
        // Only frontend cryptographic controls use a historical policy here;
        // actual worker startup always requires the independently verified root.
        let genesis: [u8; 32] = [0x2b; 32];
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::historical(
            PublicationContext::new(chain, version, epoch).unwrap(),
            domain,
            Digest32::new(HashAlgorithmId::Sha2_256, genesis),
            set,
            resolver,
        )
        .unwrap();
        let executor: crate::NativeBlockingExecutor = crate::NativeBlockingExecutor::new(
            crate::NativeBlockingPolicy::new(std::num::NonZeroUsize::new(1).unwrap()),
        );
        let end: Instant = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
        (
            Frontend::new(
                PathBuf::from("/nonexistent/ordered-custody-test.sock"),
                0,
                validator,
                policy,
                Duration::from_secs(1),
                end,
                8,
                executor,
            ),
            signer,
        )
    }

    #[test]
    fn frontend_authenticates_real_original_proposal_and_vote_and_refuses_changes() {
        let (frontend, signer): (Frontend, RealSigner) = verification_fixture();
        let initial: consensus::ConsensusState = frontend.policy.engine().genesis_state(1);
        let proposal: consensus::ConsensusProposal = frontend
            .policy
            .engine()
            .propose(&initial, Vec::new(), &signer)
            .unwrap();
        let wrapped: OrderedProposal = OrderedProposal {
            proposal: proposal.clone(),
            candidate: None,
        };
        let mut output: Output = Output {
            status: 200,
            content_type: ORDERED_PROPOSAL_MEDIA_TYPE.as_bytes().to_vec(),
            body: node_core::ordered_economics::encode_ordered_proposal(&wrapped).unwrap(),
        };
        frontend.verify(Route::Propose, &output).unwrap();
        assert!(frontend.verify(Route::Status, &output).is_err());
        output.content_type = b"text/plain".to_vec();
        assert!(frontend.verify(Route::Propose, &output).is_err());
        let verifier: Ed25519ConsensusVerifier =
            Ed25519ConsensusVerifier::new(UnsupportedSignatureSchemeResponse::InvalidSignature);
        let generated: consensus::ConsensusOutput = frontend
            .policy
            .engine()
            .on_event(
                &initial,
                ConsensusEvent::Proposal(proposal),
                &signer,
                &verifier,
            )
            .unwrap();
        let event: OrderedEventOutput = OrderedEventOutput {
            messages: generated.outbound_messages,
            committed: Vec::new(),
        };
        assert!(
            event
                .messages
                .iter()
                .any(|message: &ConsensusMessage| matches!(message, ConsensusMessage::Vote(_)))
        );
        output.content_type = ORDERED_EVENT_OUTPUT_MEDIA_TYPE.as_bytes().to_vec();
        output.body = node_core::ordered_economics::encode_ordered_event_output(&event).unwrap();
        frontend.verify(Route::Proposal, &output).unwrap();
        let mut changed: OrderedEventOutput = event.clone();
        for message in &mut changed.messages {
            if let ConsensusMessage::Vote(vote) = message {
                vote.signature[0] ^= 1;
            }
        }
        output.body = node_core::ordered_economics::encode_ordered_event_output(&changed).unwrap();
        assert!(frontend.verify(Route::Proposal, &output).is_err());
        let (mut other, _signer): (Frontend, RealSigner) = verification_fixture();
        other.validator = ValidatorId::new([0x33; 32]);
        output.body = node_core::ordered_economics::encode_ordered_event_output(&event).unwrap();
        assert!(other.verify(Route::Proposal, &output).is_err());
    }

    #[tokio::test]
    async fn dispatch_preserves_empty_encoding_presence_exact_input_and_unavailable_output() {
        use axum::routing::post;
        let app: Application = Router::new().route(
            ORDERED_ECONOMICS_PROPOSE_PATH,
            post(|headers: HeaderMap, body: Bytes| async move {
                assert_eq!(body.as_ref(), b"unchanged-request");
                assert_eq!(
                    headers.get(header::CONTENT_ENCODING).unwrap().as_bytes(),
                    b""
                );
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::CONTENT_TYPE, "text/plain")],
                    "ordered-economics-unavailable",
                )
            }),
        );
        let input: Input = Input {
            route: Route::Propose,
            parameter: String::new(),
            content_type: vec![ORDERED_PROPOSE_REQUEST_MEDIA_TYPE.as_bytes().to_vec()],
            encoding: vec![Vec::new()],
            body: b"unchanged-request".to_vec(),
        };
        let bytes: Vec<u8> = input.encode().unwrap();
        let output: Output = execute(app, Input::decode(&bytes).unwrap()).await.unwrap();
        assert_eq!(output.status, 503);
        assert_eq!(output.body, b"ordered-economics-unavailable");
    }
    #[tokio::test]
    async fn dispatch_preserves_all_header_occurrences_in_order() {
        use axum::routing::post;
        let app: Application = Router::new().route(
            ORDERED_ECONOMICS_PROPOSE_PATH,
            post(|headers: HeaderMap| async move {
                let encoding: Vec<&[u8]> = headers
                    .get_all(header::CONTENT_ENCODING)
                    .iter()
                    .map(HeaderValue::as_bytes)
                    .collect();
                assert_eq!(
                    encoding,
                    vec![b"identity".as_slice(), b"gzip".as_slice(), b"".as_slice()]
                );
                let media: Vec<&[u8]> = headers
                    .get_all(header::CONTENT_TYPE)
                    .iter()
                    .map(HeaderValue::as_bytes)
                    .collect();
                assert_eq!(
                    media,
                    vec![
                        b"application/first".as_slice(),
                        b"application/second".as_slice()
                    ]
                );
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            }),
        );
        let input: Input = Input {
            route: Route::Propose,
            parameter: String::new(),
            content_type: vec![
                b"application/first".to_vec(),
                b"application/second".to_vec(),
            ],
            encoding: vec![b"identity".to_vec(), b"gzip".to_vec(), Vec::new()],
            body: Vec::new(),
        };
        let bytes: Vec<u8> = input.encode().unwrap();
        assert_eq!(
            execute(app, Input::decode(&bytes).unwrap())
                .await
                .unwrap()
                .status,
            415
        );
    }

    #[test]
    fn closed_ipc_roundtrip_rejects_wrong_version_kind_trailing_and_declared_lengths() {
        let input: Input = Input {
            route: Route::Propose,
            parameter: String::new(),
            content_type: vec![ORDERED_PROPOSE_REQUEST_MEDIA_TYPE.as_bytes().to_vec()],
            encoding: Vec::new(),
            body: vec![1, 2, 3],
        };
        let bytes: Vec<u8> = input.encode().unwrap();
        assert_eq!(Input::decode(&bytes).unwrap(), input);
        let mut repeated: Input = input.clone();
        repeated.content_type.push(b"application/second".to_vec());
        repeated.encoding = vec![b"identity".to_vec(), b"gzip".to_vec(), Vec::new()];
        assert_eq!(
            Input::decode(&repeated.encode().unwrap()).unwrap(),
            repeated
        );
        let mut old_version: Vec<u8> = bytes.clone();
        old_version[0] = 1;
        assert!(Input::decode(&old_version).is_err());
        repeated.encoding = vec![Vec::new(); MAX_HEADER_VALUES + 1];
        assert!(repeated.encode().is_err());
        repeated.encoding = vec![vec![0; MAX_HEADER + 1]];
        assert!(repeated.encode().is_err());
        let mut too_many: Vec<u8> = bytes.clone();
        // Empty parameter ends at offset 6; this is the first header count.
        too_many[6] = u8::try_from(MAX_HEADER_VALUES + 1).unwrap();
        assert!(Input::decode(&too_many).is_err());
        for offset in [0, 1] {
            let mut changed: Vec<u8> = bytes.clone();
            changed[offset] = 255;
            assert!(Input::decode(&changed).is_err());
        }
        let mut changed: Vec<u8> = bytes.clone();
        changed.push(0);
        assert!(Input::decode(&changed).is_err());
        let mut changed: Vec<u8> = bytes.clone();
        changed[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Input::decode(&changed).is_err());
        for end in 0..bytes.len() {
            assert!(Input::decode(&bytes[..end]).is_err());
        }
    }
    #[test]
    fn routes_cannot_select_fastvote_readiness_raw_frames_or_caller_paths() {
        for path in [
            "/v1/fastvote/prepare",
            "/sign",
            "/tmp/key",
            "/v1/conditional-readiness",
        ] {
            assert!(Route::select(&Method::POST, path).is_err());
        }
        assert!(Route::Status.path("/tmp/key").is_err());
        assert!(Route::Outcome.path(&"g".repeat(64)).is_err());
        assert!(Route::select(&Method::POST, ORDERED_ECONOMICS_STATUS_PATH).is_err());
        let input: Input = Input {
            route: Route::Status,
            parameter: String::new(),
            content_type: Vec::new(),
            encoding: Vec::new(),
            body: vec![0; 2],
        };
        assert!(input.encode().is_err());
    }
    #[test]
    fn response_roundtrip_is_exact_and_refuses_trailing_or_malformed_status() {
        let output: Output = Output {
            status: 503,
            content_type: b"text/plain".to_vec(),
            body: b"ordered-economics-unavailable".to_vec(),
        };
        let mut bytes: Vec<u8> = output.encode().unwrap();
        assert_eq!(Output::decode(&bytes).unwrap(), output);
        bytes.push(0);
        assert!(Output::decode(&bytes).is_err());
        bytes.pop();
        bytes[1..3].copy_from_slice(&0_u16.to_be_bytes());
        assert!(Output::decode(&bytes).is_err());
    }
    #[tokio::test]
    async fn wrong_peer_refuses_before_body_or_dispatch_and_outer_length_is_bounded() {
        let (mut first, mut second): (UnixStream, UnixStream) = UnixStream::pair().unwrap();
        let uid: u32 = first.peer_cred().unwrap().uid();
        assert!(authenticate(&first, uid.checked_add(1).unwrap()).is_err());
        second.write_u32(u32::MAX).await.unwrap();
        assert!(read_frame(&mut first, MAX_REQUEST).await.is_err());
    }

    struct SocketFixture {
        directory: PathBuf,
        path: PathBuf,
    }
    impl SocketFixture {
        fn new() -> Self {
            let nonce: u128 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory: PathBuf = std::env::temp_dir()
                .join(format!("ordered-custody-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let path: PathBuf = directory.join("local.sock");
            Self { directory, path }
        }
    }
    impl Drop for SocketFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[tokio::test]
    async fn frontend_wrong_peer_sends_no_request_bytes_and_makes_no_retry() {
        let fixture: SocketFixture = SocketFixture::new();
        let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
        let (mut frontend, _signer): (Frontend, RealSigner) = verification_fixture();
        frontend.socket = fixture.path.clone();
        let (first, _second): (UnixStream, UnixStream) = UnixStream::pair().unwrap();
        frontend.worker_uid = first.peer_cred().unwrap().uid().checked_add(1).unwrap();
        let frontend: Arc<Frontend> = Arc::new(frontend);
        let server = async {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut byte: [u8; 1] = [0];
            assert_eq!(
                peer.read(&mut byte).await.unwrap(),
                0,
                "client authenticates before outer length"
            );
        };
        let client = async {
            assert!(frontend.preflight().await.is_err());
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
        assert_eq!(frontend.remaining.load(Ordering::Relaxed), 7);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn worker_authenticates_before_body_and_deadline_closes_admission() {
        let fixture: SocketFixture = SocketFixture::new();
        let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
        let (first, _second): (UnixStream, UnixStream) = UnixStream::pair().unwrap();
        let wrong_uid: u32 = first.peer_cred().unwrap().uid().checked_add(1).unwrap();
        let calls: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let called: Arc<AtomicU64> = Arc::clone(&calls);
        let app: Application = Router::new().fallback(move || {
            let called: Arc<AtomicU64> = Arc::clone(&called);
            async move {
                called.fetch_add(1, Ordering::Relaxed);
                StatusCode::OK
            }
        });
        let end: Instant = Instant::now()
            .checked_add(Duration::from_millis(50))
            .unwrap();
        let identity: Identity = Identity::new(
            ValidatorId::new([1; 32]),
            AtomicityDomainId::new([2; 32]).unwrap(),
            [3; 32],
        );
        let server = serve_worker(
            listener,
            app,
            identity,
            wrong_uid,
            1,
            1,
            Duration::from_millis(20),
            end,
            tokio::time::sleep_until(end),
        );
        let client = async {
            let mut stream: UnixStream = UnixStream::connect(&fixture.path).await.unwrap();
            // No length/body is sent: rejection cannot depend on decoding it.
            let mut byte: [u8; 1] = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            let (served, ()) = tokio::join!(server, client);
            served.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
