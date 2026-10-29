//! Private local acceptance transport: terminate fixture TLS and forward exact
//! HTTP bytes to one real compiled loopback host. It produces no protocol result
//! and holds no validator signing authority. Its keys authenticate fixture TLS.
//! Only an explicitly armed test mode can withhold one genuine successful apply
//! acknowledgement after reading it completely and before any application write.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::{Acceptor, ClientHello, NoServerSessionStorage},
};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 512;
const MAX_CLIENT_HELLO_BYTES: u64 = 64 * 1024;
const MAX_LIFETIME: Duration = Duration::from_secs(10 * 60);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL: Duration = Duration::from_millis(5);

// Fixture identity only; never a protocol ID or a source of authority.
static NEXT_RELAY: AtomicU64 = AtomicU64::new(1);

pub fn fixture_server_name() -> String {
    let instance: u64 = NEXT_RELAY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value: u64| {
            value.checked_add(1)
        })
        .expect("HTTPS fixture identity exhausted");
    format!(
        "validator-{}-{instance}.sunrise-edge.invalid",
        std::process::id()
    )
}

/// Retained disposable issuer, independent of validator signing authority.
pub struct FixtureCa {
    pub der: Vec<u8>,
    pub subject: String,
    issuer: Issuer<'static, KeyPair>,
}

impl FixtureCa {
    pub fn new(subject: &str) -> Self {
        let mut params: CertificateParams =
            CertificateParams::new(Vec::<String>::new()).expect("fixture CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, subject);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key: KeyPair = KeyPair::generate().expect("fixture CA key");
        let certificate: Certificate = params.self_signed(&key).expect("fixture CA certificate");
        Self {
            der: certificate.der().to_vec(),
            subject: subject.to_owned(),
            issuer: Issuer::new(params, key),
        }
    }

    pub fn issue_leaf(&self, server_name: &str) -> FixtureLeaf {
        let mut params: CertificateParams = CertificateParams::new(vec![server_name.to_owned()])
            .expect("fixture DNS leaf parameters");
        params
            .distinguished_name
            .push(DnType::CommonName, server_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key: KeyPair = KeyPair::generate().expect("fixture leaf key");
        let certificate: Certificate = params
            .signed_by(&key, &self.issuer)
            .expect("fixture CA-signed DNS leaf");
        let key_pkcs8_der: Vec<u8> = key.serialize_der();
        let private_key: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(key_pkcs8_der.clone()).into();
        let mut config: ServerConfig = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .expect("fixture TLS configuration");
        // No tickets or cache can substitute a prior generation's handshake.
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        FixtureLeaf {
            ca_der: self.der.clone(),
            server_name: server_name.to_owned(),
            der: certificate.der().to_vec(),
            public_key_der: key.subject_public_key_info(),
            key_pkcs8_der,
            server_config: Arc::new(config),
        }
    }
}

pub struct FixtureLeaf {
    pub ca_der: Vec<u8>,
    pub server_name: String,
    pub der: Vec<u8>,
    /// DER SubjectPublicKeyInfo, independent of certificate metadata/DER.
    pub public_key_der: Vec<u8>,
    /// Disposable test key written to the actual Native TLS loader's input.
    pub key_pkcs8_der: Vec<u8>,
    server_config: Arc<ServerConfig>,
}

#[derive(Default)]
pub struct RelayCounters {
    pub accepted: AtomicUsize,
    pub handshakes: AtomicUsize,
    pub requests: AtomicUsize,
    /// Conservative count of POST forwarding attempts, including failed writes.
    pub posts: AtomicUsize,
}

/// Bounded original bytes observed after a genuine successful upstream apply.
/// No response is constructed by the relay and no TLS application bytes escape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LostApplyAcknowledgement {
    pub request: Vec<u8>,
    pub request_header_length: usize,
    pub response: Vec<u8>,
    pub response_header_length: usize,
    pub upstream_status: u16,
    pub handshake_completed: bool,
    pub downstream_application_bytes: usize,
}

struct ApplyAckLoss {
    target: [u8; 32],
    observed: Option<LostApplyAcknowledgement>,
}

/// One bounded CA/DNS endpoint in front of one actual local host. Explicit
/// stopped rotation joins successfully and retains the exact bound listener.
pub struct HttpsRelay {
    pub addr: SocketAddr,
    pub ca_der: Vec<u8>,
    pub server_name: String,
    pub counters: Arc<RelayCounters>,
    apply_ack_loss: Option<Arc<Mutex<ApplyAckLoss>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<TcpListener>>,
}

impl HttpsRelay {
    pub fn bind(backend: SocketAddr, leaf: &FixtureLeaf) -> Self {
        let listener: TcpListener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind private HTTPS fixture listener");
        Self::start(listener, backend, leaf)
    }

    pub fn start(listener: TcpListener, backend: SocketAddr, leaf: &FixtureLeaf) -> Self {
        Self::start_mode(listener, backend, leaf, None)
    }

    /// Explicit test-only one-shot: withhold the first complete successful
    /// published-apply acknowledgement for this exact request on this peer.
    pub fn start_losing_apply_ack_once(
        listener: TcpListener,
        backend: SocketAddr,
        leaf: &FixtureLeaf,
        target: [u8; 32],
    ) -> Self {
        node_core::RequestId::new(target).expect("ACK-loss target request ID");
        Self::start_mode(
            listener,
            backend,
            leaf,
            Some(Arc::new(Mutex::new(ApplyAckLoss {
                target,
                observed: None,
            }))),
        )
    }

    pub fn apply_ack_loss_is_armed(&self) -> bool {
        self.apply_ack_loss.is_some()
    }

    pub fn lost_apply_acknowledgement(&self) -> Option<LostApplyAcknowledgement> {
        self.apply_ack_loss
            .as_ref()
            .expect("ACK loss requires explicit arming")
            .lock()
            .expect("ACK-loss observation mutex")
            .observed
            .clone()
    }

    fn start_mode(
        listener: TcpListener,
        backend: SocketAddr,
        leaf: &FixtureLeaf,
        apply_ack_loss: Option<Arc<Mutex<ApplyAckLoss>>>,
    ) -> Self {
        assert!(
            backend.ip().is_loopback(),
            "HTTPS fixture backend must be loopback"
        );
        listener
            .set_nonblocking(true)
            .expect("nonblocking HTTPS fixture listener");
        let addr: SocketAddr = listener.local_addr().expect("HTTPS fixture address");
        assert!(
            addr.ip().is_loopback(),
            "HTTPS fixture listener must be loopback"
        );
        let server_config: Arc<ServerConfig> = Arc::clone(&leaf.server_config);
        let stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let counters: Arc<RelayCounters> = Arc::new(RelayCounters::default());
        let worker_stop: Arc<AtomicBool> = Arc::clone(&stop);
        let worker_counters: Arc<RelayCounters> = Arc::clone(&counters);
        let worker_ack_loss: Option<Arc<Mutex<ApplyAckLoss>>> = apply_ack_loss.clone();
        let deadline: Instant = Instant::now()
            .checked_add(MAX_LIFETIME)
            .expect("HTTPS fixture lifetime overflow");
        let worker: JoinHandle<TcpListener> = thread::spawn(move || {
            let mut accepted: usize = 0;
            while accepted < MAX_CONNECTIONS
                && !worker_stop.load(Ordering::Acquire)
                && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((socket, _peer)) => {
                        accepted += 1;
                        worker_counters.accepted.fetch_add(1, Ordering::SeqCst);
                        let Some(connection_deadline) =
                            Instant::now().checked_add(CONNECTION_TIMEOUT)
                        else {
                            break;
                        };
                        // Wrong CA/name alerts, aborted clients and bounded I/O
                        // errors refuse only this connection, without a fake reply.
                        let _ignored: io::Result<()> = forward_connection(
                            socket,
                            backend,
                            Arc::clone(&server_config),
                            &worker_counters,
                            Arc::clone(&worker_stop),
                            connection_deadline.min(deadline),
                            worker_ack_loss.as_deref(),
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("HTTPS fixture accept failed: {error}"),
                }
            }
            listener
        });
        Self {
            addr,
            ca_der: leaf.ca_der.clone(),
            server_name: leaf.server_name.clone(),
            counters,
            apply_ack_loss,
            stop,
            worker: Some(worker),
        }
    }

    pub fn stop(mut self) -> TcpListener {
        self.stop.store(true, Ordering::Release);
        let listener: TcpListener = self
            .worker
            .take()
            .expect("owned HTTPS worker")
            .join()
            .expect("HTTPS fixture worker must finish successfully");
        assert_eq!(
            listener.local_addr().unwrap(),
            self.addr,
            "retained HTTPS listener"
        );
        listener
    }
}

impl Drop for HttpsRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Accepted socket operations expire within SOCKET_TIMEOUT, and
            // connect and nonblocking accept have their own tighter bounds.
            // Cleanup never panics during a failed test's unwind.
            let _ignored: thread::Result<TcpListener> = worker.join();
        }
    }
}

/// Full authenticated peer observation, never an insecure verifier or a
/// configured-leaf echo. Its fresh client explicitly disables all resumption.
pub fn authenticated_leaf(addr: SocketAddr, server_name: &str, ca_der: &[u8]) -> Vec<u8> {
    assert!(addr.ip().is_loopback());
    let mut roots: RootCertStore = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("observer CA root");
    let mut config: ClientConfig = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    let name: ServerName<'static> = ServerName::try_from(server_name.to_owned()).unwrap();
    let mut connection: ClientConnection = ClientConnection::new(Arc::new(config), name).unwrap();
    let deadline: Instant = Instant::now().checked_add(CONNECTION_TIMEOUT).unwrap();
    let socket: TcpStream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).unwrap();
    let mut bounded: DeadlineSocket = DeadlineSocket {
        socket,
        deadline,
        stop: Arc::new(AtomicBool::new(false)),
    };
    while connection.is_handshaking() {
        connection
            .complete_io(&mut bounded)
            .expect("authenticated observer handshake");
    }
    let der: Vec<u8> = connection
        .peer_certificates()
        .expect("received peer certificates")
        .first()
        .expect("received peer leaf")
        .to_vec();
    connection.send_close_notify();
    while connection.wants_write() {
        connection
            .write_tls(&mut bounded)
            .expect("observer close-notify");
    }
    der
}

/// One finite actual ClientHello close. It owns no backend address, identity,
/// response or signing key, and cannot manufacture an HTTP/TLS error result.
pub struct PeerClose {
    pub counters: Arc<RelayCounters>,
    pub client_hellos: Arc<AtomicUsize>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<TcpListener>>,
}

impl PeerClose {
    pub fn start(listener: TcpListener, server_name: &str) -> Self {
        listener.set_nonblocking(true).unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        let name: String = server_name.to_owned();
        let counters: Arc<RelayCounters> = Arc::new(RelayCounters::default());
        let client_hellos: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let worker_counts: Arc<RelayCounters> = Arc::clone(&counters);
        let worker_hellos: Arc<AtomicUsize> = Arc::clone(&client_hellos);
        let worker_stop: Arc<AtomicBool> = Arc::clone(&stop);
        let deadline: Instant = Instant::now().checked_add(CONNECTION_TIMEOUT).unwrap();
        let worker: JoinHandle<TcpListener> = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((socket, _peer)) => {
                        worker_counts.accepted.fetch_add(1, Ordering::SeqCst);
                        socket.set_nonblocking(false).unwrap();
                        let bounded: DeadlineSocket = DeadlineSocket {
                            socket,
                            deadline,
                            stop: Arc::clone(&worker_stop),
                        };
                        let mut limited: io::Take<DeadlineSocket> =
                            bounded.take(MAX_CLIENT_HELLO_BYTES);
                        let mut acceptor: Acceptor = Acceptor::default();
                        loop {
                            let read: usize = acceptor
                                .read_tls(&mut limited)
                                .expect("read actual ClientHello");
                            assert_ne!(read, 0, "ClientHello missing, truncated or exceeds bound");
                            if let Some(accepted) = acceptor
                                .accept()
                                .unwrap_or_else(|_| panic!("parse actual ClientHello"))
                            {
                                let hello: ClientHello<'_> = accepted.client_hello();
                                assert_eq!(hello.server_name(), Some(name.as_str()));
                                worker_hellos.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                        }
                        // Drop the socket before starting any TLS handshake or HTTP.
                        return listener;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("accept actual peer-close connection: {error}"),
                }
            }
            listener
        });
        Self {
            counters,
            client_hellos,
            addr,
            stop,
            worker: Some(worker),
        }
    }

    pub fn finish(mut self) -> TcpListener {
        let listener: TcpListener = self
            .worker
            .take()
            .expect("owned peer-close worker")
            .join()
            .expect("peer-close worker must finish successfully");
        assert_eq!(self.counters.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(self.client_hellos.load(Ordering::SeqCst), 1);
        assert_eq!(self.counters.handshakes.load(Ordering::SeqCst), 0);
        assert_eq!(self.counters.requests.load(Ordering::SeqCst), 0);
        assert_eq!(self.counters.posts.load(Ordering::SeqCst), 0);
        assert_eq!(listener.local_addr().unwrap(), self.addr);
        listener
    }
}

impl Drop for PeerClose {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ignored: thread::Result<TcpListener> = worker.join();
        }
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Enforces an absolute deadline even inside rustls StreamOwned's handshake
/// and partial-record I/O loops. A trickle never renews the connection lifetime.
struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
    stop: Arc<AtomicBool>,
}

impl DeadlineSocket {
    fn remaining(&self, maximum: Duration) -> io::Result<Duration> {
        if self.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTPS fixture stopped",
            ));
        }
        let remaining: Duration = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTPS fixture deadline elapsed",
            ));
        }
        Ok(remaining.min(maximum))
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket
            .set_read_timeout(Some(self.remaining(SOCKET_TIMEOUT)?))?;
        self.socket.read(bytes)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(self.remaining(SOCKET_TIMEOUT)?))?;
        self.socket.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining(SOCKET_TIMEOUT)?;
        self.socket.flush()
    }
}

fn forward_connection(
    socket: TcpStream,
    backend: SocketAddr,
    server_config: Arc<ServerConfig>,
    counters: &RelayCounters,
    stop: Arc<AtomicBool>,
    deadline: Instant,
    apply_ack_loss: Option<&Mutex<ApplyAckLoss>>,
) -> io::Result<()> {
    socket.set_nonblocking(false)?;
    let connection: ServerConnection =
        ServerConnection::new(server_config).map_err(io::Error::other)?;
    let client: DeadlineSocket = DeadlineSocket {
        socket,
        deadline,
        stop: Arc::clone(&stop),
    };
    let mut tls: StreamOwned<ServerConnection, DeadlineSocket> =
        StreamOwned::new(connection, client);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    counters.handshakes.fetch_add(1, Ordering::SeqCst);
    let (request, is_post): (Vec<u8>, bool) = read_request(&mut tls)?;
    counters.requests.fetch_add(1, Ordering::SeqCst);
    let connect_timeout: Duration = tls.sock.remaining(CONNECT_TIMEOUT)?;
    let backend_socket: TcpStream = TcpStream::connect_timeout(&backend, connect_timeout)?;
    let mut upstream: DeadlineSocket = DeadlineSocket {
        socket: backend_socket,
        deadline,
        stop,
    };
    upstream.remaining(SOCKET_TIMEOUT)?;
    if is_post {
        // Count conservatively before the first write: a partial/failed POST
        // remains an attempt, while an unauthenticated TLS peer cannot count.
        counters.posts.fetch_add(1, Ordering::SeqCst);
    }
    upstream.write_all(&request)?;
    upstream.flush()?;
    let response: Vec<u8> = read_response(&mut upstream)?;
    let mut downstream: ApplicationResponseWriter<'_> = ApplicationResponseWriter {
        tls: &mut tls,
        application_bytes: 0,
    };
    if let Some(loss) = apply_ack_loss {
        let mut loss: std::sync::MutexGuard<'_, ApplyAckLoss> = loss
            .lock()
            .map_err(|_| invalid("ACK-loss observation poisoned"))?;
        if loss.observed.is_none()
            && matches_published_apply(&request, loss.target)
            && let Some((upstream_status, response_header_length)) =
                successful_apply_response(&response, loss.target)
        {
            loss.observed = Some(LostApplyAcknowledgement {
                request_header_length: http_header_length(&request)
                    .expect("already matched complete request"),
                request,
                response,
                response_header_length,
                upstream_status,
                handshake_completed: !downstream.tls.conn.is_handshaking(),
                downstream_application_bytes: downstream.application_bytes,
            });
            // Drop the real socket without close_notify, any application write,
            // or a manufactured HTTP/TLS result. Only this peer's one-shot is
            // consumed; exact replay takes the ordinary forwarding path below.
            return Ok(());
        }
    }
    downstream.write_all(&response)?;
    downstream.flush()?;
    downstream.tls.conn.send_close_notify();
    downstream.flush()
}

/// Counts actual plaintext response bytes accepted by rustls, including partial
/// writes. Handshake records cannot count as HTTP application-response bytes.
struct ApplicationResponseWriter<'a> {
    tls: &'a mut StreamOwned<ServerConnection, DeadlineSocket>,
    application_bytes: usize,
}

impl Write for ApplicationResponseWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written: usize = self.tls.write(bytes)?;
        self.application_bytes = self
            .application_bytes
            .checked_add(written)
            .ok_or_else(|| invalid("HTTPS application response byte count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls.flush()
    }
}

fn http_header_length(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window: &[u8]| window == b"\r\n\r\n")
        .map(|position: usize| position + 4)
}

fn matches_published_apply(request: &[u8], target: [u8; 32]) -> bool {
    let Some(header_length) = http_header_length(request) else {
        return false;
    };
    let expected: String = format!(
        "POST {} HTTP/1.1\r\n",
        node_wire::FASTVOTE_PUBLISHED_APPLY_PATH
    );
    if !request.starts_with(expected.as_bytes()) {
        return false;
    }
    let apply: node_wire::FastVotePublishedApplyRequest =
        match node_wire::FastVotePublishedApplyRequest::decode(&request[header_length..]) {
            Ok(apply) => apply,
            Err(_) => return false,
        };
    let signed: execution::paid_execution::SignedPaidIntent =
        match execution::paid_execution::decode_signed_paid_intent(&apply.signed_paid_intent) {
            Ok(signed) => signed,
            Err(_) => return false,
        };
    signed.intent.request_id == target
}

/// A complete fixed-length 200 response must contain the original canonical
/// single Accepted node result and successful paid payload for the target.
fn successful_apply_response(response: &[u8], target: [u8; 32]) -> Option<(u16, usize)> {
    let header_length: usize = http_header_length(response)?;
    let header: &str = std::str::from_utf8(&response[..header_length - 4]).ok()?;
    let mut lines: std::str::Split<'_, &str> = header.split("\r\n");
    let status_line: Vec<&str> = lines.next()?.split_ascii_whitespace().collect();
    if status_line.len() < 2 || status_line[0] != "HTTP/1.1" {
        return None;
    }
    let status: u16 = status_line[1].parse::<u16>().ok()?;
    if status != 200 {
        return None;
    }
    let mut length: Option<usize> = None;
    for line in lines {
        let (name, value): (&str, &str) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return None;
            }
            length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    let body: &[u8] = &response[header_length..];
    if length? != body.len() {
        return None;
    }
    let result: node_wire::HttpNodeResult = node_wire::HttpNodeResult::decode(body).ok()?;
    if result.request_id().as_bytes() != &target || result.encode().ok()? != body {
        return None;
    }
    let [accepted] = result.responses() else {
        return None;
    };
    if accepted.status() != node_core::NodeResponseStatus::Accepted {
        return None;
    }
    let paid: execution::paid_execution::PaidExecutionResult =
        execution::paid_execution::decode_paid_execution_result(accepted.payload()?).ok()?;
    if paid.request_id != target
        || paid.status != execution::paid_execution::PaidExecutionStatus::Success
        || execution::paid_execution::encode_paid_execution_result(&paid).ok()?
            != accepted.payload()?
    {
        return None;
    }
    Some((status, header_length))
}

/// Reads only a capped header plus any body bytes coalesced into those reads.
/// The caller retains all original bytes; framing inspection never rewrites them.
fn read_header<R: Read>(source: &mut R) -> io::Result<(Vec<u8>, usize)> {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk: [u8; 4096] = [0; 4096];
    loop {
        if let Some(position) = raw
            .windows(4)
            .position(|window: &[u8]| window == b"\r\n\r\n")
        {
            return Ok((raw, position + 4));
        }
        let remaining: usize = MAX_HEADER_BYTES - raw.len();
        if remaining == 0 {
            return Err(invalid("HTTPS fixture HTTP header exceeds bound"));
        }
        let limit: usize = chunk.len().min(remaining);
        let read: usize = source.read(&mut chunk[..limit])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete HTTP header",
            ));
        }
        raw.extend_from_slice(&chunk[..read]);
    }
}

fn read_request<R: Read>(source: &mut R) -> io::Result<(Vec<u8>, bool)> {
    let (mut raw, header_length): (Vec<u8>, usize) = read_header(source)?;
    let header: &str = std::str::from_utf8(&raw[..header_length])
        .map_err(|_| invalid("HTTP fixture request header is not UTF-8"))?;
    if !header.is_ascii() {
        return Err(invalid("HTTP fixture request header is not ASCII"));
    }
    let mut lines: std::str::Split<'_, &str> = header[..header.len() - 4].split("\r\n");
    let first: &str = lines
        .next()
        .ok_or_else(|| invalid("missing HTTP request line"))?;
    let fields: Vec<&str> = first.split_ascii_whitespace().collect();
    if fields.len() != 3
        || fields[2] != "HTTP/1.1"
        || !fields[1].starts_with('/')
        || !http_token(fields[0])
    {
        return Err(invalid("unsupported HTTP fixture request line"));
    }
    let is_post: bool = fields[0] == "POST";
    let mut content_length: Option<usize> = None;
    for line in lines {
        let (name, value): (&str, &str) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid HTTP fixture header"))?;
        if !http_token(name)
            || value
                .bytes()
                .any(|byte: u8| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid("invalid HTTP fixture header characters"));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid(
                "HTTP fixture requires fixed-length request framing",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value: &str =
                value.trim_matches(|character: char| character == ' ' || character == '\t');
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte: u8| byte.is_ascii_digit())
            {
                return Err(invalid("ambiguous HTTP fixture content length"));
            }
            let length: usize = value
                .parse::<usize>()
                .map_err(|_| invalid("invalid HTTP content length"))?;
            if length > MAX_REQUEST_BODY_BYTES {
                return Err(invalid("HTTPS fixture request body exceeds bound"));
            }
            content_length = Some(length);
        }
    }
    let expected: usize = header_length
        .checked_add(content_length.unwrap_or(0))
        .ok_or_else(|| invalid("HTTP fixture request length overflow"))?;
    if raw.len() > expected {
        return Err(invalid("HTTP fixture received bytes beyond one request"));
    }
    let mut chunk: [u8; 4096] = [0; 4096];
    while raw.len() < expected {
        let limit: usize = chunk.len().min(expected - raw.len());
        let read: usize = source.read(&mut chunk[..limit])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete HTTP request body",
            ));
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    Ok((raw, is_post))
}

fn http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte: u8| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// The compiled host sends Connection: close. Read its complete raw response
/// to EOF under the same absolute deadline, preserving even its HTTP headers.
fn read_response<R: Read>(source: &mut R) -> io::Result<Vec<u8>> {
    let (mut response, _header_length): (Vec<u8>, usize) = read_header(source)?;
    let mut chunk: [u8; 4096] = [0; 4096];
    loop {
        // One bounded lookahead byte distinguishes exact-cap EOF from oversize.
        let remaining: usize = MAX_RESPONSE_BYTES - response.len();
        let limit: usize = chunk.len().min(remaining + 1);
        let read: usize = source.read(&mut chunk[..limit])?;
        if read == 0 {
            return Ok(response);
        }
        if read > remaining {
            return Err(invalid("HTTPS fixture response exceeds bound"));
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fixture_framing_preserves_request_bytes_including_opaque_body() {
        let bytes: &[u8] =
            b"POST /ordinary HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 3\r\n\r\na\0b";
        let (observed, is_post): (Vec<u8>, bool) = read_request(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(observed, bytes);
        assert!(is_post);
        let get: &[u8] = b"GET /ordinary HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n";
        let (observed, is_post): (Vec<u8>, bool) = read_request(&mut Cursor::new(get)).unwrap();
        assert_eq!(observed, get);
        assert!(!is_post);
    }

    #[test]
    fn fixture_framing_refuses_ambiguous_truncated_and_oversized_requests() {
        let oversized: String = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_BYTES + 1
        );
        let overflow: String =
            format!("POST / HTTP/1.1\r\nContent-Length: {}0\r\n\r\n", usize::MAX);
        for bytes in [
            b"POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\n\r\nextra".as_slice(),
            b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nX: \x1b[31m\r\n\r\n".as_slice(),
            oversized.as_bytes(),
            overflow.as_bytes(),
        ] {
            assert!(read_request(&mut Cursor::new(bytes)).is_err());
        }
        let mut too_large: Vec<u8> = b"GET / HTTP/1.1\r\nX: ".to_vec();
        too_large.resize(MAX_HEADER_BYTES, b'a');
        too_large.extend_from_slice(b"\r\n\r\n");
        assert!(read_request(&mut Cursor::new(too_large)).is_err());
    }
}
