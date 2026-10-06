//! Private local acceptance transport: terminate fixture TLS and forward exact
//! HTTP bytes to one real compiled loopback host. It produces no protocol result
//! and holds no validator signing authority. Its keys authenticate fixture TLS.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 512;
const MAX_LIFETIME: Duration = Duration::from_secs(10 * 60);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL: Duration = Duration::from_millis(5);

// Fixture identity only; never a protocol ID or a source of authority.
static NEXT_RELAY: AtomicU64 = AtomicU64::new(1);

/// One ephemeral CA/DNS-bound endpoint in front of one actual local host.
/// Failed TLS connections are isolated; Drop stops and joins the sole worker.
pub struct HttpsRelay {
    pub addr: SocketAddr,
    pub ca_der: Vec<u8>,
    pub server_name: String,
    /// Conservative count of POST forwarding attempts, including failed writes.
    /// TLS handshakes, HTTP reads and backend connection failures never count.
    pub posts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HttpsRelay {
    pub fn new(backend: SocketAddr) -> Self {
        assert!(
            backend.ip().is_loopback(),
            "HTTPS fixture backend must be loopback"
        );
        let instance: u64 = NEXT_RELAY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value: u64| {
                value.checked_add(1)
            })
            .expect("HTTPS fixture identity exhausted");
        let server_name: String = format!(
            "validator-{}-{instance}.sunrise-edge.invalid",
            std::process::id()
        );
        let (ca_der, server_config): (Vec<u8>, Arc<ServerConfig>) = certificate(&server_name);
        let listener: TcpListener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind private HTTPS fixture listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking HTTPS fixture listener");
        let addr: SocketAddr = listener.local_addr().expect("HTTPS fixture address");
        let stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let posts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let worker_stop: Arc<AtomicBool> = Arc::clone(&stop);
        let worker_posts: Arc<AtomicUsize> = Arc::clone(&posts);
        let deadline: Instant = Instant::now()
            .checked_add(MAX_LIFETIME)
            .expect("HTTPS fixture lifetime overflow");
        let worker: JoinHandle<()> = thread::spawn(move || {
            let mut accepted: usize = 0;
            while accepted < MAX_CONNECTIONS
                && !worker_stop.load(Ordering::Acquire)
                && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((socket, _peer)) => {
                        accepted += 1;
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
                            &worker_posts,
                            Arc::clone(&worker_stop),
                            connection_deadline.min(deadline),
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            ca_der,
            server_name,
            posts,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for HttpsRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Accepted socket operations expire within SOCKET_TIMEOUT, and
            // connect and nonblocking accept have their own tighter bounds.
            // Cleanup never panics during a failed test's unwind.
            let _ignored: thread::Result<()> = worker.join();
        }
    }
}

fn certificate(server_name: &str) -> (Vec<u8>, Arc<ServerConfig>) {
    let mut ca_params: CertificateParams =
        CertificateParams::new(Vec::<String>::new()).expect("fixture CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key: KeyPair = KeyPair::generate().expect("fixture CA key");
    let ca: Certificate = ca_params
        .self_signed(&ca_key)
        .expect("fixture CA certificate");
    let ca_der: Vec<u8> = ca.der().to_vec();
    let issuer: Issuer<'_, KeyPair> = Issuer::new(ca_params, ca_key);
    let mut leaf_params: CertificateParams =
        CertificateParams::new(vec![server_name.to_owned()]).expect("fixture DNS leaf parameters");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key: KeyPair = KeyPair::generate().expect("fixture leaf key");
    let leaf: Certificate = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("fixture CA-signed DNS leaf");
    let private_key: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
    let config: ServerConfig = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], private_key)
        .expect("fixture TLS configuration");
    (ca_der, Arc::new(config))
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
    posts: &AtomicUsize,
    stop: Arc<AtomicBool>,
    deadline: Instant,
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
    let (request, is_post): (Vec<u8>, bool) = read_request(&mut tls)?;
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
        posts.fetch_add(1, Ordering::SeqCst);
    }
    upstream.write_all(&request)?;
    upstream.flush()?;
    let response: Vec<u8> = read_response(&mut upstream)?;
    tls.write_all(&response)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    tls.flush()
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
