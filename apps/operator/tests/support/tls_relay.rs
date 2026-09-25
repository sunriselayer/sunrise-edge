//! Minimal transparent TLS-terminating PostgreSQL relay.
//!
//! The shared CI/live PostgreSQL service (`SUNRISE_EDGE_TEST_POSTGRES_URL`)
//! exposes only a plaintext port, but `fee_escrow_inventory_pg` refuses any
//! connection that is not TLS with a certificate-validating host (see
//! `require_tls_tcp_host` in `src/bin/fee_escrow_inventory_pg.rs`). This proxy
//! bridges the two for the operator E2E test: it terminates PostgreSQL's
//! ordinary `SSLRequest` negotiation using an ephemeral, private CA-issued
//! `localhost` certificate, then relays every byte in both directions
//! verbatim to the real backend. No PostgreSQL wire frame is ever inspected
//! or altered, unlike `runtime-postgres`'s own `tls_commit_loss` proxy (which
//! this is deliberately simpler than, since no fault injection is needed
//! here). It is deliberately not an end-to-end PostgreSQL-server TLS or
//! production PKI fixture.

use postgres_rustls::{MakeTlsConnector, tokio, tokio_rustls};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{net::SocketAddr, sync::Arc, thread, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Builder,
    sync::watch,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];
const MAX_ACCEPTED_CONNECTIONS: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Bounded, test-only TLS terminator relaying to one fixed backend address.
pub struct TlsPassthroughProxy {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    accept_handle: Option<thread::JoinHandle<()>>,
}

impl TlsPassthroughProxy {
    /// Starts the bounded proxy and returns the strictly verifying client
    /// connector (trusting only this proxy's ephemeral CA) plus that CA's raw
    /// DER bytes, for the operator binary's own independent `--tls-root-der`.
    pub fn spawn(backend_addr: SocketAddr) -> (Self, MakeTlsConnector, Vec<u8>) {
        let (server_config, client_connector, ca_der) = tls_configs();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let local_addr = listener.local_addr().unwrap();
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let accept_handle = thread::spawn(move || {
            let runtime = Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(run_accept_loop(
                listener,
                backend_addr,
                server_config,
                shutdown_receiver,
            ));
        });
        (
            Self {
                local_addr,
                shutdown,
                accept_handle: Some(accept_handle),
            },
            client_connector,
            ca_der,
        )
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for TlsPassthroughProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        let _ = std::net::TcpStream::connect(self.local_addr);
        if let Some(handle) = self.accept_handle.take() {
            let _ = handle.join();
        }
    }
}

fn tls_configs() -> (Arc<ServerConfig>, MakeTlsConnector, Vec<u8>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Sunrise Edge ephemeral operator-E2E CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der: Vec<u8> = ca_cert.der().to_vec();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let private_key: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert.der().clone()], private_key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.clone())).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    (
        Arc::new(server_config),
        MakeTlsConnector::new(connector),
        ca_der,
    )
}

async fn run_accept_loop(
    listener: std::net::TcpListener,
    backend_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener = TcpListener::from_std(listener).unwrap();
    for _ in 0..MAX_ACCEPTED_CONNECTIONS {
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                return;
            }
            accepted = listener.accept() => accepted,
        };
        let Ok((client, _)) = accepted else {
            return;
        };
        if *shutdown.borrow() {
            return;
        }
        let config: Arc<ServerConfig> = Arc::clone(&server_config);
        tokio::spawn(async move {
            handle_connection(client, backend_addr, config).await;
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    backend_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
) {
    let _ = client.set_nodelay(true);
    let mut ssl_request = [0_u8; POSTGRES_SSL_REQUEST.len()];
    if bounded(client.read_exact(&mut ssl_request)).await.is_err()
        || ssl_request != POSTGRES_SSL_REQUEST
        || bounded(client.write_all(b"S")).await.is_err()
    {
        return;
    }
    let acceptor = TlsAcceptor::from(server_config);
    let Ok(Ok(mut tls_client)) = timeout(IO_TIMEOUT, acceptor.accept(client)).await else {
        return;
    };
    let Ok(Ok(mut backend)) = timeout(IO_TIMEOUT, TcpStream::connect(backend_addr)).await else {
        return;
    };
    let _ = backend.set_nodelay(true);
    // Fully transparent from here: every remaining byte (the plaintext
    // startup message this test's client sends immediately after the TLS
    // handshake, and the entire ordinary PostgreSQL session that follows) is
    // relayed verbatim in both directions, with no frame parsing at all.
    let _ = tokio::io::copy_bidirectional(&mut tls_client, &mut backend).await;
}

async fn bounded<F, T>(future: F) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    timeout(IO_TIMEOUT, future)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "bounded I/O timed out"))?
}
