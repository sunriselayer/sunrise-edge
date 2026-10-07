//! One immutable, opt-in Native TLS configuration. Endpoint authentication
//! never supplies protocol, caller, signer, store or writer-fence authority.
use crate::common::FlagSet;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::NoServerSessionStorage,
};
use std::{error::Error, fmt, io, path::PathBuf, sync::Arc, time::Duration};
#[cfg(unix)]
use std::{
    fs::{self, File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

pub(crate) const CERT_FLAG: &str = "--tls-cert-der-file";
pub(crate) const KEY_FLAG: &str = "--tls-key-pkcs8-der-file";
const MAX_CERTIFICATES: usize = 4;
const MAX_FILE_BYTES: usize = 16 * 1024;
const MAX_CHAIN_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(5_000);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NativeTlsError {
    InvalidOptions,
    IncompletePair,
    CertificateCount,
    #[cfg(not(unix))]
    UnsupportedPlatform,
    FileUnavailable,
    NotRegular,
    InsecureKeyPermissions,
    AttachmentChanged,
    FileSize,
    InvalidCertificateOrKey,
}

impl fmt::Display for NativeTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidOptions => "invalid Native TLS options",
            Self::IncompletePair => "Native TLS requires both certificate and private-key files",
            Self::CertificateCount => "Native TLS requires one to four certificate files",
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "Native TLS private-file validation requires Unix",
            Self::FileUnavailable => "Native TLS file unavailable",
            Self::NotRegular => "Native TLS file must be nonsymlink and regular",
            Self::InsecureKeyPermissions => "Native TLS key must have private Unix permissions",
            Self::AttachmentChanged => "Native TLS file attachment changed during loading",
            Self::FileSize => "Native TLS files must be nonempty and within their byte limits",
            Self::InvalidCertificateOrKey => "invalid Native TLS certificate or PKCS8 key pair",
        })
    }
}

impl Error for NativeTlsError {}

pub(crate) struct NativeTlsInputs {
    certificates: Vec<PathBuf>,
    key: Option<PathBuf>,
}

impl NativeTlsInputs {
    /// Pure flag validation; callers finish every option/loopback check before load.
    pub(crate) fn parse(flags: &mut FlagSet) -> Result<Self, NativeTlsError> {
        let certificates: Vec<PathBuf> = flags
            .many(CERT_FLAG)
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let key: Option<PathBuf> = flags
            .optional_one(KEY_FLAG)
            .map_err(|_| NativeTlsError::InvalidOptions)?
            .map(PathBuf::from);
        if certificates.is_empty() != key.is_none() {
            return Err(NativeTlsError::IncompletePair);
        }
        if certificates.len() > MAX_CERTIFICATES {
            return Err(NativeTlsError::CertificateCount);
        }
        Ok(Self { certificates, key })
    }

    /// Must complete before genesis/state/blob access or any writer-fence claim.
    pub(crate) fn load(self) -> Result<Option<TlsAcceptor>, NativeTlsError> {
        let Some(key_path) = self.key else {
            return Ok(None);
        };
        let mut certificates: Vec<CertificateDer<'static>> = Vec::new();
        let mut total: usize = 0;
        for path in self.certificates {
            let bytes: Vec<u8> = read_attached(&path, false)?;
            total = total
                .checked_add(bytes.len())
                .ok_or(NativeTlsError::FileSize)?;
            if total > MAX_CHAIN_BYTES {
                return Err(NativeTlsError::FileSize);
            }
            certificates.push(CertificateDer::from(bytes));
        }
        let key: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(read_attached(&key_path, true)?).into();
        let mut config: ServerConfig =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| NativeTlsError::InvalidCertificateOrKey)?
                .with_no_client_auth()
                .with_single_cert(certificates, key)
                .map_err(|_| NativeTlsError::InvalidCertificateOrKey)?;
        // The pinned Ring keys expose SPKI; with_single_cert checks its leaf
        // match. This is not issuer/name/time validation of the entire chain.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.alpn_protocols = Vec::new();
        config.key_log = Arc::new(rustls::NoKeyLog {});
        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    }
}

#[cfg(unix)]
#[derive(PartialEq, Eq)]
struct Attachment {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[cfg(unix)]
impl Attachment {
    fn observe(metadata: &Metadata, private: bool) -> Result<Self, NativeTlsError> {
        if !metadata.file_type().is_file() {
            return Err(NativeTlsError::NotRegular);
        }
        if private && metadata.mode() & 0o077 != 0 {
            return Err(NativeTlsError::InsecureKeyPermissions);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

#[cfg(unix)]
fn read_attached(path: &Path, private: bool) -> Result<Vec<u8>, NativeTlsError> {
    let before: Attachment = Attachment::observe(
        &fs::symlink_metadata(path).map_err(|_| NativeTlsError::FileUnavailable)?,
        private,
    )?;
    let file: File = File::open(path).map_err(|_| NativeTlsError::FileUnavailable)?;
    let opened: Attachment = Attachment::observe(
        &file
            .metadata()
            .map_err(|_| NativeTlsError::FileUnavailable)?,
        private,
    )?;
    if before != opened {
        return Err(NativeTlsError::AttachmentChanged);
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(MAX_FILE_BYTES + 1);
    (&file)
        .take((MAX_FILE_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeTlsError::FileUnavailable)?;
    let after: Attachment = Attachment::observe(
        &file
            .metadata()
            .map_err(|_| NativeTlsError::FileUnavailable)?,
        private,
    )?;
    let attached: Attachment = Attachment::observe(
        &fs::symlink_metadata(path).map_err(|_| NativeTlsError::FileUnavailable)?,
        private,
    )?;
    if before != after || before != attached {
        return Err(NativeTlsError::AttachmentChanged);
    }
    if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
        return Err(NativeTlsError::FileSize);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_attached(_path: &std::path::Path, _private: bool) -> Result<Vec<u8>, NativeTlsError> {
    Err(NativeTlsError::UnsupportedPlatform)
}

/// One absolute handshake budget; shutdown/permit/task ownership is native-http's.
pub(crate) async fn accept(
    acceptor: TlsAcceptor,
    stream: TcpStream,
) -> io::Result<TlsStream<TcpStream>> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Native TLS handshake timeout"))?
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs::OpenOptions,
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Files(PathBuf);
    impl Files {
        fn new() -> Self {
            let path: PathBuf = std::env::temp_dir().join(format!(
                "sunrise-native-tls-load-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path: PathBuf = self.0.join(name);
            let mut file: File = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            path
        }
    }
    impl Drop for Files {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn inputs(cert: &Path, key: &Path) -> NativeTlsInputs {
        let mut flags: FlagSet = FlagSet::parse(
            [
                OsString::from(CERT_FLAG),
                cert.into(),
                OsString::from(KEY_FLAG),
                key.into(),
            ],
            &[CERT_FLAG, KEY_FLAG],
            &[],
        )
        .unwrap();
        let inputs: NativeTlsInputs = NativeTlsInputs::parse(&mut flags).unwrap();
        flags.finish().unwrap();
        inputs
    }
    fn refusal(input: NativeTlsInputs, expected: NativeTlsError) {
        match input.load() {
            Err(error) => {
                assert_eq!(error, expected);
                assert!(!error.to_string().contains("private-byte-sentinel"));
            }
            Ok(_) => panic!("invalid TLS configuration accepted"),
        }
    }
    #[test]
    fn closed_options_and_pair_counts_refuse_without_file_io() {
        let mut empty: FlagSet =
            FlagSet::parse(Vec::<OsString>::new(), &[CERT_FLAG, KEY_FLAG], &[]).unwrap();
        assert!(
            NativeTlsInputs::parse(&mut empty)
                .unwrap()
                .load()
                .unwrap()
                .is_none()
        );
        for tokens in [
            vec![CERT_FLAG, "missing"],
            vec![KEY_FLAG, "missing"],
            vec![
                CERT_FLAG,
                "missing",
                KEY_FLAG,
                "missing",
                KEY_FLAG,
                "duplicate",
            ],
            vec![
                CERT_FLAG, "1", CERT_FLAG, "2", CERT_FLAG, "3", CERT_FLAG, "4", CERT_FLAG, "5",
                KEY_FLAG, "missing",
            ],
        ] {
            let mut flags: FlagSet = FlagSet::parse(
                tokens.into_iter().map(OsString::from),
                &[CERT_FLAG, KEY_FLAG],
                &[],
            )
            .unwrap();
            assert!(NativeTlsInputs::parse(&mut flags).is_err());
        }
        assert!(
            FlagSet::parse(
                [OsString::from("--tls-unknown"), "missing".into()],
                &[CERT_FLAG, KEY_FLAG],
                &[]
            )
            .is_err()
        );
    }
    #[test]
    fn bounded_regular_private_files_and_key_leaf_match() {
        let files: Files = Files::new();
        let leaf: rcgen::CertifiedKey<rcgen::KeyPair> =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert: PathBuf = files.file("leaf.der", leaf.cert.der(), 0o644);
        let key: PathBuf = files.file("key.der", &leaf.signing_key.serialize_der(), 0o600);
        let acceptor: TlsAcceptor = inputs(&cert, &key).load().unwrap().unwrap();
        let config: &ServerConfig = acceptor.config();
        assert_eq!(config.send_tls13_tickets, 0);
        assert_eq!(config.max_early_data_size, 0);
        assert!(!config.ticketer.enabled());
        assert!(config.alpn_protocols.is_empty());
        assert!(!config.session_storage.put(vec![1], vec![2]));
        let malformed: PathBuf = files.file("malformed.der", b"private-byte-sentinel", 0o600);
        refusal(
            inputs(&cert, &malformed),
            NativeTlsError::InvalidCertificateOrKey,
        );
        refusal(
            inputs(&malformed, &key),
            NativeTlsError::InvalidCertificateOrKey,
        );
        let other: rcgen::CertifiedKey<rcgen::KeyPair> =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let mismatch: PathBuf = files.file("other.der", &other.signing_key.serialize_der(), 0o600);
        refusal(
            inputs(&cert, &mismatch),
            NativeTlsError::InvalidCertificateOrKey,
        );
        let empty: PathBuf = files.file("empty", b"", 0o600);
        let oversized: PathBuf = files.file("oversized", &vec![7; MAX_FILE_BYTES + 1], 0o600);
        for invalid in [&empty, &oversized] {
            refusal(inputs(invalid, &key), NativeTlsError::FileSize);
            refusal(inputs(&cert, invalid), NativeTlsError::FileSize);
        }
        let missing: PathBuf = files.0.join("missing");
        refusal(inputs(&missing, &key), NativeTlsError::FileUnavailable);
        refusal(inputs(&cert, &missing), NativeTlsError::FileUnavailable);
        let directory: PathBuf = files.0.join("directory");
        fs::create_dir(&directory).unwrap();
        refusal(inputs(&directory, &key), NativeTlsError::NotRegular);
        refusal(inputs(&cert, &directory), NativeTlsError::NotRegular);
        let alias: PathBuf = files.0.join("symlink");
        symlink(&key, &alias).unwrap();
        refusal(inputs(&cert, &alias), NativeTlsError::NotRegular);
        let cert_alias: PathBuf = files.0.join("certificate-symlink");
        symlink(&cert, &cert_alias).unwrap();
        refusal(inputs(&cert_alias, &key), NativeTlsError::NotRegular);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        refusal(inputs(&cert, &key), NativeTlsError::InsecureKeyPermissions);
    }

    #[tokio::test]
    async fn actual_operator_handshake_deadline_is_absolute_under_peer_progress() {
        use tokio::io::AsyncWriteExt;
        let files: Files = Files::new();
        let leaf: rcgen::CertifiedKey<rcgen::KeyPair> =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert: PathBuf = files.file("deadline-leaf.der", leaf.cert.der(), 0o644);
        let key: PathBuf = files.file("deadline-key.der", &leaf.signing_key.serialize_der(), 0o600);
        let acceptor: TlsAcceptor = inputs(&cert, &key).load().unwrap().unwrap();
        let listener: tokio::net::TcpListener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: std::net::SocketAddr = listener.local_addr().unwrap();
        let (ready, started): (
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        ) = tokio::sync::oneshot::channel();
        let task: tokio::task::JoinHandle<io::Result<TlsStream<TcpStream>>> =
            tokio::spawn(async move {
                let (stream, _peer): (TcpStream, std::net::SocketAddr) =
                    listener.accept().await.unwrap();
                ready.send(()).unwrap();
                accept(acceptor, stream).await
            });
        let mut roots: rustls::RootCertStore = rustls::RootCertStore::empty();
        roots.add(leaf.cert.der().clone()).unwrap();
        let mut config: rustls::ClientConfig = rustls::ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        let mut client: rustls::ClientConnection = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut hello: Vec<u8> = Vec::new();
        client.write_tls(&mut hello).unwrap();
        assert!(hello.len() > 100);
        let mut peer: TcpStream = TcpStream::connect(address).await.unwrap();
        started.await.unwrap();
        peer.write_all(&hello[..10]).await.unwrap();
        let drip = async {
            for byte in &hello[10..40] {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if peer.write_all(&[*byte]).await.is_err() {
                    break;
                }
            }
        };
        let ((), result) = tokio::join!(drip, tokio::time::timeout(Duration::from_secs(7), task));
        let error: io::Error = result.unwrap().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "Native TLS handshake timeout");
    }
}
