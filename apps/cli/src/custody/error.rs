//! Typed, fail-closed errors for the publication-only local custody slice.
//!
//! Every variant is actionable and carries no key material. Display never
//! includes file contents, seeds, signatures, or raw wire bytes.

use std::fmt;
use std::path::PathBuf;

use sunrise_edge_client::{ExpectedProtocolContextError, TypeError};

use super::wire::CustodyResponseStatus;

/// Every failure this subsystem can report, across config loading, the
/// adapter-local wire codec, the approval store, `approve`, `serve`, and the
/// publication client leg.
#[derive(Debug)]
pub enum CustodyError {
    /// Filesystem I/O failed for the named path.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A path that must be a plain file or directory was a symlink.
    Symlink(PathBuf),
    /// A path that must be a regular file was not one.
    NotARegularFile(PathBuf),
    /// A path that must be a directory was not one, or had no parent.
    NotADirectory(PathBuf),
    /// A file or directory's mode bits were not exactly the required value.
    UnexpectedMode {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    /// The path was replaced between its pre-open validation and the open
    /// call completing (TOCTOU race detected via device/inode identity).
    PathReplacedDuringOpen(PathBuf),
    /// A bounded file exceeded its explicit maximum accepted size.
    FileTooLarge { path: PathBuf, maximum: usize },

    /// The config file was not valid UTF-8.
    ConfigNotUtf8,
    /// A config line was not `key=value`.
    ConfigMalformedLine { line: usize },
    /// A required config key never appeared.
    ConfigMissingKey { key: &'static str },
    /// A config key appeared more than once.
    ConfigDuplicateKey { key: String },
    /// A config key not in the fixed accepted set appeared.
    ConfigUnknownKey { key: String },
    /// A config value was not a valid decimal integer.
    ConfigInvalidInteger { key: &'static str },
    /// A config value was not valid hexadecimal of the expected length.
    ConfigInvalidHex { key: &'static str },
    /// A config-derived protocol type was rejected.
    Type(TypeError),
    /// The config's own fields could not build a valid expected context.
    ExpectedContext(ExpectedProtocolContextError),
    /// `--operator-uid` (as read from config) equals the UID `serve` is
    /// actually running as; custody and operator must be distinct principals.
    OperatorUidMatchesCustodyUid { uid: u32 },
    /// The configured socket path already exists; `serve` never unlinks a
    /// stale socket on its own, to avoid silently removing another
    /// process's file.
    SocketAlreadyExists(PathBuf),

    /// The adapter-local request/response codec rejected a frame.
    Wire(super::wire::CustodyWireError),

    /// An approval record was structurally malformed.
    ApprovalMalformed,
    /// An approval record declared an unsupported record version.
    ApprovalUnsupportedVersion(u8),
    /// `custody approve` requires a real interactive terminal on stdin and
    /// stdout; it never approves from a pipe or redirected file.
    ApproveRequiresTerminal,
    /// Decoding or recomputing the approved publication failed.
    Publication(Box<dyn std::error::Error + Send + Sync>),
    /// The operator's typed confirmation line did not exactly match the
    /// displayed publisher/digest/nonce/request-id/expiry.
    ApprovalConfirmationMismatch,
    /// `--expires-in-seconds` overflowed the current time.
    ExpiryOverflow,
    /// The local clock reported a time before the Unix epoch.
    ClockBeforeEpoch,

    /// Connecting to the custody socket timed out.
    ConnectTimedOut,
    /// Connecting to the custody socket failed.
    Connect(std::io::Error),
    /// Reading the connected peer's credentials failed.
    PeerCredentials(std::io::Error),
    /// The connected peer's UID did not match the pinned expectation.
    UnexpectedPeerUid { expected: u32, actual: u32 },
    /// A bounded read or write exceeded its deadline.
    IoTimedOut,
    /// A bounded read or write failed.
    IoFailed(std::io::Error),
    /// Building the async runtime for one bounded custody call failed.
    Runtime(std::io::Error),
    /// The server explicitly refused the request; `status` is the one
    /// redacted reason code it returned, never a free-form message.
    Refused(CustodyResponseStatus),

    /// Reading cryptographically secure random bytes for `keygen` failed.
    RandomSourceFailed(std::io::Error),
    /// A key file's derived public key did not match the pinned config
    /// publisher key.
    KeyFileAddressMismatch,
    /// A key file's contents were not exactly 64 hex digits (plus an
    /// optional trailing newline).
    KeyFileMalformed,
    /// A command other than publication selected `SignerSelection::Custody`.
    /// Custody signs publication submissions only; every other family is
    /// refused here, before any file, network, or device I/O.
    PublicationOnly { command: &'static str },
    /// A directory or file required to be owned by this process's own
    /// current effective UID was owned by a different UID.
    UnexpectedOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    /// This process's own effective UID could not be determined from a
    /// bounded parse of `/proc/self/status`.
    SelfUidUnavailable,
    /// The independently supplied `--approved-artifact` file decoded, but
    /// its bytes were not exactly the canonical encoding of the artifact it
    /// decodes to: re-encoding the decoded artifact produced different
    /// bytes. A decodable-but-non-canonical preimage is refused rather than
    /// silently accepted, since the approval record binds the canonical
    /// frame, not merely "some encoding that decodes to the same value."
    ApprovedPreimageNotCanonical,
    /// A `serve` lifetime/count bound (`--max-connections`, `--max-requests`,
    /// or `--total-deadline-secs`) was outside its closed accepted range.
    ServeBoundOutOfRange {
        field: &'static str,
        value: u64,
        minimum: u64,
        maximum: u64,
    },
    /// Computing the absolute total serve deadline overflowed.
    DeadlineOverflow,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "custody I/O failed for {path:?}: {source}"),
            Self::Symlink(path) => write!(f, "custody path {path:?} must not be a symlink"),
            Self::NotARegularFile(path) => {
                write!(f, "custody path {path:?} must be a regular file")
            }
            Self::NotADirectory(path) => write!(f, "custody path {path:?} must be a directory"),
            Self::UnexpectedMode {
                path,
                expected,
                actual,
            } => write!(
                f,
                "custody path {path:?} must have mode {expected:03o}, got {actual:03o}"
            ),
            Self::PathReplacedDuringOpen(path) => {
                write!(f, "custody path {path:?} was replaced while opening it")
            }
            Self::FileTooLarge { path, maximum } => {
                write!(
                    f,
                    "custody file {path:?} exceeds the maximum {maximum} bytes"
                )
            }
            Self::ConfigNotUtf8 => f.write_str("custody config file is not valid UTF-8"),
            Self::ConfigMalformedLine { line } => {
                write!(f, "custody config line {line} is not key=value")
            }
            Self::ConfigMissingKey { key } => write!(f, "custody config is missing key {key}"),
            Self::ConfigDuplicateKey { key } => {
                write!(f, "custody config key {key} appears more than once")
            }
            Self::ConfigUnknownKey { key } => write!(f, "custody config has unknown key {key}"),
            Self::ConfigInvalidInteger { key } => {
                write!(f, "custody config key {key} is not a valid decimal integer")
            }
            Self::ConfigInvalidHex { key } => {
                write!(f, "custody config key {key} is not valid hexadecimal")
            }
            Self::Type(error) => write!(f, "custody config has an invalid protocol type: {error}"),
            Self::ExpectedContext(error) => {
                write!(
                    f,
                    "custody config cannot build an expected context: {error}"
                )
            }
            Self::OperatorUidMatchesCustodyUid { uid } => write!(
                f,
                "configured operator UID {uid} must differ from the custody process's own UID"
            ),
            Self::SocketAlreadyExists(path) => {
                write!(
                    f,
                    "custody socket path {path:?} already exists; remove it first"
                )
            }
            Self::Wire(error) => write!(f, "custody wire codec rejected a frame: {error}"),
            Self::ApprovalMalformed => f.write_str("custody approval record is malformed"),
            Self::ApprovalUnsupportedVersion(version) => {
                write!(
                    f,
                    "custody approval record version {version} is not supported"
                )
            }
            Self::ApproveRequiresTerminal => {
                f.write_str("custody approve requires an interactive terminal on stdin and stdout")
            }
            Self::Publication(error) => {
                write!(f, "custody publication recomputation failed: {error}")
            }
            Self::ApprovalConfirmationMismatch => {
                f.write_str("custody approve confirmation did not match the displayed values")
            }
            Self::ExpiryOverflow => f.write_str("custody approval expiry overflowed"),
            Self::ClockBeforeEpoch => {
                f.write_str("local clock reported a time before the Unix epoch")
            }
            Self::ConnectTimedOut => f.write_str("connecting to the custody socket timed out"),
            Self::Connect(error) => write!(f, "connecting to the custody socket failed: {error}"),
            Self::PeerCredentials(error) => {
                write!(f, "reading custody peer credentials failed: {error}")
            }
            Self::UnexpectedPeerUid { expected, actual } => write!(
                f,
                "custody peer UID {actual} did not match the expected UID {expected}"
            ),
            Self::IoTimedOut => f.write_str("a bounded custody read or write timed out"),
            Self::IoFailed(error) => write!(f, "a custody read or write failed: {error}"),
            Self::Runtime(error) => write!(f, "building the custody async runtime failed: {error}"),
            Self::Refused(status) => write!(f, "custody refused the request: {status}"),
            Self::RandomSourceFailed(error) => {
                write!(f, "reading secure random bytes failed: {error}")
            }
            Self::KeyFileAddressMismatch => f.write_str(
                "custody key file's derived public key does not match the configured publisher",
            ),
            Self::KeyFileMalformed => {
                f.write_str("custody key file contents are not exactly 64 hex digits")
            }
            Self::PublicationOnly { command } => write!(
                f,
                "custody signing is publication-only; not supported for {command}"
            ),
            Self::UnexpectedOwner {
                path,
                expected,
                actual,
            } => write!(
                f,
                "custody path {path:?} must be owned by UID {expected} (this process's own effective UID), got {actual}"
            ),
            Self::SelfUidUnavailable => f.write_str(
                "could not determine this process's own effective UID from /proc/self/status",
            ),
            Self::ApprovedPreimageNotCanonical => f.write_str(
                "--approved-artifact decoded, but its bytes are not the exact canonical re-encoding of the decoded artifact",
            ),
            Self::ServeBoundOutOfRange {
                field,
                value,
                minimum,
                maximum,
            } => write!(
                f,
                "{field}={value} is outside the accepted closed range [{minimum}, {maximum}]"
            ),
            Self::DeadlineOverflow => {
                f.write_str("computing the absolute total serve deadline overflowed")
            }
        }
    }
}

impl std::error::Error for CustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Connect(source) | Self::PeerCredentials(source) => {
                Some(source)
            }
            Self::IoFailed(source) | Self::Runtime(source) | Self::RandomSourceFailed(source) => {
                Some(source)
            }
            Self::Type(error) => Some(error),
            Self::ExpectedContext(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Publication(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
