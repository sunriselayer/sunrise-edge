//! `custody serve`: a bounded-lifetime, one-request-at-a-time publication
//! signer.
//!
//! This is an optional host facility with an explicit bounded lifetime and
//! request count, not a protocol daemon assumption: it never spawns, never
//! loops without an explicit bound, and exits on its own once any one of
//! `max_connections`, `max_requests`, or the total deadline is reached.
//! Every accepted connection is checked against exactly one pinned operator
//! UID via `UnixStream::peer_cred` (an existing, safe Tokio API) before any
//! byte is read from it. `serve` never writes an approval record; it only
//! ever reads the store `custody approve` writes.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

use sunrise_edge_client::LocalSigner;

use super::approvals;
use super::config::CustodyConfig;
use super::error::CustodyError;
use super::fsperm::require_private_dir;
use super::selfuid::own_uid;
use super::wire::{self, CustodyResponse, CustodyResponseStatus, CustodyWireError};

/// Required exact socket parent-directory mode: owner may read/write/list,
/// group may traverse and connect, other has no access.
pub const SOCKET_DIR_MODE: u32 = 0o750;
/// Required exact socket file mode after bind.
pub const SOCKET_FILE_MODE: u32 = 0o660;
/// Fixed per-connection bound on each individual read or write. Mechanical,
/// not operator policy, so it is a constant rather than a flag.
const CUSTODY_IO_DEADLINE: Duration = Duration::from_secs(10);

/// Closed accepted range for `--max-connections`/`--max-requests`: at least
/// one (zero would mean "serve nothing," a meaningless invocation), at most
/// a generous fixed ceiling rather than an arbitrary `u32`.
pub const MIN_SERVE_COUNT: u32 = 1;
pub const MAX_SERVE_COUNT: u32 = 10_000;
/// Closed accepted range, in seconds, for `--total-deadline-secs`: at least
/// one second, at most 24 hours. Keeping this bounded (rather than any
/// `u32`) keeps the absolute deadline computed from it comfortably clear of
/// `Instant` arithmetic limits, checked explicitly regardless.
pub const MIN_SERVE_TOTAL_DEADLINE_SECS: u32 = 1;
pub const MAX_SERVE_TOTAL_DEADLINE_SECS: u32 = 86_400;

/// Explicit, caller-supplied bounds on one `serve` invocation's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeBounds {
    pub max_connections: u32,
    pub max_requests: u32,
    pub total_deadline: Duration,
}

impl ServeBounds {
    /// Validates `max_connections`/`max_requests`/`total_deadline_secs`
    /// against their closed accepted ranges before any socket, config, or
    /// key file is touched.
    pub fn new(
        max_connections: u32,
        max_requests: u32,
        total_deadline_secs: u32,
    ) -> Result<Self, CustodyError> {
        Self::check_range(
            "max_connections",
            max_connections,
            MIN_SERVE_COUNT,
            MAX_SERVE_COUNT,
        )?;
        Self::check_range(
            "max_requests",
            max_requests,
            MIN_SERVE_COUNT,
            MAX_SERVE_COUNT,
        )?;
        Self::check_range(
            "total_deadline_secs",
            total_deadline_secs,
            MIN_SERVE_TOTAL_DEADLINE_SECS,
            MAX_SERVE_TOTAL_DEADLINE_SECS,
        )?;
        Ok(Self {
            max_connections,
            max_requests,
            total_deadline: Duration::from_secs(u64::from(total_deadline_secs)),
        })
    }

    fn check_range(
        field: &'static str,
        value: u32,
        minimum: u32,
        maximum: u32,
    ) -> Result<(), CustodyError> {
        if value < minimum || value > maximum {
            return Err(CustodyError::ServeBoundOutOfRange {
                field,
                value: u64::from(value),
                minimum: u64::from(minimum),
                maximum: u64::from(maximum),
            });
        }
        Ok(())
    }
}

/// What one bounded `serve` invocation actually did, for operator-visible
/// output. Never includes key material or wire bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServeSummary {
    pub connections_accepted: u32,
    pub requests_handled: u32,
    pub requests_signed: u32,
    pub requests_refused: u32,
}

/// Runs one bounded custody `serve` invocation to completion.
pub fn run(
    config: CustodyConfig,
    signer: LocalSigner,
    socket_path: &Path,
    approvals_dir: &Path,
    bounds: ServeBounds,
) -> Result<ServeSummary, CustodyError> {
    if signer.address() != config.publisher() {
        return Err(CustodyError::KeyFileAddressMismatch);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(CustodyError::Runtime)?;
    runtime.block_on(serve_async(
        config,
        signer,
        socket_path,
        approvals_dir,
        bounds,
    ))
}

pub(super) async fn serve_async(
    config: CustodyConfig,
    signer: LocalSigner,
    socket_path: &Path,
    approvals_dir: &Path,
    bounds: ServeBounds,
) -> Result<ServeSummary, CustodyError> {
    let this_uid = own_uid().await.map_err(CustodyError::PeerCredentials)?;
    if config.operator_uid() == this_uid {
        return Err(CustodyError::OperatorUidMatchesCustodyUid { uid: this_uid });
    }

    let parent = socket_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CustodyError::NotADirectory(socket_path.to_path_buf()))?;
    require_private_dir(parent, SOCKET_DIR_MODE)?;
    if std::fs::symlink_metadata(socket_path).is_ok() {
        return Err(CustodyError::SocketAlreadyExists(socket_path.to_path_buf()));
    }
    let listener = UnixListener::bind(socket_path).map_err(|source| CustodyError::Io {
        path: socket_path.to_path_buf(),
        source,
    })?;
    std::fs::set_permissions(
        socket_path,
        std::fs::Permissions::from_mode(SOCKET_FILE_MODE),
    )
    .map_err(|source| CustodyError::Io {
        path: socket_path.to_path_buf(),
        source,
    })?;
    // Captured once, immediately after bind+chmod, so the cleanup unlink
    // below can prove it is removing exactly the socket this process
    // bound — never a path something else replaced in the meantime.
    let bound_identity = socket_identity(socket_path);

    // One absolute, checked deadline for this entire invocation: accept,
    // and the combined read+write of every connection, are all bounded
    // against this same instant, not independently re-granted budgets.
    let deadline = Instant::now()
        .checked_add(bounds.total_deadline)
        .ok_or(CustodyError::DeadlineOverflow)?;
    let mut summary = ServeSummary::default();

    while summary.connections_accepted < bounds.max_connections
        && summary.requests_handled < bounds.max_requests
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let stream = match timeout(remaining, listener.accept()).await {
            Ok(Ok((stream, _addr))) => stream,
            Ok(Err(_io_error)) => break,
            Err(_elapsed) => break,
        };
        summary.connections_accepted += 1;

        let accepted_uid = stream.peer_cred().ok().map(|cred| cred.uid());
        if accepted_uid != Some(config.operator_uid()) {
            // Wrong or unreadable peer UID: refuse before any byte is read,
            // and do not count this as a handled request.
            continue;
        }

        let remaining_io = deadline.saturating_duration_since(Instant::now());
        let io_deadline = remaining_io.min(CUSTODY_IO_DEADLINE);
        if io_deadline.is_zero() {
            break;
        }
        // One single timeout bounds this connection's entire combined
        // read+decode+sign+write, instead of separately re-granting
        // `io_deadline` to each read and write (which could let one
        // connection run up to several multiples of `io_deadline` past the
        // absolute deadline).
        let signed = match timeout(
            io_deadline,
            handle_one_connection(stream, &config, &signer, approvals_dir),
        )
        .await
        {
            Ok(signed) => signed,
            Err(_elapsed) => false,
        };
        summary.requests_handled += 1;
        if signed {
            summary.requests_signed += 1;
        } else {
            summary.requests_refused += 1;
        }
    }

    unlink_bound_socket_if_unreplaced(socket_path, bound_identity);
    Ok(summary)
}

/// A bound Unix socket's identity: device/inode (proves it is the same
/// filesystem object), file type (proves it is still a socket, not
/// something else at the same path), and owner (consistent with every
/// other ownership check this module makes).
#[derive(Clone, Copy)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
}

/// Captures `path`'s current identity, if it is currently a socket.
/// `None` (rather than propagating an I/O error) if the stat fails or the
/// path is not a socket: the caller treats a missing identity as "do not
/// attempt cleanup," never as a reason to fail the whole invocation.
fn socket_identity(path: &Path) -> Option<SocketIdentity> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_socket() {
        return None;
    }
    Some(SocketIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
    })
}

/// Unlinks `socket_path` only if it is still, right now, exactly the socket
/// this process bound: same device/inode, same owner, and still a socket
/// (never a symlink, regular file, or anything a replacement might have
/// left behind). This is what lets a later `serve` reuse the same path
/// (restart) without ever deleting something this process did not create.
/// Best-effort: any failure here is silently not fatal to an otherwise
/// successful `serve` invocation.
fn unlink_bound_socket_if_unreplaced(socket_path: &Path, bound_identity: Option<SocketIdentity>) {
    let Some(bound) = bound_identity else {
        return;
    };
    let Some(current) = socket_identity(socket_path) else {
        return;
    };
    if current.dev == bound.dev && current.ino == bound.ino && current.uid == bound.uid {
        let _ = std::fs::remove_file(socket_path);
    }
}

/// Handles exactly one request on an already peer-UID-checked connection.
/// Returns whether a signature was produced; every failure path still
/// attempts one best-effort response write before returning. The caller
/// wraps this entire call in one single `timeout`; the reads and write here
/// are plain, un-timed `.await`s so that one connection's combined
/// read+decode+sign+write is bounded exactly once, not by independently
/// re-granted per-step deadlines.
async fn handle_one_connection(
    mut stream: UnixStream,
    config: &CustodyConfig,
    signer: &LocalSigner,
    approvals_dir: &Path,
) -> bool {
    let frame = match read_request_frame(&mut stream).await {
        Ok(frame) => frame,
        Err(_) => return false,
    };
    let request = match wire::decode_request(&frame) {
        Ok(request) => request,
        Err(error) => {
            let status = refusal_status_for_wire_error(&error);
            let _ = write_response(&mut stream, &CustodyResponse::Refused { status }).await;
            return false;
        }
    };
    match sign_request(config, signer, approvals_dir, &request) {
        Ok(signature) => {
            let _ = write_response(&mut stream, &CustodyResponse::Signed { signature }).await;
            true
        }
        Err(status) => {
            let _ = write_response(&mut stream, &CustodyResponse::Refused { status }).await;
            false
        }
    }
}

fn refusal_status_for_wire_error(error: &CustodyWireError) -> CustodyResponseStatus {
    match error {
        CustodyWireError::UnsupportedVersion(_) => CustodyResponseStatus::UnsupportedVersion,
        CustodyWireError::UnsupportedMessageType(_) => {
            CustodyResponseStatus::UnsupportedMessageType
        }
        _ => CustodyResponseStatus::Malformed,
    }
}

async fn read_request_frame(stream: &mut UnixStream) -> Result<Vec<u8>, CustodyError> {
    let mut length_bytes = [0_u8; wire::CUSTODY_LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut length_bytes)
        .await
        .map_err(CustodyError::IoFailed)?;
    let declared_len = u32::from_be_bytes(length_bytes) as usize;
    if declared_len > wire::MAX_CUSTODY_REQUEST_FRAME_BYTES {
        return Err(CustodyError::Wire(CustodyWireError::FrameTooLarge {
            actual: declared_len,
            maximum: wire::MAX_CUSTODY_REQUEST_FRAME_BYTES,
        }));
    }
    let mut buffer = vec![0_u8; declared_len];
    stream
        .read_exact(&mut buffer)
        .await
        .map_err(CustodyError::IoFailed)?;
    Ok(buffer)
}

async fn write_response(
    stream: &mut UnixStream,
    response: &CustodyResponse,
) -> Result<(), CustodyError> {
    let encoded = wire::encode_response(response);
    stream
        .write_all(&encoded)
        .await
        .map_err(CustodyError::IoFailed)
}

/// Pure, synchronous signing decision: rebuilds `PreparedPublication` under
/// custody's own pinned config (never the caller's claimed context), checks
/// it against the stored human approval record, signs, and independently
/// verifies the produced signature (via `finalize`) before returning it.
/// `pub(super)` (not private) only so `client`'s test-owned-transport
/// round-trip test can wire it directly to a real socket without going
/// through `serve_async`'s own bind/operator-UID gating.
pub(super) fn sign_request(
    config: &CustodyConfig,
    signer: &LocalSigner,
    approvals_dir: &Path,
    request: &wire::SignPublicationRequest,
) -> Result<[u8; wire::CUSTODY_SIGNATURE_BYTES], CustodyResponseStatus> {
    let expected = config
        .expected_context()
        .map_err(|_| CustodyResponseStatus::Internal)?;
    let resolver = sunrise_edge_client::local_publication_resolver(&expected)
        .map_err(|_| CustodyResponseStatus::Internal)?;
    let artifact = sunrise_edge_client::publication::decode_code_artifact(&request.artifact_bytes)
        .map_err(|_| CustodyResponseStatus::Malformed)?;
    let prepared = sunrise_edge_client::PreparedPublication::prepare(
        config.publisher(),
        &resolver,
        &expected,
        artifact,
        request.nonce,
        request.request_id,
    )
    .map_err(|error| classify_prepare_error(&error))?;

    let now_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyResponseStatus::Internal)?
        .as_secs();
    let approval = approvals::read_approval(approvals_dir, &prepared.request_id())
        .map_err(|_| CustodyResponseStatus::Internal)?
        .ok_or(CustodyResponseStatus::NoApproval)?;
    if approvals::is_expired(&approval, now_unix_seconds)
        || approval.publisher != config.publisher()
        || approval.frame != prepared.signable_frame()
    {
        return Err(CustodyResponseStatus::NoApproval);
    }

    let submission = prepared
        .sign_and_finalize_with(signer)
        .map_err(|_| CustodyResponseStatus::Internal)?;
    Ok(*submission.request().signature())
}

/// Classifies exactly why `PreparedPublication::prepare` refused, instead of
/// collapsing every possible failure into `PublisherMismatch`: only an
/// actual publisher/address mismatch is reported as such. A trust-context
/// mismatch should be structurally unreachable here (custody always derives
/// both the resolver and the expected context from its own self-consistent
/// config), and any other failure (for example a hashing/encoding error
/// while computing the commitment or frame) is an unexpected internal
/// failure, not something the caller's artifact alone caused.
fn classify_prepare_error(error: &sunrise_edge_client::ClientError) -> CustodyResponseStatus {
    match error {
        sunrise_edge_client::ClientError::ExternalSignerAddressMismatch { .. } => {
            CustodyResponseStatus::PublisherMismatch
        }
        _ => CustodyResponseStatus::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::super::approvals::ApprovalRecord;
    use super::super::fsperm::test_support::TempDir;
    use super::*;
    use sunrise_edge_client::{
        ArtifactParts, CONTRACT_WASM_ADMISSION_PROFILE_VERSION, CodeArtifact, PackageOrigin,
        PublicationContext, RequestId,
    };

    fn config_text(publisher_hex: &str, operator_uid: u32) -> String {
        format!(
            "chain_id=sunrise-local-devnet\nprotocol_version=3\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={publisher_hex}\noperator_uid={operator_uid}\n",
            "33".repeat(32),
        )
    }

    fn write_config(dir: &TempDir, publisher_hex: &str, operator_uid: u32) -> std::path::PathBuf {
        let path = dir.child("config");
        super::super::fsperm::test_support::write_mode_file(
            &path,
            super::super::config::CONFIG_FILE_MODE,
            config_text(publisher_hex, operator_uid).as_bytes(),
        );
        path
    }

    /// Builds a structurally valid, self-consistent publication-profile
    /// artifact under `config`'s own pinned context/resolver, bound to
    /// `publisher`.
    fn sample_artifact(config: &CustodyConfig, publisher: [u8; 32]) -> CodeArtifact {
        let expected = config.expected_context().unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let context = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap();
        let origin =
            PackageOrigin::unverified(expected.chain_id().clone(), publisher, [9; 32]).unwrap();
        let semantics =
            sunrise_edge_client::local_publication_profile_semantics(&resolver, &context).unwrap();
        CodeArtifact::new(ArtifactParts {
            context,
            origin,
            revision: 1,
            wasm_profile: CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
            semantics,
            wasm: vec![0_u8; 8],
            unverified_abi: b"fixture-abi-v1".to_vec(),
            exports: vec!["run".to_string()],
            unverified_dependencies: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn serve_bounds_new_accepts_the_closed_range_boundaries() {
        ServeBounds::new(
            MIN_SERVE_COUNT,
            MIN_SERVE_COUNT,
            MIN_SERVE_TOTAL_DEADLINE_SECS,
        )
        .unwrap();
        ServeBounds::new(
            MAX_SERVE_COUNT,
            MAX_SERVE_COUNT,
            MAX_SERVE_TOTAL_DEADLINE_SECS,
        )
        .unwrap();
    }

    #[test]
    fn serve_bounds_new_rejects_zero_and_above_maximum() {
        assert!(matches!(
            ServeBounds::new(0, 1, 1),
            Err(CustodyError::ServeBoundOutOfRange {
                field: "max_connections",
                value: 0,
                ..
            })
        ));
        assert!(matches!(
            ServeBounds::new(1, 0, 1),
            Err(CustodyError::ServeBoundOutOfRange {
                field: "max_requests",
                value: 0,
                ..
            })
        ));
        assert!(matches!(
            ServeBounds::new(1, 1, 0),
            Err(CustodyError::ServeBoundOutOfRange {
                field: "total_deadline_secs",
                value: 0,
                ..
            })
        ));
        assert!(matches!(
            ServeBounds::new(MAX_SERVE_COUNT + 1, 1, 1),
            Err(CustodyError::ServeBoundOutOfRange {
                field: "max_connections",
                ..
            })
        ));
        assert!(matches!(
            ServeBounds::new(1, 1, MAX_SERVE_TOTAL_DEADLINE_SECS + 1),
            Err(CustodyError::ServeBoundOutOfRange {
                field: "total_deadline_secs",
                ..
            })
        ));
    }

    #[test]
    fn sign_request_refuses_when_no_approval_exists() {
        let dir = TempDir::new(0o700);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x55; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let config_path = write_config(&dir, &publisher_hex, 4242);
        let config = CustodyConfig::load(&config_path).unwrap();
        let artifact = sample_artifact(&config, *signer.address().as_bytes());
        let artifact_bytes =
            sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let request = wire::SignPublicationRequest {
            nonce: 1,
            request_id: RequestId::new([7; 32]).unwrap(),
            artifact_bytes,
        };
        let error = sign_request(&config, &signer, &approvals_dir.0, &request).unwrap_err();
        assert_eq!(error, CustodyResponseStatus::NoApproval);
    }

    #[test]
    fn sign_request_refuses_a_publisher_mismatch_before_touching_approvals() {
        let dir = TempDir::new(0o700);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x66; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let config_path = write_config(&dir, &publisher_hex, 4242);
        let config = CustodyConfig::load(&config_path).unwrap();
        // Artifact's own origin publisher is a different key than config.
        let artifact = sample_artifact(&config, [0xAA; 32]);
        let artifact_bytes =
            sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let request = wire::SignPublicationRequest {
            nonce: 1,
            request_id: RequestId::new([8; 32]).unwrap(),
            artifact_bytes,
        };
        let error = sign_request(&config, &signer, &approvals_dir.0, &request).unwrap_err();
        assert_eq!(error, CustodyResponseStatus::PublisherMismatch);
    }

    #[test]
    fn sign_request_signs_and_independently_verifies_a_matching_approval() {
        let dir = TempDir::new(0o700);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x77; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let config_path = write_config(&dir, &publisher_hex, 4242);
        let config = CustodyConfig::load(&config_path).unwrap();
        let artifact = sample_artifact(&config, *signer.address().as_bytes());
        let artifact_bytes =
            sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let request_id = RequestId::new([9; 32]).unwrap();
        let request = wire::SignPublicationRequest {
            nonce: 1,
            request_id,
            artifact_bytes,
        };

        let expected = config.expected_context().unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let prepared = sunrise_edge_client::PreparedPublication::prepare(
            config.publisher(),
            &resolver,
            &expected,
            sample_artifact(&config, *signer.address().as_bytes()),
            1,
            request_id,
        )
        .unwrap();
        approvals::write_approval(
            &approvals_dir.0,
            &request_id,
            &ApprovalRecord {
                publisher: config.publisher(),
                not_after_unix_seconds: u64::MAX,
                frame: prepared.signable_frame().to_vec(),
            },
        )
        .unwrap();

        let signature = sign_request(&config, &signer, &approvals_dir.0, &request).unwrap();
        assert_eq!(signature.len(), wire::CUSTODY_SIGNATURE_BYTES);
    }

    #[test]
    fn sign_request_refuses_an_expired_approval() {
        let dir = TempDir::new(0o700);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x88; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let config_path = write_config(&dir, &publisher_hex, 4242);
        let config = CustodyConfig::load(&config_path).unwrap();
        let artifact = sample_artifact(&config, *signer.address().as_bytes());
        let artifact_bytes =
            sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let request_id = RequestId::new([10; 32]).unwrap();
        let request = wire::SignPublicationRequest {
            nonce: 1,
            request_id,
            artifact_bytes,
        };
        let expected = config.expected_context().unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let prepared = sunrise_edge_client::PreparedPublication::prepare(
            config.publisher(),
            &resolver,
            &expected,
            sample_artifact(&config, *signer.address().as_bytes()),
            1,
            request_id,
        )
        .unwrap();
        approvals::write_approval(
            &approvals_dir.0,
            &request_id,
            &ApprovalRecord {
                publisher: config.publisher(),
                not_after_unix_seconds: 1,
                frame: prepared.signable_frame().to_vec(),
            },
        )
        .unwrap();

        let error = sign_request(&config, &signer, &approvals_dir.0, &request).unwrap_err();
        assert_eq!(error, CustodyResponseStatus::NoApproval);
    }

    #[test]
    fn sign_request_refuses_when_the_approved_frame_changed() {
        let dir = TempDir::new(0o700);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x99; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let config_path = write_config(&dir, &publisher_hex, 4242);
        let config = CustodyConfig::load(&config_path).unwrap();
        let artifact = sample_artifact(&config, *signer.address().as_bytes());
        let artifact_bytes =
            sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let request_id = RequestId::new([11; 32]).unwrap();
        // A different nonce than what was approved changes the exact frame.
        let request = wire::SignPublicationRequest {
            nonce: 2,
            request_id,
            artifact_bytes,
        };
        let expected = config.expected_context().unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let prepared = sunrise_edge_client::PreparedPublication::prepare(
            config.publisher(),
            &resolver,
            &expected,
            sample_artifact(&config, *signer.address().as_bytes()),
            1,
            request_id,
        )
        .unwrap();
        approvals::write_approval(
            &approvals_dir.0,
            &request_id,
            &ApprovalRecord {
                publisher: config.publisher(),
                not_after_unix_seconds: u64::MAX,
                frame: prepared.signable_frame().to_vec(),
            },
        )
        .unwrap();

        let error = sign_request(&config, &signer, &approvals_dir.0, &request).unwrap_err();
        assert_eq!(error, CustodyResponseStatus::NoApproval);
    }

    #[test]
    fn run_refuses_at_startup_when_operator_uid_equals_custodys_own_uid() {
        let config_dir = TempDir::new(0o700);
        let socket_dir = TempDir::new(SOCKET_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0xC3; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());

        // A throwaway runtime, used and dropped before `run` builds and
        // drops its own: sequential, not nested, so this is not the
        // "runtime within a runtime" case `run` itself cannot be called
        // from inside.
        let this_uid = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(own_uid())
            .unwrap();

        let config_path = write_config(&config_dir, &publisher_hex, this_uid);
        let config = CustodyConfig::load(&config_path).unwrap();
        let socket_path = socket_dir.child("custody.sock");
        let bounds = ServeBounds {
            max_connections: 1,
            max_requests: 1,
            total_deadline: Duration::from_millis(100),
        };

        let error = run(
            config,
            signer,
            &socket_path,
            Path::new("/nonexistent"),
            bounds,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CustodyError::OperatorUidMatchesCustodyUid { uid } if uid == this_uid
        ));
        // The listener must never have been bound.
        assert!(std::fs::symlink_metadata(&socket_path).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn serve_refuses_an_unapproved_request_end_to_end_over_a_real_socket() {
        let config_dir = TempDir::new(0o700);
        let socket_dir = TempDir::new(SOCKET_DIR_MODE);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x21; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());

        let this_uid = own_uid().await.unwrap();
        // The operator UID must differ from our own to pass the startup
        // check, but the test still connects as this same process, so it
        // must be refused as a wrong-UID peer before any request is read.
        let other_uid = this_uid.wrapping_add(1).max(1);
        let config_path = write_config(&config_dir, &publisher_hex, other_uid);
        let config = CustodyConfig::load(&config_path).unwrap();
        let socket_path = socket_dir.child("custody.sock");

        let bounds = ServeBounds {
            max_connections: 1,
            max_requests: 1,
            total_deadline: Duration::from_millis(500),
        };
        let serve_socket_path = socket_path.clone();
        let serve_approvals_dir = approvals_dir.0.clone();
        let serve_task = tokio::spawn(async move {
            serve_async(
                config,
                signer,
                &serve_socket_path,
                &serve_approvals_dir,
                bounds,
            )
            .await
        });

        // Give the listener a moment to bind before connecting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let connect_result = UnixStream::connect(&socket_path).await;
        drop(connect_result);

        let summary = serve_task.await.unwrap().unwrap();
        assert_eq!(summary.connections_accepted, 1);
        assert_eq!(summary.requests_handled, 0);
        // `serve` unlinks its own cleanly-exited socket: a later `serve`
        // invocation at the same path must not see a stale file.
        assert!(std::fs::symlink_metadata(&socket_path).is_err());
    }

    /// `unlink_bound_socket_if_unreplaced` removes exactly the socket whose
    /// identity it was given, proving restart at the same path works.
    #[test]
    fn unlink_removes_the_exact_bound_socket() {
        let dir = TempDir::new(SOCKET_DIR_MODE);
        let socket_path = dir.child("custody.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let identity = socket_identity(&socket_path);
        assert!(identity.is_some());

        unlink_bound_socket_if_unreplaced(&socket_path, identity);
        assert!(std::fs::symlink_metadata(&socket_path).is_err());
    }

    /// If the path was replaced with a different object before cleanup runs
    /// (different device/inode), the replacement must survive untouched —
    /// "never a replacement."
    #[test]
    fn unlink_never_removes_a_path_replaced_with_a_different_object() {
        let dir = TempDir::new(SOCKET_DIR_MODE);
        let socket_path = dir.child("custody.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let original_identity = socket_identity(&socket_path);
        assert!(original_identity.is_some());
        drop(listener);
        std::fs::remove_file(&socket_path).unwrap();
        // A different object at the same path: a plain regular file
        // (deliberately not even a socket), standing in for "something else
        // now occupies this path."
        std::fs::write(&socket_path, b"not a socket").unwrap();

        unlink_bound_socket_if_unreplaced(&socket_path, original_identity);

        assert_eq!(std::fs::read(&socket_path).unwrap(), b"not a socket");
    }

    /// A missing captured identity (bind/chmod never actually completed, so
    /// nothing was ever confirmed bound) must never attempt an unlink.
    #[test]
    fn unlink_does_nothing_when_no_identity_was_captured() {
        let dir = TempDir::new(SOCKET_DIR_MODE);
        let socket_path = dir.child("custody.sock");
        std::fs::write(&socket_path, b"untouched").unwrap();

        unlink_bound_socket_if_unreplaced(&socket_path, None);

        assert_eq!(std::fs::read(&socket_path).unwrap(), b"untouched");
    }

    /// `serve` must be able to restart at the same socket path after a
    /// clean exit: a second bounded invocation targeting the path a first
    /// invocation cleanly unlinked must itself bind successfully, not fail
    /// with `SocketAlreadyExists`.
    #[tokio::test(flavor = "current_thread")]
    async fn serve_can_restart_at_the_same_socket_path_after_a_clean_exit() {
        let config_dir = TempDir::new(0o700);
        let socket_dir = TempDir::new(SOCKET_DIR_MODE);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0x31; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let this_uid = own_uid().await.unwrap();
        let other_uid = this_uid.wrapping_add(1).max(1);
        let socket_path = socket_dir.child("custody.sock");

        for _ in 0..2 {
            let config_path = write_config(&config_dir, &publisher_hex, other_uid);
            let config = CustodyConfig::load(&config_path).unwrap();
            let bounds = ServeBounds {
                max_connections: 1,
                max_requests: 1,
                total_deadline: Duration::from_millis(100),
            };
            let summary = serve_async(
                config,
                signer.clone(),
                &socket_path,
                &approvals_dir.0,
                bounds,
            )
            .await
            .unwrap();
            assert_eq!(summary.connections_accepted, 0);
            assert!(std::fs::symlink_metadata(&socket_path).is_err());
        }
    }
}
