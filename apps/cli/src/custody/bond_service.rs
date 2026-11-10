//! Bounded, Unix peer-authenticated original bond approval broker and two
//! operation-specific key workers. All peer credentials are read before any
//! request body; no endpoint accepts a raw signable frame.

use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

use sunrise_edge_client::LocalSigner;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

use super::{
    bond_approvals,
    bond_config::{BondConfig, BondRole},
    bond_policy::{BondApprovalContent, BondTrust},
    bond_wire::{self, BondPhase, BondRequest, BrokerMessage, Reply},
    client::connect_and_check_peer,
    error::CustodyError,
    positive_fee_split::now,
    selfuid::own_uid,
    server::{self, ServeBounds, ServeSummary},
};
use crate::error::CliError;

fn invalid(message: &'static str) -> CliError {
    CliError::LocalExecution(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    )))
}

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

/// One advisory lock per trusted approval directory. The file is retained on
/// normal exit/crash; the kernel releases the lock with the open descriptor,
/// so restart never removes or bypasses a possibly live broker's lock.
struct BrokerStoreLock {
    _file: File,
    directory: PathBuf,
    lock_path: PathBuf,
    directory_identity: (u64, u64),
    lock_identity: (u64, u64),
    uid: u32,
}

impl BrokerStoreLock {
    fn acquire(directory: &Path, uid: u32) -> Result<Self, CliError> {
        super::fsperm::require_private_dir(directory, 0o700).map_err(failure)?;
        let directory_metadata = fs::symlink_metadata(directory).map_err(failure)?;
        let lock_path = directory.join(".bond-broker.lock");
        let create = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path);
        let file = match create {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&lock_path).map_err(failure)?;
                Self::check_file_metadata(&metadata, uid)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lock_path)
                    .map_err(failure)?
            }
            Err(error) => return Err(failure(error)),
        };
        let file_metadata = file.metadata().map_err(failure)?;
        Self::check_file_metadata(&file_metadata, uid)?;
        file.try_lock().map_err(|_| {
            invalid("bond approval store already has a broker or lock is unavailable")
        })?;
        let locked = Self {
            _file: file,
            directory: directory.to_path_buf(),
            lock_path,
            directory_identity: (directory_metadata.dev(), directory_metadata.ino()),
            lock_identity: (file_metadata.dev(), file_metadata.ino()),
            uid,
        };
        locked.check()?;
        Ok(locked)
    }

    fn check_file_metadata(metadata: &fs::Metadata, uid: u32) -> Result<(), CliError> {
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.uid() != uid
            || metadata.nlink() != 1
        {
            return Err(invalid(
                "bond broker store lock identity or mode is invalid",
            ));
        }
        Ok(())
    }

    fn check(&self) -> Result<(), CliError> {
        super::fsperm::require_private_dir(&self.directory, 0o700).map_err(failure)?;
        let directory = fs::symlink_metadata(&self.directory).map_err(failure)?;
        let lock = fs::symlink_metadata(&self.lock_path).map_err(failure)?;
        Self::check_file_metadata(&lock, self.uid)?;
        if (directory.dev(), directory.ino()) != self.directory_identity
            || (lock.dev(), lock.ino()) != self.lock_identity
        {
            return Err(invalid("bond broker approval store identity changed"));
        }
        Ok(())
    }
}

enum ServiceMode<'a> {
    Broker {
        approvals_dir: &'a Path,
        inner_worker_socket: &'a Path,
        outer_worker_socket: &'a Path,
    },
    Worker {
        phase: BondPhase,
        signer: &'a LocalSigner,
    },
}

pub(super) fn serve_broker(
    trust: &BondTrust,
    socket: &Path,
    approvals_dir: &Path,
    inner_worker_socket: &Path,
    outer_worker_socket: &Path,
    bounds: ServeBounds,
) -> Result<ServeSummary, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(failure)?;
    runtime.block_on(serve(
        trust,
        socket,
        bounds,
        ServiceMode::Broker {
            approvals_dir,
            inner_worker_socket,
            outer_worker_socket,
        },
    ))
}

pub(super) fn serve_worker(
    trust: &BondTrust,
    phase: BondPhase,
    signer: &LocalSigner,
    socket: &Path,
    bounds: ServeBounds,
) -> Result<ServeSummary, CliError> {
    let expected = match phase {
        BondPhase::Inner => trust.config().source_key(),
        BondPhase::Outer => trust.config().validator_key_address(),
    };
    if signer.address() != expected {
        return Err(invalid("bond worker key differs from the pinned role key"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(failure)?;
    runtime.block_on(serve(
        trust,
        socket,
        bounds,
        ServiceMode::Worker { phase, signer },
    ))
}

async fn serve(
    trust: &BondTrust,
    socket: &Path,
    bounds: ServeBounds,
    mode: ServiceMode<'_>,
) -> Result<ServeSummary, CliError> {
    let role = match mode {
        ServiceMode::Broker { .. } => BondRole::Broker,
        ServiceMode::Worker {
            phase: BondPhase::Inner,
            ..
        } => BondRole::InnerWorker,
        ServiceMode::Worker {
            phase: BondPhase::Outer,
            ..
        } => BondRole::OuterWorker,
    };
    let uid = own_uid().await.map_err(failure)?;
    trust.config().check_role_uid(role, uid).map_err(failure)?;
    let store_lock = match &mode {
        ServiceMode::Broker { approvals_dir, .. } => {
            Some(BrokerStoreLock::acquire(approvals_dir, uid)?)
        }
        ServiceMode::Worker { .. } => None,
    };
    let (listener, socket_guard) = server::bind_custody_socket(socket).map_err(failure)?;
    let deadline = Instant::now()
        .checked_add(bounds.total_deadline)
        .ok_or_else(|| failure(CustodyError::DeadlineOverflow))?;
    let mut summary = ServeSummary::default();
    while summary.connections_accepted < bounds.max_connections
        && summary.requests_handled < bounds.max_requests
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let stream = match timeout(remaining, listener.accept()).await {
            Ok(Ok((stream, _))) => stream,
            _ => break,
        };
        summary.connections_accepted += 1;
        let observed_uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(_) => continue,
        };
        let permitted_before_read = match mode {
            ServiceMode::Broker { .. } => [
                trust.config().cli_uid(),
                trust.config().inner_approver_uid(),
                trust.config().outer_approver_uid(),
            ]
            .contains(&observed_uid),
            ServiceMode::Worker { .. } => observed_uid == trust.config().broker_uid(),
        };
        if !permitted_before_read {
            continue;
        }
        if store_lock
            .as_ref()
            .is_some_and(|lock| lock.check().is_err())
        {
            return Err(invalid("bond broker approval store identity changed"));
        }
        let io_deadline = deadline
            .saturating_duration_since(Instant::now())
            .min(server::CUSTODY_IO_DEADLINE);
        if io_deadline.is_zero() {
            break;
        }
        let signed = timeout(
            io_deadline,
            handle_connection(stream, observed_uid, trust, &mode, store_lock.as_ref()),
        )
        .await
        .unwrap_or(false);
        summary.requests_handled += 1;
        if signed {
            summary.requests_signed += 1;
        } else {
            summary.requests_refused += 1;
        }
    }
    drop(socket_guard);
    drop(store_lock);
    Ok(summary)
}

async fn handle_connection(
    mut stream: UnixStream,
    observed_uid: u32,
    trust: &BondTrust,
    mode: &ServiceMode<'_>,
    store_lock: Option<&BrokerStoreLock>,
) -> bool {
    let maximum = match mode {
        ServiceMode::Broker { .. } => bond_wire::MAX_BROKER_MESSAGE_BYTES,
        ServiceMode::Worker { .. } => bond_wire::MAX_REQUEST_BYTES,
    };
    let body = match server::read_request_frame(&mut stream, maximum).await {
        Ok(body) => body,
        Err(_) => return false,
    };
    let reply = match mode {
        ServiceMode::Broker {
            approvals_dir,
            inner_worker_socket,
            outer_worker_socket,
        } => {
            // A CLI/approver connection carries exactly one request and
            // closes its write half before the broker mutates any record.
            let mut trailing = [0_u8; 1];
            if !matches!(stream.read(&mut trailing).await, Ok(0)) {
                Reply::Refused
            } else {
                match bond_wire::decode_broker_message(&body) {
                    Ok(BrokerMessage::Sign { request, config }) => {
                        broker_sign(
                            trust,
                            approvals_dir,
                            inner_worker_socket,
                            outer_worker_socket,
                            observed_uid,
                            request,
                            config,
                        )
                        .await
                    }
                    Ok(message) => {
                        handle_broker_message(trust, approvals_dir, observed_uid, message).await
                    }
                    Err(_) => Reply::Refused,
                }
            }
        }
        ServiceMode::Worker { phase, signer } => match bond_wire::decode_request(&body) {
            Ok(request) if request.phase() == *phase => {
                handle_worker_request(&mut stream, trust, *phase, signer, &request).await
            }
            _ => Reply::Refused,
        },
    };
    // The broker's single-thread loop cannot accept/complete a revocation
    // until this write and close complete. The final authorization sample
    // immediately before emission is the expiry decision; the write/close
    // is the sign/revoke ordering point. No delivery-time claim is made.
    let release_authorized = !store_lock.is_some_and(|lock| lock.check().is_err())
        && match (mode, &reply) {
            (ServiceMode::Broker { approvals_dir, .. }, Reply::Signed(_)) => {
                match bond_wire::decode_broker_message(&body) {
                    Ok(BrokerMessage::Sign { request, .. }) => {
                        authorized_content(trust, approvals_dir, &request)
                            .await
                            .is_ok()
                    }
                    _ => false,
                }
            }
            _ => true,
        }
        && !store_lock.is_some_and(|lock| lock.check().is_err());
    let reply = if !release_authorized {
        Reply::Refused
    } else {
        reply
    };
    let accepted = matches!(reply, Reply::Approved | Reply::Signed(_));
    if stream
        .write_all(&bond_wire::encode_reply(&reply))
        .await
        .is_err()
    {
        return false;
    }
    if stream.shutdown().await.is_err() {
        return false;
    }
    accepted
}

async fn authorized_content(
    trust: &BondTrust,
    dir: &Path,
    request: &BondRequest,
) -> Result<BondApprovalContent, CliError> {
    let prepared = trust.prepare(request)?;
    let content = &prepared.content;
    let inner_content = if let BondRequest::Outer { inner, .. } = request {
        let inner_request = BondRequest::Inner(inner.clone());
        Some(trust.prepare(&inner_request)?.content)
    } else {
        None
    };
    prepared.requery_async(trust, request).await?;
    // Sample approval expiry after the potentially slow node round trip.
    // The broker's final call to this function is immediately before reply
    // emission, while its serial loop still excludes a revoke request.
    bond_approvals::authorize_for_sign(
        dir,
        content,
        inner_content.as_ref(),
        trust.config().inner_approver_uid(),
        trust.config().outer_approver_uid(),
        now().map_err(failure)?,
    )
    .map_err(failure)?;
    Ok(prepared.content)
}

async fn handle_broker_message(
    trust: &BondTrust,
    dir: &Path,
    observed_uid: u32,
    message: BrokerMessage,
) -> Reply {
    let result: Result<(), CliError> = async {
        match message {
            BrokerMessage::Approve {
                request,
                not_after,
                config,
            } => {
                if config != trust.config().raw_bytes() {
                    return Err(invalid("bond approval role config differs from broker pin"));
                }
                let expected_uid = match request.phase() {
                    BondPhase::Inner => trust.config().inner_approver_uid(),
                    BondPhase::Outer => trust.config().outer_approver_uid(),
                };
                if observed_uid != expected_uid {
                    return Err(invalid("bond approval peer has the wrong phase role"));
                }
                let prepared = trust.prepare(&request)?;
                // Requery before sampling any expiry: the inner approval and
                // the new record must both be checked after the potentially
                // slow node round trip, never against an earlier sample.
                prepared.requery_async(trust, &request).await?;
                if let BondRequest::Outer { inner, .. } = &request {
                    let inner_content = trust.prepare(&BondRequest::Inner(inner.clone()))?.content;
                    bond_approvals::authorize(
                        dir,
                        &inner_content,
                        trust.config().inner_approver_uid(),
                        now().map_err(failure)?,
                    )
                    .map_err(failure)?;
                }
                bond_approvals::write(
                    dir,
                    &prepared.content,
                    observed_uid,
                    not_after,
                    now().map_err(failure)?,
                )
                .map_err(failure)
            }
            // Check is accepted only as the response to a broker-initiated
            // worker request on that same authenticated Unix connection.
            BrokerMessage::Check { .. } | BrokerMessage::Sign { .. } => {
                Err(invalid("bond broker message has the wrong connection role"))
            }
            BrokerMessage::Revoke { phase, request_id } => {
                let expected_uid = match phase {
                    BondPhase::Inner => trust.config().inner_approver_uid(),
                    BondPhase::Outer => trust.config().outer_approver_uid(),
                };
                if observed_uid != expected_uid {
                    return Err(invalid("bond revocation peer has the wrong phase role"));
                }
                bond_approvals::revoke(dir, &request_id).map_err(failure)
            }
        }
    }
    .await;
    if result.is_ok() {
        Reply::Approved
    } else {
        Reply::Refused
    }
}

async fn handle_worker_request(
    stream: &mut UnixStream,
    trust: &BondTrust,
    phase: BondPhase,
    signer: &LocalSigner,
    request: &BondRequest,
) -> Reply {
    let result: Result<[u8; 64], CliError> = async {
        if request.phase() != phase {
            return Err(invalid("bond worker phase mismatch"));
        }
        let prepared = trust.prepare(request)?;
        if signer.address() != prepared.content.expected_key {
            return Err(invalid("bond worker signer mismatch"));
        }
        // Requery first so the broker's expiry/revocation check is the last
        // authorization decision before the protected key signs.
        let permit = prepared.requery_async(trust, request).await?;
        let challenge = BrokerMessage::Check {
            request: request.clone(),
            config: trust.config().raw_bytes().to_vec(),
        };
        let bytes = bond_wire::encode_broker_message(&challenge).map_err(failure)?;
        write_frame(stream, &bytes).await?;
        let mut answer = [0_u8; 2];
        stream.read_exact(&mut answer).await.map_err(failure)?;
        if bond_wire::decode_reply(&answer).map_err(failure)? != Reply::Approved {
            return Err(invalid("bond broker refused worker approval challenge"));
        }
        let signature = prepared.sign_with(signer, permit)?;
        Ok(signature)
    }
    .await;
    match result {
        Ok(signature) => Reply::Signed(signature),
        Err(_) => Reply::Refused,
    }
}

async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), CliError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| invalid("bond IPC request exceeds its length bound"))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(failure)?;
    stream.write_all(bytes).await.map_err(failure)
}

/// The broker alone releases signatures to the CLI. Its single-threaded
/// accept loop cannot complete a revoke while this operation is in flight.
async fn broker_sign(
    trust: &BondTrust,
    dir: &Path,
    inner_worker_socket: &Path,
    outer_worker_socket: &Path,
    observed_uid: u32,
    request: BondRequest,
    config: Vec<u8>,
) -> Reply {
    let result: Result<[u8; 64], CliError> = async {
        if observed_uid != trust.config().cli_uid() || config != trust.config().raw_bytes() {
            return Err(invalid(
                "bond signing caller or role config differs from pin",
            ));
        }
        authorized_content(trust, dir, &request).await?;
        let prepared = trust.prepare(&request)?;
        let (socket, worker_uid) = match request.phase() {
            BondPhase::Inner => (inner_worker_socket, trust.config().inner_worker_uid()),
            BondPhase::Outer => (outer_worker_socket, trust.config().outer_worker_uid()),
        };
        let mut worker = connect_and_check_peer(socket, worker_uid)
            .await
            .map_err(failure)?;
        let request_bytes = bond_wire::encode_request(&request).map_err(failure)?;
        write_frame(&mut worker, &request_bytes).await?;
        let challenge_bytes =
            server::read_request_frame(&mut worker, bond_wire::MAX_BROKER_MESSAGE_BYTES)
                .await
                .map_err(failure)?;
        match bond_wire::decode_broker_message(&challenge_bytes).map_err(failure)? {
            BrokerMessage::Check {
                request: challenged,
                config: challenged_config,
            } if challenged == request && challenged_config == config => {}
            _ => {
                return Err(invalid(
                    "bond worker approval challenge differs from request",
                ));
            }
        }
        authorized_content(trust, dir, &request).await?;
        worker
            .write_all(&bond_wire::encode_reply(&Reply::Approved))
            .await
            .map_err(failure)?;
        let mut response = Vec::new();
        worker
            .take((bond_wire::MAX_REPLY_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await
            .map_err(failure)?;
        let signature = match bond_wire::decode_reply(&response).map_err(failure)? {
            Reply::Signed(signature) => signature,
            _ => return Err(invalid("bond worker refused the requested signature")),
        };
        // Verify the returned signature with the owner's exact prepared
        // operation. The caller reauthorizes at the emission point.
        let permit = prepared.requery_async(trust, &request).await?;
        prepared.finalize(signature.to_vec(), permit)?;
        Ok(signature)
    }
    .await;
    match result {
        Ok(signature) => Reply::Signed(signature),
        Err(_) => Reply::Refused,
    }
}

async fn send_async(socket: &Path, expected_uid: u32, bytes: &[u8]) -> Result<Reply, CliError> {
    timeout(server::CUSTODY_IO_DEADLINE, async {
        let mut stream = connect_and_check_peer(socket, expected_uid)
            .await
            .map_err(failure)?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| invalid("bond IPC request exceeds its length bound"))?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(failure)?;
        stream.write_all(bytes).await.map_err(failure)?;
        stream.shutdown().await.map_err(failure)?;
        let mut reply = Vec::new();
        stream
            .take((bond_wire::MAX_REPLY_BYTES + 1) as u64)
            .read_to_end(&mut reply)
            .await
            .map_err(failure)?;
        bond_wire::decode_reply(&reply).map_err(failure)
    })
    .await
    .map_err(|_| invalid("bond IPC deadline exceeded"))?
}

pub(super) fn request_broker(
    socket: &Path,
    config: &BondConfig,
    message: &BrokerMessage,
) -> Result<(), CliError> {
    let bytes = bond_wire::encode_broker_message(message).map_err(failure)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(failure)?;
    match runtime.block_on(send_async(socket, config.broker_uid(), &bytes))? {
        Reply::Approved => Ok(()),
        _ => Err(invalid("bond broker refused the operation")),
    }
}

pub(super) fn request_signature_from_broker(
    socket: &Path,
    config: &BondConfig,
    request: &BondRequest,
) -> Result<[u8; 64], CliError> {
    let bytes = bond_wire::encode_broker_message(&BrokerMessage::Sign {
        request: request.clone(),
        config: config.raw_bytes().to_vec(),
    })
    .map_err(failure)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(failure)?;
    match runtime.block_on(send_async(socket, config.broker_uid(), &bytes))? {
        Reply::Signed(signature) => Ok(signature),
        _ => Err(invalid("bond key worker refused the operation")),
    }
}
