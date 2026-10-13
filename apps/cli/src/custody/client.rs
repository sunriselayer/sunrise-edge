//! The publication CLI's custody client leg.
//!
//! This is deliberately not a generic `ExternalSigner`: it never hands
//! custody a caller-built signable frame. It sends only the untrusted inputs
//! to `PreparedPublication::prepare` (canonical artifact bytes, nonce,
//! request id); the caller (`commands/publication.rs`) builds its own local
//! `PreparedPublication` from the same inputs and independently verifies the
//! returned signature via `PreparedPublication::finalize`, exactly as it
//! already does for the local/Ledger signer paths.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use sunrise_edge_client::{CodeArtifact, RequestId};

use super::error::CustodyError;
use super::wire::{self, CustodyResponse};

/// Bounded deadline to establish the connection.
const CONNECT_DEADLINE: Duration = Duration::from_secs(5);
/// Bounded deadline for each individual read/write once connected.
const IO_DEADLINE: Duration = Duration::from_secs(10);

/// Everything the client must pin explicitly; none of these have a default
/// or environment-variable fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyTarget {
    pub socket: std::path::PathBuf,
    pub custody_uid: u32,
    pub expected_public_key: [u8; 32],
}

/// Connects to custody, sends the bounded artifact/nonce/request-id, checks
/// the server's peer UID against `target.custody_uid` before ever sending
/// anything, and returns either the raw 64-byte signature or a typed,
/// redacted refusal. Never retried, never falls back.
pub fn request_signature(
    target: &CustodyTarget,
    artifact: &CodeArtifact,
    nonce: u64,
    request_id: RequestId,
) -> Result<[u8; wire::CUSTODY_SIGNATURE_BYTES], CustodyError> {
    let artifact_bytes = sunrise_edge_client::publication::encode_code_artifact(artifact)
        .map_err(|error| CustodyError::Publication(Box::new(error)))?;
    let request = wire::SignPublicationRequest {
        nonce,
        request_id,
        artifact_bytes,
    };
    let frame = wire::encode_request(&request).map_err(CustodyError::Wire)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(CustodyError::Runtime)?;
    runtime.block_on(request_signature_async(target, &frame))
}

async fn request_signature_async(
    target: &CustodyTarget,
    frame: &[u8],
) -> Result<[u8; wire::CUSTODY_SIGNATURE_BYTES], CustodyError> {
    let mut stream = connect_and_check_peer(&target.socket, target.custody_uid).await?;

    let length = u32::try_from(frame.len()).map_err(|_| {
        CustodyError::Wire(wire::CustodyWireError::ArtifactTooLarge {
            actual: frame.len(),
            maximum: wire::MAX_CUSTODY_REQUEST_FRAME_BYTES,
        })
    })?;
    timeout(IO_DEADLINE, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(frame).await
    })
    .await
    .map_err(|_| CustodyError::IoTimedOut)?
    .map_err(CustodyError::IoFailed)?;

    let mut header = [0_u8; 2];
    timeout(IO_DEADLINE, stream.read_exact(&mut header))
        .await
        .map_err(|_| CustodyError::IoTimedOut)?
        .map_err(CustodyError::IoFailed)?;
    let mut response_bytes = header.to_vec();
    if header[0] == wire::CUSTODY_WIRE_VERSION && header[1] == 0 {
        let mut signature = [0_u8; wire::CUSTODY_SIGNATURE_BYTES];
        timeout(IO_DEADLINE, stream.read_exact(&mut signature))
            .await
            .map_err(|_| CustodyError::IoTimedOut)?
            .map_err(CustodyError::IoFailed)?;
        response_bytes.extend_from_slice(&signature);
    }

    match wire::decode_response(&response_bytes).map_err(CustodyError::Wire)? {
        CustodyResponse::Signed { signature } => Ok(signature),
        CustodyResponse::Refused { status } => Err(CustodyError::Refused(status)),
    }
}

async fn connect_and_check_peer(
    socket: &Path,
    expected_uid: u32,
) -> Result<UnixStream, CustodyError> {
    let stream = timeout(CONNECT_DEADLINE, UnixStream::connect(socket))
        .await
        .map_err(|_| CustodyError::ConnectTimedOut)?
        .map_err(CustodyError::Connect)?;
    let credentials = stream.peer_cred().map_err(CustodyError::PeerCredentials)?;
    if credentials.uid() != expected_uid {
        return Err(CustodyError::UnexpectedPeerUid {
            expected: expected_uid,
            actual: credentials.uid(),
        });
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::super::approvals::ApprovalRecord;
    use super::super::config::CustodyConfig;
    use super::super::fsperm::test_support::TempDir;
    use super::super::selfuid::own_uid;
    use super::super::server::{self, ServeBounds};
    use super::super::{approvals, wire};
    use super::*;
    use sunrise_edge_client::{ArtifactParts, PackageOrigin, PublicationContext};

    fn config_text(publisher_hex: &str, operator_uid: u32) -> String {
        format!(
            "chain_id=sunrise-local-devnet\nprotocol_version=3\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={publisher_hex}\noperator_uid={operator_uid}\n",
            "44".repeat(32),
        )
    }

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
            PackageOrigin::unverified(expected.chain_id().clone(), publisher, [3; 32]).unwrap();
        let semantics =
            sunrise_edge_client::local_publication_profile_semantics(&resolver, &context).unwrap();
        CodeArtifact::new(ArtifactParts {
            context,
            origin,
            revision: 1,
            wasm_profile: sunrise_edge_client::CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
            semantics,
            wasm: vec![0_u8; 8],
            unverified_abi: Vec::new(),
            exports: vec!["run".to_string()],
            unverified_dependencies: Vec::new(),
        })
        .unwrap()
    }

    /// Exercises a full signed round trip over a real Unix socket: real
    /// framing, a real `peer_cred` check on both the client and server
    /// side, a real approval-store lookup, and independent signature
    /// verification via `PreparedPublication::finalize`. This calls
    /// `serve_async` directly rather than the public `server::run`, because
    /// in a single test process the only available peer necessarily shares
    /// this process's own UID, so `config.operator_uid` is set to that same
    /// UID here. `server::run`'s separate "operator UID must differ from
    /// custody's own UID" startup invariant is covered on its own in
    /// `server::tests::run_refuses_at_startup_when_operator_uid_equals_custodys_own_uid`;
    /// genuinely distinct-UID behavior needs the separate Docker fixture
    /// (see the custody guide), not an in-process test.
    #[tokio::test(flavor = "current_thread")]
    async fn round_trip_signs_an_approved_request_over_a_real_socket() {
        let config_dir = TempDir::new(0o700);
        let socket_dir = TempDir::new(server::SOCKET_DIR_MODE);
        let approvals_dir = TempDir::new(approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0xA1; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());

        let this_uid = own_uid().await.unwrap();
        let config_path = config_dir.child("config");
        super::super::fsperm::test_support::write_mode_file(
            &config_path,
            super::super::config::CONFIG_FILE_MODE,
            config_text(&publisher_hex, this_uid).as_bytes(),
        );
        let config = CustodyConfig::load(&config_path).unwrap();
        let socket_path = socket_dir.child("custody.sock");

        let artifact = sample_artifact(&config, *signer.address().as_bytes());
        let artifact_bytes =
            sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let request_id = sunrise_edge_client::RequestId::new([0x5A; 32]).unwrap();
        let nonce = 11_u64;

        let expected = config.expected_context().unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let prepared = sunrise_edge_client::PreparedPublication::prepare(
            config.publisher(),
            &resolver,
            &expected,
            sample_artifact(&config, *signer.address().as_bytes()),
            nonce,
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

        let bounds = ServeBounds {
            max_connections: 1,
            max_requests: 1,
            total_deadline: Duration::from_secs(5),
        };
        let serve_socket_path = socket_path.clone();
        let serve_approvals_dir = approvals_dir.0.clone();
        let serve_task = tokio::spawn(async move {
            server::serve_async(
                config,
                signer,
                &serve_socket_path,
                &serve_approvals_dir,
                bounds,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let target = CustodyTarget {
            socket: socket_path,
            custody_uid: this_uid,
            expected_public_key: *prepared.publisher().as_bytes(),
        };
        let signature_frame = wire::encode_request(&wire::SignPublicationRequest {
            nonce,
            request_id,
            artifact_bytes,
        })
        .unwrap();
        let signature = request_signature_async(&target, &signature_frame)
            .await
            .unwrap();

        let submission = prepared.finalize(signature.to_vec()).unwrap();
        assert_eq!(*submission.request().signature(), signature);

        let summary = serve_task.await.unwrap().unwrap();
        assert_eq!(summary.requests_signed, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connect_refuses_an_impostor_server_peer_uid() {
        let socket_dir = TempDir::new(server::SOCKET_DIR_MODE);
        let socket_path = socket_dir.child("custody.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let this_uid = own_uid().await.unwrap();
        let wrong_expected_uid = this_uid.wrapping_add(1).max(1);

        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let error = connect_and_check_peer(&socket_path, wrong_expected_uid)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CustodyError::UnexpectedPeerUid {
                expected,
                actual
            } if expected == wrong_expected_uid && actual == this_uid
        ));
        let _ = accept_task.await;
    }
}
