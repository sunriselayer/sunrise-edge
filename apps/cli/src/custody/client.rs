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
    // Exactly one response occupies this connection. Require its EOF as
    // well as the fixed fields so unknown trailing bytes cannot disappear
    // before the strict wire decoder sees them.
    let mut trailing: [u8; 1] = [0];
    let extra: usize = timeout(IO_DEADLINE, stream.read(&mut trailing))
        .await
        .map_err(|_| CustodyError::IoTimedOut)?
        .map_err(CustodyError::IoFailed)?;
    if extra != 0 {
        return Err(CustodyError::Wire(wire::CustodyWireError::LengthMismatch {
            declared: response_bytes.len(),
            actual: response_bytes.len() + extra,
        }));
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
    use super::super::server;
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
            wasm: crate::test_support::publication_wasm(),
            unverified_abi: b"fixture-abi-v1".to_vec(),
            exports: vec!["run".to_string()],
            unverified_dependencies: Vec::new(),
        })
        .unwrap()
    }

    /// Exercises a full signed round trip over a real Unix socket, using the
    /// real client (`request_signature_async`/`connect_and_check_peer`) and
    /// the real signing decision (`server::sign_request`, which itself
    /// rebuilds `PreparedPublication` and verifies its own produced
    /// signature via `finalize`), wired to a **test-owned** listener rather
    /// than `server::serve_async`.
    ///
    /// This is deliberate, not a simplification: `serve_async` always
    /// enforces "operator UID must differ from custody's own UID" at
    /// startup (see `server::tests::run_refuses_at_startup_when_operator_uid_equals_custodys_own_uid`,
    /// which proves that invariant on its own and must not be weakened to
    /// make this test pass). In one test process, this operator (the
    /// connecting client) and custody (the accepting peer) are necessarily
    /// the same UID, so a real `serve_async` would always legitimately
    /// refuse before ever binding here. Binding the listener directly in
    /// the test exercises the actual wire framing and `sign_request`/
    /// `finalize` wiring end to end without touching that invariant.
    /// Genuinely distinct-UID behavior is the separate Docker fixture's
    /// responsibility (see the custody guide), not this in-process test's.
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

        // Test-owned transport: bind and serve exactly one request using
        // the real wire codec and the real `sign_request`, without going
        // through `serve_async`'s bind/permission/operator-UID logic.
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let serve_config = config.clone();
        let serve_signer = signer.clone();
        let serve_approvals_dir = approvals_dir.0.clone();
        let serve_task = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.unwrap();
            let mut length_bytes = [0_u8; wire::CUSTODY_LENGTH_PREFIX_BYTES];
            stream.read_exact(&mut length_bytes).await.unwrap();
            let declared_len = u32::from_be_bytes(length_bytes) as usize;
            let mut buffer = vec![0_u8; declared_len];
            stream.read_exact(&mut buffer).await.unwrap();
            let request = wire::decode_request(&buffer).unwrap();
            let response = match server::sign_request(
                &serve_config,
                &serve_signer,
                &serve_approvals_dir,
                &request,
            ) {
                Ok(signature) => CustodyResponse::Signed { signature },
                Err(status) => CustodyResponse::Refused { status },
            };
            stream
                .write_all(&wire::encode_response(&response))
                .await
                .unwrap();
            response
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

        let served_response = serve_task.await.unwrap();
        assert_eq!(served_response, CustodyResponse::Signed { signature });
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

    #[tokio::test(flavor = "current_thread")]
    async fn transport_refuses_a_signed_response_with_trailing_bytes() {
        let socket_dir: TempDir = TempDir::new(server::SOCKET_DIR_MODE);
        let socket_path: std::path::PathBuf = socket_dir.child("custody.sock");
        let listener: tokio::net::UnixListener =
            tokio::net::UnixListener::bind(&socket_path).unwrap();
        let this_uid: u32 = own_uid().await.unwrap();
        let serving = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request: [u8; 5] = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            let mut response: Vec<u8> = wire::encode_response(&CustodyResponse::Signed {
                signature: [0; wire::CUSTODY_SIGNATURE_BYTES],
            });
            response.push(0xfe);
            stream.write_all(&response).await.unwrap();
        });
        let target: CustodyTarget = CustodyTarget {
            socket: socket_path,
            custody_uid: this_uid,
            expected_public_key: [0x11; 32],
        };
        let error: CustodyError = request_signature_async(&target, &[1]).await.unwrap_err();
        assert!(matches!(
            error,
            CustodyError::Wire(wire::CustodyWireError::LengthMismatch {
                declared: 66,
                actual: 67,
            })
        ));
        serving.await.unwrap();
    }

    /// Fixture-only probe for the Docker/Linux-UID acceptance fixture
    /// (`scripts/check-docker-custody-fixture-1013.mjs`). No production CLI
    /// surface calls `request_signature` against a socket bound by a
    /// genuinely distinct real Linux UID without also requiring a live node
    /// endpoint (`contract publish`'s network round trip), so the fixture
    /// runs this exact compiled test by name instead of adding a new
    /// production binary/subcommand. It never reads custody's own config or
    /// key file — exactly like the real operator path in
    /// `commands/publication.rs`, every expected-context field and the
    /// expected publisher arrive as plain public inputs the fixture already
    /// holds, mirroring `--expected-chain-id`/`--custody-expected-public-key`
    /// etc. `#[ignore]` keeps this out of the ordinary `cargo test` gate; the
    /// fixture must pass `--ignored --exact` to run it, and every input
    /// arrives through an explicit environment variable with no default, so
    /// a missing prerequisite is a hard failure, never a silent skip.
    #[ignore = "exercised only by the Docker/Linux-UID custody fixture; see scripts/check-docker-custody-fixture-1013.mjs"]
    #[test]
    fn fixture_distinct_uid_round_trip() {
        fn required(name: &'static str) -> String {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("custody fixture prerequisite missing: {name}"))
        }
        fn required_hex32(name: &'static str) -> [u8; 32] {
            crate::hex::decode_hex_32(name, &required(name))
                .unwrap_or_else(|error| panic!("custody fixture: {name} is invalid: {error}"))
        }
        fn required_parsed<T: std::str::FromStr>(name: &'static str) -> T
        where
            T::Err: std::fmt::Display,
        {
            required(name)
                .parse()
                .unwrap_or_else(|error| panic!("custody fixture: {name} is invalid: {error}"))
        }

        let mode = required("CUSTODY_FIXTURE_MODE");
        let chain_id = sunrise_edge_client::ChainId::new(required("CUSTODY_FIXTURE_CHAIN_ID"))
            .expect("custody fixture: CUSTODY_FIXTURE_CHAIN_ID is invalid");
        let protocol_version = sunrise_edge_client::ProtocolVersion::new(required_parsed(
            "CUSTODY_FIXTURE_PROTOCOL_VERSION",
        ));
        let epoch = sunrise_edge_client::Epoch::new(required_parsed("CUSTODY_FIXTURE_EPOCH"));
        let hash_suite_id =
            sunrise_edge_client::HashSuiteId::new(required_parsed("CUSTODY_FIXTURE_HASH_SUITE_ID"));
        let domain = sunrise_edge_client::AtomicityDomainId::new(required_hex32(
            "CUSTODY_FIXTURE_DOMAIN_HEX",
        ))
        .expect("custody fixture: CUSTODY_FIXTURE_DOMAIN_HEX is invalid");
        let publisher_bytes = required_hex32("CUSTODY_FIXTURE_PUBLISHER_HEX");
        let publisher = sunrise_edge_client::Address::new(publisher_bytes);
        let nonce: u64 = required_parsed("CUSTODY_FIXTURE_NONCE");
        let request_id =
            sunrise_edge_client::RequestId::new(required_hex32("CUSTODY_FIXTURE_REQUEST_ID_HEX"))
                .expect("custody fixture: CUSTODY_FIXTURE_REQUEST_ID_HEX is invalid");

        let expected = sunrise_edge_client::ExpectedProtocolContext::new(
            chain_id.clone(),
            protocol_version,
            epoch,
            hash_suite_id,
            sunrise_edge_client::ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            sunrise_edge_client::SignatureSchemeId::Ed25519.as_u16(),
            sunrise_edge_client::ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            domain,
        )
        .expect("custody fixture: expected protocol context is invalid");
        let resolver = sunrise_edge_client::local_publication_resolver(&expected)
            .expect("custody fixture: resolver construction failed");
        let context =
            sunrise_edge_client::PublicationContext::new(chain_id.clone(), protocol_version, epoch)
                .expect("custody fixture: publication context is invalid");
        // Fixed, non-secret, deterministic fixture content (not real code,
        // not a real origin seed): identical on every invocation, so the
        // artifact `custody approve` is shown out of band and the artifact
        // `serve` re-derives under its own pinned config are byte-identical.
        let origin =
            sunrise_edge_client::PackageOrigin::unverified(chain_id, publisher_bytes, [0x5E; 32])
                .expect("custody fixture: package origin is invalid");
        let semantics =
            sunrise_edge_client::local_publication_profile_semantics(&resolver, &context)
                .expect("custody fixture: semantics commitment failed");
        // Optional, defaulted (not a required prerequisite): lets the
        // fixture's changed-artifact negative case build a frame that
        // differs from the one `custody approve` was shown, without a
        // second probe mode.
        let wasm_first_byte: u8 = std::env::var("CUSTODY_FIXTURE_WASM_FIRST_BYTE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let mut wasm: Vec<u8> = crate::test_support::publication_wasm();
        wasm[0] = wasm_first_byte;
        let artifact = sunrise_edge_client::CodeArtifact::new(sunrise_edge_client::ArtifactParts {
            context,
            origin,
            revision: 1,
            wasm_profile: sunrise_edge_client::CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
            semantics,
            wasm,
            unverified_abi: b"fixture-abi-v1".to_vec(),
            exports: vec!["run".to_string()],
            unverified_dependencies: Vec::new(),
        })
        .expect("custody fixture: artifact construction is invalid");

        match mode.as_str() {
            // Run once, independently of custody and before `custody
            // approve`, to produce the exact canonical artifact bytes the
            // custody administrator pins as `--approved-artifact`.
            "generate-artifact" => {
                let artifact_out = required("CUSTODY_FIXTURE_ARTIFACT_OUT");
                let bytes = sunrise_edge_client::publication::encode_code_artifact(&artifact)
                    .expect("custody fixture: artifact encoding failed");
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file: std::fs::File = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&artifact_out)
                    .expect("custody fixture: creating the generated artifact failed");
                file.write_all(&bytes)
                    .expect("custody fixture: writing the generated artifact failed");
                file.sync_all()
                    .expect("custody fixture: synchronizing preimage failed");
                println!(
                    "{{\"mode\":\"generate-artifact\",\"artifact_bytes\":{}}}",
                    bytes.len()
                );
            }
            // Run as the operator UID against the already-running `serve`
            // process (a genuinely distinct real Linux UID), then
            // independently re-verify the returned signature exactly as
            // `commands/publication.rs` does via `PreparedPublication::finalize`.
            "sign-and-verify" => {
                let prepared = sunrise_edge_client::PreparedPublication::prepare(
                    publisher, &resolver, &expected, artifact, nonce, request_id,
                )
                .expect("custody fixture: local PreparedPublication::prepare failed");
                let target = CustodyTarget {
                    socket: std::path::PathBuf::from(required("CUSTODY_FIXTURE_SOCKET")),
                    custody_uid: required_parsed("CUSTODY_FIXTURE_CUSTODY_UID"),
                    expected_public_key: publisher_bytes,
                };
                let signature = request_signature(
                    &target,
                    prepared.artifact(),
                    prepared.nonce(),
                    prepared.request_id(),
                )
                .expect("custody fixture: request_signature failed");
                let submission = prepared
                    .finalize(signature.to_vec())
                    .expect("custody fixture: independent finalize/verify failed");
                // The signature is a public value attached to the
                // publication (not key material); printing it lets the
                // fixture confirm byte-for-byte equality across a
                // `serve` restart against the same persisted approval.
                println!(
                    "{{\"mode\":\"sign-and-verify\",\"verified\":true,\"nonce\":{},\"request_id\":\"{}\",\"signature_hex\":\"{}\"}}",
                    submission.request().nonce(),
                    crate::hex::encode_hex(submission.request_id()),
                    crate::hex::encode_hex(&signature),
                );
            }
            other => panic!("custody fixture: unknown CUSTODY_FIXTURE_MODE {other:?}"),
        }
    }
}
