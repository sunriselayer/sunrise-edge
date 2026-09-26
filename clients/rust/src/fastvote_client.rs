//! Certified-only FastVote network client (DR-0148).
//!
//! This module is the client-side half of `native-http::fastvote`: it
//! builds and signs an ordinary paid `Call`, sends it to every configured
//! validator's `POST /v1/fastvote/prepare`, forms a canonical
//! `consensus::FastCertificate` locally from the returned votes using the
//! LOCAL, offline-pinned genesis validator set (never a set fetched live
//! from any server), and submits `POST /v1/fastvote/certificates`.
//!
//! Trust boundaries this module enforces, none of which a remote endpoint
//! can weaken:
//!
//! * [`load_trusted_fastvote_genesis`] only trusts a genesis manifest file
//!   after its exact commitment digest, embedded context, and authority
//!   signature all match a caller-supplied expected digest/context --
//!   exactly [`node_core::genesis`]'s own production trust model, reused
//!   unchanged. The [`validator_set::ValidatorSet`]/[`consensus::FastPathCertifier`]
//!   this produces is the sole source of truth for which `ValidatorId`s and
//!   public keys exist; nothing here ever substitutes a value from a live
//!   `/v1/context` or similar response.
//! * [`FastVoteEndpoint`] is a fixed, caller-configured `(ValidatorId,
//!   Client<T>)` pair. [`collect_fastvote_certificate`] rejects a returned
//!   vote whose `validator` disagrees with the endpoint's own configured
//!   identity before it is ever considered for certificate formation, so a
//!   compromised or misconfigured endpoint cannot borrow another
//!   validator's identity merely by claiming it (its vote would in any case
//!   fail cryptographic verification without that validator's private key,
//!   but this rejects the mismatch immediately, before spending any
//!   verification work on it).
//! * [`collect_fastvote_certificate`] never anchors to the first responding
//!   endpoint. Every returned vote is grouped by its own exact `(tx_hash,
//!   execution_effects_hash, locked_objects_digest)` header, and every
//!   group -- not only the first -- is independently offered to
//!   [`consensus::FastPathCertifier::try_form_certificate`], so one
//!   unavailable or actively Byzantine endpoint (wrong header, foreign
//!   validator, garbage bytes) can neither block a certificate the
//!   remaining honest endpoints' votes still reach quorum for, nor cause a
//!   minority group of its own to be mistaken for the certified outcome:
//!   `try_form_certificate`'s own quorum-weight check still applies to
//!   every group.
//! * The whole prepare-collection phase is bounded by one caller-supplied
//!   wall-clock deadline for the *entire* configured endpoint set, not a
//!   fixed per-request timeout multiplied by endpoint count: each
//!   endpoint's own request deadline is derived from whatever wall-clock
//!   budget remains when that request starts.

use core::fmt;
use std::collections::BTreeMap;
use std::error::Error;
use std::time::Instant;

use consensus::{
    FastCertificate, FastPathCertifier, FastVote, decode_fast_vote, encode_fast_certificate,
};
use execution::local_execution::instance_target;
use execution::paid_execution::{
    PaidApplication, PaidExecutionResult, PaidExecutionStatus, PaidResultKind, PaidResultTarget,
    SignedPaidIntent, decode_paid_execution_result, encode_signed_paid_intent,
};
use execution::publication::PublicationContext;
use node_core::fast_path::FastPathEd25519Verifier;
use node_core::fast_path::records::FastPathValidatorSetRecord;
use node_core::genesis::{
    GenesisManifest, decode_genesis_manifest, genesis_manifest_commitment,
    genesis_manifest_signing_frame,
};
use node_core::{MAX_GENESIS_MANIFEST_BYTES, RequestId};
use node_wire::{FASTVOTE_CERTIFICATES_PATH, FASTVOTE_PREPARE_PATH, FastVoteApplyRequest};
use protocol_types::{Digest32, SignatureSchemeId, ValidatorId};
use validator_set::{ValidatorInfo, ValidatorSet};

use crate::client::expect_success;
use crate::error::ClientError;
use crate::transport::{Method, Transport, WireRequest};
use crate::{Client, NODE_RESULT_MEDIA_TYPE};
use node_wire::{HttpNodeResult, NODE_EVENT_MEDIA_TYPE};

/// Failures constructing a locally trusted FastVote genesis pin.
#[derive(Debug)]
pub enum FastVoteGenesisTrustError {
    /// The manifest file could not be read or exceeded
    /// [`MAX_GENESIS_MANIFEST_BYTES`].
    Io(std::io::Error),
    /// The manifest bytes were not a valid canonical genesis manifest.
    Decode(node_core::genesis::GenesisError),
    /// The manifest's own commitment digest did not match the caller's
    /// independently trusted expected digest.
    CommitmentMismatch,
    /// The manifest's embedded context did not match the caller's
    /// independently trusted expected chain/protocol/epoch.
    ContextMismatch,
    /// The genesis authority signature failed to verify.
    InvalidSignature,
    /// The embedded validator-set record's context, scheme, or structure
    /// was invalid.
    InvalidValidatorSet(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{TransportError, WireResponse};
    use consensus::encode_fast_vote;
    use ed25519_zebra::{SigningKey, VerificationKey};
    use execution::call::InstanceTarget;
    use execution::paid_execution::{FeeSourceConsent, PaidIntent, ReservationAccessKind};
    use execution::publication::UnverifiedDependencyRef;
    use protocol_types::{ChainId, Epoch, HashAlgorithmId, ProtocolVersion};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn chain() -> ChainId {
        ChainId::new("fastvote-client-test-chain").unwrap()
    }
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(3)
    }
    fn epoch() -> Epoch {
        Epoch::new(9)
    }
    fn test_context() -> PublicationContext {
        PublicationContext::new(chain(), protocol_version(), epoch()).unwrap()
    }

    struct TestSigner {
        id: ValidatorId,
        key: SigningKey,
    }
    impl consensus::ConsensusSigner for TestSigner {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.key.sign(framed).to_bytes().to_vec())
        }
    }
    fn validator(byte: u8) -> (TestSigner, ValidatorInfo) {
        let key = SigningKey::from([byte; 32]);
        let public_key: [u8; 32] = VerificationKey::from(&key).into();
        let id = ValidatorId::new(public_key);
        (
            TestSigner { id, key },
            ValidatorInfo {
                id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key.to_vec(),
            },
        )
    }
    fn four_validators() -> (Vec<TestSigner>, Vec<ValidatorInfo>) {
        let mut signers = Vec::new();
        let mut infos = Vec::new();
        for byte in [1u8, 2, 3, 4] {
            let (signer, info) = validator(byte);
            signers.push(signer);
            infos.push(info);
        }
        (signers, infos)
    }
    fn certifier(infos: Vec<ValidatorInfo>) -> FastPathCertifier {
        FastPathCertifier::new(
            chain(),
            protocol_version(),
            epoch(),
            ValidatorSet::new(epoch(), infos).unwrap(),
        )
        .unwrap()
    }
    fn tx_hash(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }
    fn cast(certifier: &FastPathCertifier, signer: &TestSigner, seed: u8) -> FastVote {
        certifier
            .cast_vote(tx_hash(seed), tx_hash(seed + 1), tx_hash(seed + 2), signer)
            .unwrap()
    }

    /// A transport that returns one fixed scripted response (or error) for
    /// every request it receives, and records how many requests it saw.
    struct ScriptedTransport {
        response: Result<WireResponse, TransportError>,
        calls: AtomicUsize,
    }
    impl ScriptedTransport {
        fn ok(content_type: &'static str, body: Vec<u8>) -> Self {
            Self {
                response: Ok(WireResponse {
                    status: 200,
                    content_type: Some(content_type.to_string()),
                    body,
                }),
                calls: AtomicUsize::new(0),
            }
        }
        fn unreachable() -> Self {
            Self {
                response: Err(TransportError::RequestDeadlineExceeded),
                calls: AtomicUsize::new(0),
            }
        }
    }
    impl Transport for ScriptedTransport {
        fn send(&self, _request: &WireRequest) -> Result<WireResponse, TransportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match &self.response {
                Ok(response) => Ok(WireResponse {
                    status: response.status,
                    content_type: response.content_type.clone(),
                    body: response.body.clone(),
                }),
                Err(_) => Err(TransportError::RequestDeadlineExceeded),
            }
        }
    }

    fn endpoint(
        validator_id: ValidatorId,
        transport: ScriptedTransport,
    ) -> FastVoteEndpoint<ScriptedTransport> {
        FastVoteEndpoint {
            validator_id,
            client: Client::new(transport),
        }
    }

    fn vote_endpoint(
        signer: &TestSigner,
        certifier: &FastPathCertifier,
        seed: u8,
    ) -> FastVoteEndpoint<ScriptedTransport> {
        let vote = cast(certifier, signer, seed);
        endpoint(
            signer.id,
            ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, encode_fast_vote(&vote).unwrap()),
        )
    }

    fn sample_signed_intent(sender: [u8; 32]) -> SignedPaidIntent {
        let context = test_context();
        let intent = PaidIntent {
            context: context.clone(),
            request_id: [0x77; 32],
            sender,
            nonce: 1,
            fee_policy_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
            consent: FeeSourceConsent {
                source: objects::ObjectRef {
                    id: objects::ObjectId::new([0x22; 32]),
                    version: 1,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
                },
                access: ReservationAccessKind::Write,
                max_fee: fees::Amount::new(1),
                refund_recipient: sender,
            },
            application: PaidApplication::Call(execution::call::CallIntent {
                context: context.clone(),
                request_id: [0x77; 32],
                sender,
                nonce: 1,
                code: UnverifiedDependencyRef::new(
                    abi::package_types::PackageOrigin::unverified(
                        context.chain_id().clone(),
                        sender,
                        [0x44; 32],
                    )
                    .unwrap(),
                    1,
                    context.clone(),
                    Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
                )
                .unwrap(),
                instance: InstanceTarget {
                    creator: sender,
                    seed: [0x46; 32],
                    revision: 1,
                    record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x47; 32]),
                },
                entrypoint: "transfer".to_owned(),
                type_arguments: Vec::new(),
                access: abi::AccessManifest::new(),
                arguments: Vec::new(),
                gas_limit: 1,
            }),
            gas_limit: 1,
            authorizations: Vec::new(),
        };
        SignedPaidIntent {
            intent,
            signature: [0xAA; 64],
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn collect_fastvote_certificate_tolerates_a_malicious_first_responder() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        // Endpoint 0 answers first with a well-formed but *foreign* vote
        // (different tx_hash/effects_hash/locked digest), never the honest
        // group's target -- this must not be treated as an authoritative
        // anchor merely for answering first.
        let malicious = vote_endpoint(&signers[0], &certifier, 0x90);
        let honest: Vec<FastVoteEndpoint<ScriptedTransport>> = (1..=3)
            .map(|index| vote_endpoint(&signers[index], &certifier, 0x10))
            .collect();
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> =
            std::iter::once(malicious).chain(honest).collect();

        let signed = sample_signed_intent([0x01; 32]);
        let (certificate, attempts) =
            collect_fastvote_certificate(&endpoints, &certifier, &signed, deadline())
                .unwrap_or_else(|_| panic!("expected a certificate from the 3 honest votes"));

        assert_eq!(attempts.len(), 4);
        assert_eq!(certificate.votes.len(), 3);
        assert_eq!(certificate.tx_hash, tx_hash(0x10));
        for vote in &certificate.votes {
            assert_ne!(vote.validator, signers[0].id);
        }
    }

    #[test]
    fn collect_fastvote_certificate_tolerates_one_unreachable_endpoint() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let mut endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..3)
            .map(|index| vote_endpoint(&signers[index], &certifier, 0x10))
            .collect();
        endpoints.push(endpoint(signers[3].id, ScriptedTransport::unreachable()));

        let signed = sample_signed_intent([0x02; 32]);
        let (certificate, attempts) =
            collect_fastvote_certificate(&endpoints, &certifier, &signed, deadline())
                .unwrap_or_else(|_| panic!("expected a certificate despite one unreachable peer"));

        assert_eq!(certificate.votes.len(), 3);
        let failed = attempts
            .iter()
            .filter(|attempt| attempt.result.is_err())
            .count();
        assert_eq!(failed, 1);
    }

    #[test]
    fn collect_fastvote_certificate_fails_closed_below_quorum() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..2)
            .map(|index| vote_endpoint(&signers[index], &certifier, 0x10))
            .collect();

        let signed = sample_signed_intent([0x03; 32]);
        let error = collect_fastvote_certificate(&endpoints, &certifier, &signed, deadline())
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(
            error,
            FastVoteQuorumError::InsufficientQuorum(failure) if failure.attempts.len() == 2
        ));
    }

    #[test]
    fn collect_fastvote_certificate_rejects_a_vote_claiming_the_wrong_endpoint_identity() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        // Endpoint is *configured* for validator 0's identity, but the vote
        // it actually returns is validator 1's -- a spoofed/misrouted
        // endpoint must never be silently credited to validator 0.
        let vote = cast(&certifier, &signers[1], 0x10);
        let spoofed = endpoint(
            signers[0].id,
            ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, encode_fast_vote(&vote).unwrap()),
        );
        let honest: Vec<FastVoteEndpoint<ScriptedTransport>> = (1..=3)
            .map(|index| vote_endpoint(&signers[index], &certifier, 0x10))
            .collect();
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> =
            std::iter::once(spoofed).chain(honest).collect();

        let signed = sample_signed_intent([0x04; 32]);
        let (_certificate, attempts) =
            collect_fastvote_certificate(&endpoints, &certifier, &signed, deadline()).unwrap();
        let spoofed_attempt = attempts
            .iter()
            .find(|attempt| attempt.validator_id == signers[0].id)
            .unwrap();
        assert!(matches!(
            spoofed_attempt.result,
            Err(ClientError::FastVoteEndpointIdentityMismatch { .. })
        ));
    }

    #[test]
    fn apply_fastvote_to_all_reports_every_endpoint_independently() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = sample_signed_intent([0x05; 32]);
        let votes: Vec<FastVote> = signers[..3]
            .iter()
            .map(|signer| cast(&certifier, signer, 0x10))
            .collect();
        let certificate = certifier
            .try_form_certificate(
                tx_hash(0x10),
                tx_hash(0x11),
                tx_hash(0x12),
                &votes,
                &node_core::fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("3-of-4 quorum");

        // Endpoints 0 and 1 return a well-formed but deliberately
        // unmatchable acknowledgement (a different request id) -- proving
        // each is decoded and validated on its own, independent of the
        // others -- while endpoint 2 is entirely unreachable. No global
        // claim is ever produced: each attempt stands alone.
        let mismatched =
            HttpNodeResult::new(node_core::RequestId::new([0x99; 32]).unwrap(), Vec::new())
                .unwrap();
        let mismatched_body = mismatched.encode().unwrap();
        let mut endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..2)
            .map(|index| {
                endpoint(
                    signers[index].id,
                    ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, mismatched_body.clone()),
                )
            })
            .collect();
        endpoints.push(endpoint(signers[2].id, ScriptedTransport::unreachable()));

        let resolver = hashing::HashSuiteResolver::new(
            chain(),
            protocol_version(),
            vec![protocol_types::HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: protocol_types::HashSuite::genesis(),
            }],
        )
        .unwrap();
        let attempts =
            apply_fastvote_to_all(&endpoints, &signed, &resolver, &certificate, deadline());
        assert_eq!(attempts.len(), 3);
        assert!(matches!(
            attempts[0].result,
            Err(ClientError::SubmitResponseRequestIdMismatch { .. })
        ));
        assert!(matches!(
            attempts[1].result,
            Err(ClientError::SubmitResponseRequestIdMismatch { .. })
        ));
        assert!(matches!(attempts[2].result, Err(ClientError::Transport(_))));
    }
}

impl fmt::Display for FastVoteGenesisTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read genesis manifest: {error}"),
            Self::Decode(error) => write!(f, "invalid genesis manifest: {error}"),
            Self::CommitmentMismatch => {
                f.write_str("genesis manifest commitment does not match the locally trusted expected digest")
            }
            Self::ContextMismatch => f.write_str(
                "genesis manifest context does not match the locally trusted expected chain/protocol/epoch",
            ),
            Self::InvalidSignature => f.write_str("genesis authority signature is invalid"),
            Self::InvalidValidatorSet(reason) => {
                write!(f, "genesis validator set is invalid: {reason}")
            }
        }
    }
}

impl Error for FastVoteGenesisTrustError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

/// Reads and strictly validates a genesis manifest file, trusting it only
/// after its own commitment digest and context match `expected_digest`/
/// `expected_context` exactly and its authority signature verifies. Returns
/// the `consensus::FastPathCertifier` this caller may use to verify votes
/// and form/verify certificates -- the sole, offline, locally pinned source
/// of validator identity and public keys for this network config.
#[allow(clippy::result_large_err)]
pub fn load_trusted_fastvote_genesis(
    manifest_path: &std::path::Path,
    resolver: &hashing::HashSuiteResolver,
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
) -> Result<FastPathCertifier, FastVoteGenesisTrustError> {
    let bytes = read_bounded(manifest_path, MAX_GENESIS_MANIFEST_BYTES)
        .map_err(FastVoteGenesisTrustError::Io)?;
    let manifest: GenesisManifest =
        decode_genesis_manifest(&bytes).map_err(FastVoteGenesisTrustError::Decode)?;
    let digest: Digest32 = genesis_manifest_commitment(resolver, &manifest)
        .map_err(FastVoteGenesisTrustError::Decode)?;
    if digest.bytes() != expected_digest {
        return Err(FastVoteGenesisTrustError::CommitmentMismatch);
    }
    if manifest.context() != expected_context {
        return Err(FastVoteGenesisTrustError::ContextMismatch);
    }
    let verifier = crypto::Ed25519Verifier::from_verifying_key_bytes(&manifest.genesis_authority)
        .map_err(|_| FastVoteGenesisTrustError::InvalidSignature)?;
    let frame =
        genesis_manifest_signing_frame(&manifest).map_err(FastVoteGenesisTrustError::Decode)?;
    use crypto::SignatureVerifier;
    let valid = verifier
        .verify_framed(&frame, &manifest.signature)
        .map_err(|_| FastVoteGenesisTrustError::InvalidSignature)?;
    if !valid {
        return Err(FastVoteGenesisTrustError::InvalidSignature);
    }
    validator_set_from_record(&manifest.validator_set, expected_context).and_then(|validator_set| {
        FastPathCertifier::new(
            expected_context.chain_id().clone(),
            expected_context.protocol_version(),
            expected_context.epoch(),
            validator_set,
        )
        .map_err(|error| FastVoteGenesisTrustError::InvalidValidatorSet(error.to_string()))
    })
}

#[allow(clippy::result_large_err)]
fn validator_set_from_record(
    record: &FastPathValidatorSetRecord,
    expected_context: &PublicationContext,
) -> Result<ValidatorSet, FastVoteGenesisTrustError> {
    if &record.context != expected_context {
        return Err(FastVoteGenesisTrustError::InvalidValidatorSet(
            "validator set record context mismatch".to_string(),
        ));
    }
    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(record.validators.len());
    for validator in &record.validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(FastVoteGenesisTrustError::InvalidValidatorSet(
                "FastVote phase 1 supports only Ed25519 validators".to_string(),
            ));
        }
        info.push(ValidatorInfo {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: validator.signature_scheme,
            public_key: validator.public_key.clone(),
        });
    }
    ValidatorSet::new(expected_context.epoch(), info)
        .map_err(|error| FastVoteGenesisTrustError::InvalidValidatorSet(error.to_string()))
}

fn read_bounded(path: &std::path::Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let cap = u64::try_from(maximum).unwrap_or(u64::MAX);
    let mut buffer = Vec::new();
    file.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)?;
    if buffer.len() > maximum {
        return Err(std::io::Error::other(
            "genesis manifest exceeds the maximum accepted size",
        ));
    }
    Ok(buffer)
}

/// One caller-configured FastVote validator endpoint: a fixed,
/// locally-trusted mapping from a specific transport to the exact validator
/// identity it must speak for (DR-0148 item 3). A returned vote claiming a
/// different `ValidatorId` is rejected before it is ever considered for
/// certificate formation.
pub struct FastVoteEndpoint<T> {
    /// The validator identity this endpoint is configured to speak for.
    pub validator_id: ValidatorId,
    /// The bounded, already-authenticated-transport client for this
    /// endpoint (loopback-plaintext only for local development; TLS with
    /// its own independently configured server name and CA for anything
    /// remote -- this module never mixes trust levels within one network
    /// config).
    pub client: Client<T>,
}

/// One endpoint's outcome from a single collection round.
#[derive(Debug)]
pub struct FastVoteAttempt {
    /// The endpoint's configured validator identity.
    pub validator_id: ValidatorId,
    /// The vote it returned, or why it did not contribute one. A vote whose
    /// own `validator` field disagrees with `validator_id` is reported as
    /// [`ClientError::FastVoteEndpointIdentityMismatch`], not silently
    /// dropped.
    pub result: Result<FastVote, ClientError>,
}

/// Bounded quorum collection failed for every candidate `(tx_hash,
/// execution_effects_hash, locked_objects_digest)` group observed.
#[derive(Debug)]
pub struct FastVoteQuorumFailure {
    /// Every endpoint's own outcome, for honest per-endpoint reporting.
    pub attempts: Vec<FastVoteAttempt>,
}

/// Failure to produce a certificate at all: either the signed intent could
/// not be encoded (a local, pre-network fault) or no candidate vote group
/// reached quorum.
#[derive(Debug)]
pub enum FastVoteQuorumError {
    /// The signed intent failed to encode before any endpoint was contacted.
    Encoding(ClientError),
    /// No candidate `(tx_hash, execution_effects_hash, locked_objects_digest)`
    /// group reached quorum.
    InsufficientQuorum(FastVoteQuorumFailure),
}

/// Sends `signed` to every configured endpoint's `POST
/// /v1/fastvote/prepare` (bounded by `overall_deadline`, the whole
/// operation's wall-clock budget -- not `endpoints.len()` independent
/// per-request timeouts), validates and groups the returned votes, and
/// returns the first group -- in deterministic `(tx_hash,
/// execution_effects_hash, locked_objects_digest)` order -- that reaches
/// `certifier`'s quorum threshold. One unreachable or actively Byzantine
/// endpoint (wrong header, foreign validator identity, or a vote that fails
/// cryptographic verification) never prevents a certificate the remaining
/// honest endpoints' votes still reach quorum for, and never gets treated
/// as an authoritative anchor merely for answering first.
#[allow(clippy::result_large_err)]
pub fn collect_fastvote_certificate<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    signed: &SignedPaidIntent,
    overall_deadline: Instant,
) -> Result<(FastCertificate, Vec<FastVoteAttempt>), FastVoteQuorumError> {
    let signed_bytes = encode_signed_paid_intent(signed)
        .map_err(|error| FastVoteQuorumError::Encoding(error.into()))?;

    let mut attempts: Vec<FastVoteAttempt> = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let now = Instant::now();
        let result = if now >= overall_deadline {
            Err(ClientError::FastVoteOverallDeadlineExceeded)
        } else {
            endpoint
                .client
                .prepare_fastvote(&signed_bytes, Some(overall_deadline))
                .and_then(|vote| {
                    if vote.validator != endpoint.validator_id {
                        Err(ClientError::FastVoteEndpointIdentityMismatch {
                            expected: endpoint.validator_id,
                            actual: vote.validator,
                        })
                    } else {
                        Ok(vote)
                    }
                })
        };
        attempts.push(FastVoteAttempt {
            validator_id: endpoint.validator_id,
            result,
        });
    }

    let mut groups: BTreeMap<(Digest32, Digest32, Digest32), Vec<FastVote>> = BTreeMap::new();
    for attempt in &attempts {
        if let Ok(vote) = &attempt.result {
            groups
                .entry((
                    vote.tx_hash,
                    vote.execution_effects_hash,
                    vote.locked_objects_digest,
                ))
                .or_default()
                .push(vote.clone());
        }
    }
    for ((tx_hash, effects_hash, locked_digest), votes) in groups {
        if let Ok(Some(certificate)) = certifier.try_form_certificate(
            tx_hash,
            effects_hash,
            locked_digest,
            &votes,
            &FastPathEd25519Verifier,
        ) {
            return Ok((certificate, attempts));
        }
    }
    Err(FastVoteQuorumError::InsufficientQuorum(
        FastVoteQuorumFailure { attempts },
    ))
}

/// One endpoint's outcome from a certificate-apply round.
#[derive(Debug)]
pub struct FastVoteApplyAttempt {
    /// The endpoint's configured validator identity.
    pub validator_id: ValidatorId,
    /// The endpoint's own result, or why it failed. A committed
    /// charged-trap result is `Ok` here: it is a valid, applied outcome,
    /// not a transport or protocol failure.
    pub result: Result<PaidExecutionResult, ClientError>,
}

/// Submits the exact signed intent and certificate bytes to every
/// configured endpoint's `POST /v1/fastvote/certificates`, bounded by
/// `overall_deadline`. Reports only the acknowledgements actually received
/// per known endpoint: it never infers or claims that an endpoint this call
/// did not hear back from also applied the certificate, and it never
/// aggregates these into one invented "all validators" or "durable/final"
/// claim -- each `FastVoteApplyAttempt` stands on its own.
pub fn apply_fastvote_to_all<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    signed: &SignedPaidIntent,
    resolver: &hashing::HashSuiteResolver,
    certificate: &FastCertificate,
    overall_deadline: Instant,
) -> Vec<FastVoteApplyAttempt> {
    let certificate_bytes = match encode_fast_certificate(certificate) {
        Ok(bytes) => bytes,
        Err(error) => {
            return endpoints
                .iter()
                .map(|endpoint| FastVoteApplyAttempt {
                    validator_id: endpoint.validator_id,
                    result: Err(ClientError::FastVoteConsensus(error.clone())),
                })
                .collect();
        }
    };
    endpoints
        .iter()
        .map(|endpoint| {
            let now = Instant::now();
            let result = if now >= overall_deadline {
                Err(ClientError::FastVoteOverallDeadlineExceeded)
            } else {
                endpoint.client.apply_fastvote(
                    signed,
                    resolver,
                    &certificate_bytes,
                    Some(overall_deadline),
                )
            };
            FastVoteApplyAttempt {
                validator_id: endpoint.validator_id,
                result,
            }
        })
        .collect()
}

impl<T: Transport> Client<T> {
    /// `POST /v1/fastvote/prepare`: submits exact signed paid-intent bytes
    /// and returns the endpoint's own [`FastVote`]. Does not verify the
    /// vote against any validator set; callers pass the response to
    /// [`collect_fastvote_certificate`] (or their own equivalent) for that.
    pub fn prepare_fastvote(
        &self,
        signed_bytes: &[u8],
        deadline: Option<Instant>,
    ) -> Result<FastVote, ClientError> {
        let request = WireRequest {
            method: Method::Post,
            path: FASTVOTE_PREPARE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: signed_bytes.to_vec(),
            deadline,
        };
        let response = self.transport().send(&request)?;
        let body = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        decode_fast_vote(&body).map_err(ClientError::FastVoteConsensus)
    }

    /// `POST /v1/fastvote/certificates`: submits the exact signed intent
    /// (which must carry [`PaidApplication::Call`] -- DR-0130 fast-path
    /// phase 1's only supported application) and certificate bytes, and
    /// returns the bound [`PaidExecutionResult`] after the same
    /// acknowledgement-binding checks [`Client::submit_paid_execution`]
    /// performs for the direct path.
    pub fn apply_fastvote(
        &self,
        signed: &SignedPaidIntent,
        resolver: &hashing::HashSuiteResolver,
        certificate_bytes: &[u8],
        deadline: Option<Instant>,
    ) -> Result<PaidExecutionResult, ClientError> {
        let PaidApplication::Call(call) = &signed.intent.application else {
            return Err(ClientError::FastVoteUnsupportedApplication);
        };
        let signed_bytes = encode_signed_paid_intent(signed)?;
        let apply_request = FastVoteApplyRequest {
            signed_paid_intent: signed_bytes,
            certificate: certificate_bytes.to_vec(),
        };
        let body = apply_request
            .encode()
            .map_err(ClientError::FastVoteApplyRequestWire)?;
        let request = WireRequest {
            method: Method::Post,
            path: FASTVOTE_CERTIFICATES_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        };
        let response = self.transport().send(&request)?;
        let response_body = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let outer: HttpNodeResult = HttpNodeResult::decode(&response_body)?;
        let expected_request_id: RequestId = RequestId::new(signed.intent.request_id)?;
        if outer.request_id() != expected_request_id {
            return Err(ClientError::SubmitResponseRequestIdMismatch {
                expected: expected_request_id,
                actual: outer.request_id(),
            });
        }
        let [ack] = outer.responses() else {
            return Err(ClientError::PaidExecutionAcknowledgementMismatch);
        };
        let payload = ack
            .payload()
            .ok_or(ClientError::PaidExecutionAcknowledgementMismatch)?;
        let result: PaidExecutionResult = decode_paid_execution_result(payload)?;
        if ack.request_id() != expected_request_id || result.request_id != signed.intent.request_id
        {
            return Err(ClientError::PaidExecutionAcknowledgementMismatch);
        }
        let expected_status = if result.status == PaidExecutionStatus::Success {
            node_core::NodeResponseStatus::Accepted
        } else {
            node_core::NodeResponseStatus::Rejected
        };
        if ack.status() != expected_status {
            return Err(ClientError::PaidExecutionAcknowledgementMismatch);
        }
        match (&result.kind, &result.target) {
            (PaidResultKind::Call, PaidResultTarget::Instance(record))
                if instance_target(resolver, record)
                    .map(|target| target == call.instance)
                    .unwrap_or(false) => {}
            _ => return Err(ClientError::PaidExecutionAcknowledgementMismatch),
        }
        Ok(result)
    }
}
