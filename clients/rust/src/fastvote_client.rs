//! Certified-only FastVote network client (DR-0148).
//!
//! This module is the client-side half of `native-http::fastvote`: it sends
//! an already-built, already-signed ordinary paid `Call` to every configured
//! validator's `POST /v1/fastvote/prepare`, forms a canonical
//! `consensus::FastCertificate` locally from the returned votes using the
//! LOCAL, offline-pinned genesis validator set (never a set fetched live
//! from any server), and submits `POST /v1/fastvote/certificates`.
//!
//! Trust boundaries this module enforces, none of which a remote endpoint or
//! network observer can weaken:
//!
//! * [`load_trusted_fastvote_genesis`] only trusts a genesis manifest file
//!   after its exact commitment digest, embedded context, and authority
//!   signature all match a caller-supplied expected digest/context --
//!   exactly [`node_core::genesis`]'s own production trust model, reused
//!   unchanged. The [`validator_set::ValidatorSet`]/[`consensus::FastPathCertifier`]
//!   this produces is the sole source of truth for which `ValidatorId`s and
//!   public keys exist; nothing here ever substitutes a value from a live
//!   `/v1/context` or similar response.
//! * [`validate_fastvote_endpoints`] is required, bounded, library-enforced
//!   preflight (not merely a CLI convention): it rejects more than
//!   [`MAX_FASTVOTE_NETWORK_ENDPOINTS`] configured endpoints, a duplicate
//!   `ValidatorId` or duplicate configured endpoint label (so distinct
//!   `Client`s can never manufacture two "independent" votes for one
//!   member), and any configured `ValidatorId` absent from the local pin.
//!   [`collect_fastvote_certificate`] and [`apply_fastvote_to_all`] both run
//!   it themselves, before any network I/O, so a caller cannot accidentally
//!   skip it.
//! * [`collect_fastvote_certificate`] authenticates the exact signed bytes
//!   against the certifier's own pinned chain/protocol/epoch context (the
//!   same [`execution::paid_execution::authenticate_paid_intent`] production
//!   authentication path, not a reimplementation) and independently
//!   computes this exact intent's `tx_hash` via
//!   [`execution::paid_execution::paid_invocation_digest`] *before* any
//!   endpoint is contacted. Every returned vote is then individually
//!   verified -- endpoint identity match, exact expected `tx_hash`, and
//!   `consensus::FastPathCertifier::verify_vote` cryptographic validity --
//!   and marked as a failed attempt (never silently dropped, never reported
//!   as a valid vote) the moment any one of those checks fails. Only votes
//!   that pass every check are grouped by their own `(execution_effects_hash,
//!   locked_objects_digest)` pair, and every group -- not only the first --
//!   is independently offered to
//!   [`consensus::FastPathCertifier::try_form_certificate`], so one
//!   unavailable or actively Byzantine endpoint (wrong transaction, foreign
//!   validator, invalid signature, or a disagreeing effects hash for the
//!   *same* transaction) can neither block a certificate the remaining
//!   honest endpoints' votes still reach quorum for, nor be miscounted
//!   toward it.
//! * [`apply_fastvote_to_all`] independently re-verifies the exact
//!   certificate against the pinned certifier (`verify_certificate`) and
//!   confirms its `tx_hash` matches this exact submitted intent's own digest
//!   *before* any endpoint is contacted -- it never relies on an endpoint's
//!   own (untrusted) response to reject a bad certificate after the fact.
//! * Both collection phases share one caller-supplied whole-workflow
//!   deadline (covering every phase of one network operation, not a freshly
//!   replenished budget per phase) and bound every individual endpoint
//!   request to `min(remaining whole-workflow budget, per_request_cap)`, so
//!   one stalled or unreachable first peer can consume at most
//!   `per_request_cap` of the shared budget before the remaining
//!   independent peers get their turn.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::time::{Duration, Instant};

use consensus::{
    FastCertificate, FastPathCertifier, FastVote, decode_fast_vote, encode_fast_certificate,
};
use execution::local_execution::instance_target;
use execution::paid_execution::{
    PaidApplication, PaidExecutionResult, PaidExecutionStatus, PaidResultKind, PaidResultTarget,
    SignedPaidIntent, authenticate_paid_intent, decode_paid_execution_result,
    encode_signed_paid_intent, paid_invocation_digest,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
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

/// Bounded fan-out cap for one configured FastVote network: a caller-side
/// resource bound, not a protocol quorum limit (`validator_set` may still
/// carry up to `node_core::fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS`
/// members; this crate simply never dials more than this many at once).
pub const MAX_FASTVOTE_NETWORK_ENDPOINTS: usize = 32;

/// Maximum accepted per-request timeout cap for FastVote endpoint calls.
///
/// This is a client operational resource bound, not a protocol latency target
/// or evidence of network readiness. The caller's remaining whole-operation
/// deadline can further shorten every request.
pub const MAX_FASTVOTE_PER_REQUEST_CAP: Duration = Duration::from_secs(300);

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

impl fmt::Display for FastVoteGenesisTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read genesis manifest: {error}"),
            Self::Decode(error) => write!(f, "invalid genesis manifest: {error}"),
            Self::CommitmentMismatch => f.write_str(
                "genesis manifest commitment does not match the locally trusted expected digest",
            ),
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
    resolver: &HashSuiteResolver,
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
/// certificate formation. `endpoint_label` is an opaque, caller-chosen
/// string identifying the configured connection target (for example
/// `"host:port"` or a DNS name) used only to detect a caller mistake that
/// configured the same physical endpoint twice under two different
/// validator identities; it is never parsed or dialed by this crate.
pub struct FastVoteEndpoint<T> {
    /// The validator identity this endpoint is configured to speak for.
    pub validator_id: ValidatorId,
    /// Caller-chosen label identifying this endpoint's configured
    /// connection target, used only for duplicate-endpoint detection.
    pub endpoint_label: String,
    /// The bounded, already-authenticated-transport client for this
    /// endpoint (loopback-plaintext only for local development; TLS with
    /// its own independently configured server name and CA for anything
    /// remote -- this module never mixes trust levels within one network
    /// config).
    pub client: Client<T>,
}

/// Fail-closed configuration errors [`validate_fastvote_endpoints`] rejects
/// before any network I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastVoteEndpointConfigError {
    /// No endpoints were configured.
    NoEndpoints,
    /// More than [`MAX_FASTVOTE_NETWORK_ENDPOINTS`] endpoints were configured.
    TooManyEndpoints {
        /// Number of endpoints the caller configured.
        configured: usize,
        /// The bounded maximum.
        maximum: usize,
    },
    /// Two configured endpoints share the same `ValidatorId`.
    DuplicateValidatorId(ValidatorId),
    /// Two configured endpoints share the same `endpoint_label`.
    DuplicateEndpointLabel(String),
    /// A configured `ValidatorId` is not a member of the locally pinned
    /// validator set.
    UnknownValidator(ValidatorId),
}

impl fmt::Display for FastVoteEndpointConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEndpoints => f.write_str("no FastVote endpoints were configured"),
            Self::TooManyEndpoints {
                configured,
                maximum,
            } => write!(
                f,
                "{configured} FastVote endpoints were configured, maximum is {maximum}"
            ),
            Self::DuplicateValidatorId(id) => {
                write!(f, "duplicate configured FastVote validator identity {id}")
            }
            Self::DuplicateEndpointLabel(label) => {
                write!(f, "duplicate configured FastVote endpoint label {label:?}")
            }
            Self::UnknownValidator(id) => write!(
                f,
                "configured FastVote validator {id} is not a member of the locally pinned validator set"
            ),
        }
    }
}

impl Error for FastVoteEndpointConfigError {}

/// Required, bounded preflight over a configured FastVote endpoint set,
/// checked before any network I/O (and before signing, when called from a
/// caller that has not yet signed anything): endpoint count is bounded,
/// every `ValidatorId` and `endpoint_label` is distinct, and every
/// configured `ValidatorId` is an actual member of `certifier`'s locally
/// pinned validator set. [`collect_fastvote_certificate`] and
/// [`apply_fastvote_to_all`] both call this themselves as their first step,
/// so a library caller cannot accidentally bypass it, but a CLI should also
/// call it immediately after loading its network config, before building or
/// signing anything.
pub fn validate_fastvote_endpoints<T>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
) -> Result<(), FastVoteEndpointConfigError> {
    if endpoints.is_empty() {
        return Err(FastVoteEndpointConfigError::NoEndpoints);
    }
    if endpoints.len() > MAX_FASTVOTE_NETWORK_ENDPOINTS {
        return Err(FastVoteEndpointConfigError::TooManyEndpoints {
            configured: endpoints.len(),
            maximum: MAX_FASTVOTE_NETWORK_ENDPOINTS,
        });
    }
    let mut seen_ids: BTreeSet<ValidatorId> = BTreeSet::new();
    let mut seen_labels: BTreeSet<&str> = BTreeSet::new();
    for endpoint in endpoints {
        if !seen_ids.insert(endpoint.validator_id) {
            return Err(FastVoteEndpointConfigError::DuplicateValidatorId(
                endpoint.validator_id,
            ));
        }
        if !seen_labels.insert(endpoint.endpoint_label.as_str()) {
            return Err(FastVoteEndpointConfigError::DuplicateEndpointLabel(
                endpoint.endpoint_label.clone(),
            ));
        }
        if certifier
            .validator_set()
            .get(endpoint.validator_id)
            .is_none()
        {
            return Err(FastVoteEndpointConfigError::UnknownValidator(
                endpoint.validator_id,
            ));
        }
    }
    Ok(())
}

/// A local, pre-network failure: bad endpoint configuration, or the signed
/// intent itself failed to encode, authenticate, or hash.
#[derive(Debug)]
pub enum FastVoteNetworkError {
    /// [`validate_fastvote_endpoints`] rejected the configured endpoint set.
    EndpointConfig(FastVoteEndpointConfigError),
    /// The caller-supplied per-request timeout cap was zero.
    ZeroPerRequestCap,
    /// The caller-supplied per-request timeout cap exceeded [`MAX_FASTVOTE_PER_REQUEST_CAP`].
    ExcessivePerRequestCap {
        /// The configured cap.
        configured: Duration,
        /// The bounded maximum.
        maximum: Duration,
    },
    /// The caller-supplied overall deadline has already elapsed before network operations began.
    OverallDeadlineElapsed,
    /// Computing the bounded request deadline overflowed.
    DeadlineOverflow,
    /// Encoding, authenticating, or hashing the signed intent (or
    /// verifying a certificate) failed before any endpoint was contacted.
    Preflight(ClientError),
}

impl fmt::Display for FastVoteNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointConfig(error) => write!(f, "FastVote endpoint configuration: {error}"),
            Self::ZeroPerRequestCap => {
                f.write_str("FastVote per-request timeout cap cannot be zero")
            }
            Self::ExcessivePerRequestCap {
                configured,
                maximum,
            } => write!(
                f,
                "FastVote per-request timeout cap {configured:?} exceeds maximum {maximum:?}"
            ),
            Self::OverallDeadlineElapsed => {
                f.write_str("FastVote overall deadline has already elapsed")
            }
            Self::DeadlineOverflow => {
                f.write_str("FastVote bounded deadline calculation overflowed")
            }
            Self::Preflight(error) => write!(f, "FastVote preflight: {error}"),
        }
    }
}

impl Error for FastVoteNetworkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EndpointConfig(error) => Some(error),
            Self::Preflight(error) => Some(error),
            Self::ZeroPerRequestCap
            | Self::ExcessivePerRequestCap { .. }
            | Self::OverallDeadlineElapsed
            | Self::DeadlineOverflow => None,
        }
    }
}

impl From<FastVoteEndpointConfigError> for FastVoteNetworkError {
    fn from(value: FastVoteEndpointConfigError) -> Self {
        Self::EndpointConfig(value)
    }
}

impl From<ClientError> for FastVoteNetworkError {
    fn from(value: ClientError) -> Self {
        Self::Preflight(value)
    }
}

/// One endpoint's outcome from a single collection round.
#[derive(Debug)]
pub struct FastVoteAttempt {
    /// The endpoint's configured validator identity.
    pub validator_id: ValidatorId,
    /// The vote it returned, or why it did not contribute one. A vote whose
    /// own `validator` disagrees with `validator_id`
    /// ([`ClientError::FastVoteEndpointIdentityMismatch`]), whose `tx_hash`
    /// disagrees with this exact submitted intent's digest
    /// ([`ClientError::FastVoteUnexpectedTransaction`]), or that fails
    /// cryptographic verification against the pinned validator set
    /// ([`ClientError::FastVoteConsensus`]) is reported as that exact error,
    /// never silently dropped and never reported as a valid vote.
    pub result: Result<FastVote, ClientError>,
}

/// Bounded quorum collection failed for every candidate `(execution_effects_hash,
/// locked_objects_digest)` group observed among the votes that passed
/// individual verification.
#[derive(Debug)]
pub struct FastVoteQuorumFailure {
    /// Every endpoint's own outcome, for honest per-endpoint reporting.
    pub attempts: Vec<FastVoteAttempt>,
}

/// Failure to produce a certificate at all: local preflight, or no
/// candidate vote group reached quorum.
#[derive(Debug)]
pub enum FastVoteQuorumError {
    /// A local, pre-network failure (see [`FastVoteNetworkError`]).
    Network(FastVoteNetworkError),
    /// No candidate `(execution_effects_hash, locked_objects_digest)` group,
    /// among individually verified votes for this exact transaction, reached
    /// quorum.
    InsufficientQuorum(FastVoteQuorumFailure),
}

impl From<FastVoteNetworkError> for FastVoteQuorumError {
    fn from(value: FastVoteNetworkError) -> Self {
        Self::Network(value)
    }
}

impl From<FastVoteEndpointConfigError> for FastVoteQuorumError {
    fn from(value: FastVoteEndpointConfigError) -> Self {
        Self::Network(FastVoteNetworkError::EndpointConfig(value))
    }
}

/// Returns `min(overall_deadline, now + per_request_cap)`: one endpoint
/// request is bounded by whatever remains of the shared whole-workflow
/// budget *and* by an independently configured per-request ceiling, so one
/// stalled peer can never consume more than `per_request_cap` of the shared
/// budget before the next independent peer gets its turn.
///
/// Validates that `per_request_cap` is non-zero and within
/// [`MAX_FASTVOTE_PER_REQUEST_CAP`], and that `overall_deadline` has not
/// already elapsed.  Uses checked addition to prevent arithmetic overflow.
// Keep the same typed preflight error as collection/apply for caller diagnostics.
#[allow(clippy::result_large_err)]
fn bounded_deadline(
    overall_deadline: Instant,
    per_request_cap: Duration,
) -> Result<Instant, FastVoteNetworkError> {
    if per_request_cap.is_zero() {
        return Err(FastVoteNetworkError::ZeroPerRequestCap);
    }
    if per_request_cap > MAX_FASTVOTE_PER_REQUEST_CAP {
        return Err(FastVoteNetworkError::ExcessivePerRequestCap {
            configured: per_request_cap,
            maximum: MAX_FASTVOTE_PER_REQUEST_CAP,
        });
    }
    let now = Instant::now();
    if now >= overall_deadline {
        return Err(FastVoteNetworkError::OverallDeadlineElapsed);
    }
    let per_request_deadline = now
        .checked_add(per_request_cap)
        .ok_or(FastVoteNetworkError::DeadlineOverflow)?;
    Ok(overall_deadline.min(per_request_deadline))
}

/// Sends `signed` to every configured endpoint's `POST
/// /v1/fastvote/prepare`, individually verifies every returned vote, groups
/// only the votes that pass verification, and returns the first group -- in
/// deterministic `(execution_effects_hash, locked_objects_digest)` order --
/// that reaches `certifier`'s quorum threshold for this exact transaction.
///
/// `overall_deadline` is the shared whole-workflow budget (covering this
/// call, any earlier preparatory reads the caller already spent time on, and
/// the later [`apply_fastvote_to_all`] call); `per_request_cap` bounds any
/// single endpoint request independently of how much of that budget remains.
#[allow(clippy::result_large_err)]
pub fn collect_fastvote_certificate<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    signed: &SignedPaidIntent,
    overall_deadline: Instant,
    per_request_cap: Duration,
) -> Result<(FastCertificate, Vec<FastVoteAttempt>), FastVoteQuorumError> {
    validate_fastvote_endpoints(endpoints, certifier)?;
    bounded_deadline(overall_deadline, per_request_cap)?;

    let expected_context = PublicationContext::new(
        certifier.chain_id().clone(),
        certifier.protocol_version(),
        certifier.epoch(),
    )
    .map_err(|error| FastVoteNetworkError::Preflight(error.into()))?;
    let signed_bytes = encode_signed_paid_intent(signed)
        .map_err(|error| FastVoteNetworkError::Preflight(error.into()))?;
    // Authenticate the exact bytes this call is about to submit against the
    // certifier's own pinned context, using the same production
    // authentication path `fast_path::prepare` itself uses -- before any
    // endpoint is contacted. This proves the intent this caller believes it
    // is submitting is genuinely signed and addressed to this exact pinned
    // chain/protocol/epoch; it does not authenticate the network responses,
    // which are checked per vote below.
    authenticate_paid_intent(resolver, &expected_context, &signed_bytes)
        .map_err(|error| FastVoteNetworkError::Preflight(error.into()))?;
    let expected_tx_hash: Digest32 = paid_invocation_digest(resolver, signed)
        .map_err(|error| FastVoteNetworkError::Preflight(error.into()))?;

    let mut attempts: Vec<FastVoteAttempt> = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let result = match bounded_deadline(overall_deadline, per_request_cap) {
            Err(_) => Err(ClientError::FastVoteOverallDeadlineExceeded),
            Ok(deadline) => endpoint
                .client
                .prepare_fastvote(&signed_bytes, Some(deadline))
                .and_then(|vote| {
                    if vote.validator != endpoint.validator_id {
                        return Err(ClientError::FastVoteEndpointIdentityMismatch {
                            expected: endpoint.validator_id,
                            actual: vote.validator,
                        });
                    }
                    if vote.tx_hash != expected_tx_hash {
                        return Err(ClientError::FastVoteUnexpectedTransaction {
                            expected: expected_tx_hash,
                            actual: vote.tx_hash,
                        });
                    }
                    certifier
                        .verify_vote(&vote, &FastPathEd25519Verifier)
                        .map_err(ClientError::FastVoteConsensus)?;
                    Ok(vote)
                }),
        };
        attempts.push(FastVoteAttempt {
            validator_id: endpoint.validator_id,
            result,
        });
    }

    let mut groups: BTreeMap<(Digest32, Digest32), Vec<FastVote>> = BTreeMap::new();
    for attempt in &attempts {
        if let Ok(vote) = &attempt.result {
            groups
                .entry((vote.execution_effects_hash, vote.locked_objects_digest))
                .or_default()
                .push(vote.clone());
        }
    }
    for ((effects_hash, locked_digest), votes) in groups {
        if let Ok(Some(certificate)) = certifier.try_form_certificate(
            expected_tx_hash,
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

/// Independently re-verifies `certificate` against `certifier` (the local
/// pin) and against this exact `signed` intent's own digest, then submits
/// the exact signed intent and certificate bytes to every configured
/// endpoint's `POST /v1/fastvote/certificates`, bounded by the same
/// whole-workflow `overall_deadline`/`per_request_cap` contract as
/// [`collect_fastvote_certificate`]. This never trusts an endpoint's
/// response to reject a bad certificate after the fact: a certificate that
/// does not verify, or that certifies a different transaction than `signed`,
/// is rejected before any endpoint is contacted, exactly like a caller that
/// loaded a possibly-stale or tampered certificate artifact from disk for a
/// replay would need.
///
/// Reports only the acknowledgements actually received per known endpoint:
/// it never infers or claims that an endpoint this call did not hear back
/// from also applied the certificate, and it never aggregates these into one
/// invented "all validators" or "durable/final" claim -- each
/// `FastVoteApplyAttempt` stands on its own.
#[allow(clippy::result_large_err)]
pub fn apply_fastvote_to_all<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    signed: &SignedPaidIntent,
    resolver: &HashSuiteResolver,
    certificate: &FastCertificate,
    overall_deadline: Instant,
    per_request_cap: Duration,
) -> Result<Vec<FastVoteApplyAttempt>, FastVoteNetworkError> {
    validate_fastvote_endpoints(endpoints, certifier)?;
    bounded_deadline(overall_deadline, per_request_cap)?;
    let expected_tx_hash: Digest32 =
        paid_invocation_digest(resolver, signed).map_err(ClientError::from)?;
    if certificate.tx_hash != expected_tx_hash {
        return Err(FastVoteNetworkError::Preflight(
            ClientError::FastVoteUnexpectedTransaction {
                expected: expected_tx_hash,
                actual: certificate.tx_hash,
            },
        ));
    }
    certifier
        .verify_certificate(certificate, &FastPathEd25519Verifier)
        .map_err(ClientError::from)?;
    let certificate_bytes = encode_fast_certificate(certificate).map_err(ClientError::from)?;

    let mut attempts: Vec<FastVoteApplyAttempt> = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let result = match bounded_deadline(overall_deadline, per_request_cap) {
            Err(_) => Err(ClientError::FastVoteOverallDeadlineExceeded),
            Ok(deadline) => {
                endpoint
                    .client
                    .apply_fastvote(signed, resolver, &certificate_bytes, Some(deadline))
            }
        };
        attempts.push(FastVoteApplyAttempt {
            validator_id: endpoint.validator_id,
            result,
        });
    }
    Ok(attempts)
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
        resolver: &HashSuiteResolver,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::LocalSigner;
    use crate::transport::{TransportError, WireResponse};
    use consensus::ConsensusError;
    use consensus::encode_fast_vote;
    use crypto::SignatureSigner;
    use ed25519_zebra::{SigningKey, VerificationKey};
    use execution::call::InstanceTarget;
    use execution::paid_execution::{
        FeeSourceConsent, PaidIntent, ReservationAccessKind, paid_intent_signing_frame,
    };
    use execution::publication::UnverifiedDependencyRef;
    use protocol_types::{ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn chain() -> ChainId {
        ChainId::new("fastvote-client-test-chain").unwrap()
    }
    fn protocol_version() -> protocol_types::ProtocolVersion {
        protocol_types::ProtocolVersion::new(3)
    }
    fn epoch() -> Epoch {
        Epoch::new(9)
    }
    fn test_context() -> PublicationContext {
        PublicationContext::new(chain(), protocol_version(), epoch()).unwrap()
    }
    fn resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            chain(),
            protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
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
    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }
    fn cast_for(
        certifier: &FastPathCertifier,
        signer: &TestSigner,
        tx_hash: Digest32,
        seed: u8,
    ) -> FastVote {
        certifier
            .cast_vote(tx_hash, digest(seed), digest(seed.wrapping_add(1)), signer)
            .unwrap()
    }

    /// Builds a real, fully authenticatable, sender-signed `transfer`
    /// `SignedPaidIntent` -- the same shape the CLI's paid-call path builds
    /// -- so tests exercise real signature verification and real
    /// `paid_invocation_digest` values instead of an unrelated fixed digest.
    fn signed_transfer(sender_seed: u8, request_id: [u8; 32]) -> SignedPaidIntent {
        let signer = LocalSigner::from_seed([sender_seed; 32]);
        let context = test_context();
        let sender = *signer.address().as_bytes();
        let intent = PaidIntent {
            context: context.clone(),
            request_id,
            sender,
            nonce: 1,
            fee_policy_digest: digest(0x11),
            consent: FeeSourceConsent {
                source: objects::ObjectRef {
                    id: objects::ObjectId::new([0x22; 32]),
                    version: 1,
                    digest: digest(0x33),
                },
                access: ReservationAccessKind::Write,
                max_fee: fees::Amount::new(1),
                refund_recipient: sender,
            },
            application: PaidApplication::Call(execution::call::CallIntent {
                context: context.clone(),
                request_id,
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
                    digest(0x45),
                )
                .unwrap(),
                instance: InstanceTarget {
                    creator: sender,
                    seed: [0x46; 32],
                    revision: 1,
                    record_digest: digest(0x47),
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
        let frame = paid_intent_signing_frame(&context, &intent).unwrap();
        let signature_bytes = signer.sign_framed(&frame).unwrap();
        let signature: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
        SignedPaidIntent { intent, signature }
    }

    fn expected_tx_hash(signed: &SignedPaidIntent) -> Digest32 {
        paid_invocation_digest(&resolver(), signed).unwrap()
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

    /// A transport that sleeps until exactly the caller-supplied per-request
    /// deadline (proving the deadline it was actually handed is bounded, not
    /// the whole-workflow deadline) and then fails, recording the deadline
    /// it observed for the test to assert against.
    struct RecordingSlowTransport {
        seen_deadline: Mutex<Option<Instant>>,
    }
    impl Transport for Arc<RecordingSlowTransport> {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            *self.seen_deadline.lock().unwrap() = request.deadline;
            if let Some(deadline) = request.deadline {
                let now = Instant::now();
                if deadline > now {
                    std::thread::sleep(deadline - now);
                }
            }
            Err(TransportError::RequestDeadlineExceeded)
        }
    }

    fn endpoint(
        validator_id: ValidatorId,
        label: &str,
        transport: ScriptedTransport,
    ) -> FastVoteEndpoint<ScriptedTransport> {
        FastVoteEndpoint {
            validator_id,
            endpoint_label: label.to_string(),
            client: Client::new(transport),
        }
    }

    fn vote_endpoint(
        signer: &TestSigner,
        label: &str,
        certifier: &FastPathCertifier,
        tx_hash: Digest32,
        seed: u8,
    ) -> FastVoteEndpoint<ScriptedTransport> {
        let vote = cast_for(certifier, signer, tx_hash, seed);
        endpoint(
            signer.id,
            label,
            ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, encode_fast_vote(&vote).unwrap()),
        )
    }

    const CAP: Duration = Duration::from_secs(5);
    fn deadline() -> Instant {
        Instant::now() + CAP
    }

    #[test]
    fn collect_fastvote_certificate_tolerates_a_same_header_invalid_signature_malicious_first_responder()
     {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(1, [0x10; 32]);
        let tx_hash = expected_tx_hash(&signed);

        // Endpoint 0 answers first with a *tampered* signature over the
        // exact same header (tx_hash/effects_hash/locked_objects_digest)
        // the 3 honest votes below use -- not a different, easily-grouped-
        // away transaction. This must be individually rejected as an
        // invalid vote, never silently excluded-as-if-valid nor allowed to
        // poison the honest group.
        let mut tampered = cast_for(&certifier, &signers[0], tx_hash, 0x10);
        tampered.signature[0] ^= 0xFF;
        let malicious = endpoint(
            signers[0].id,
            "peer-0",
            ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, encode_fast_vote(&tampered).unwrap()),
        );
        let honest: Vec<FastVoteEndpoint<ScriptedTransport>> = (1..=3)
            .map(|index| {
                vote_endpoint(
                    &signers[index],
                    &format!("peer-{index}"),
                    &certifier,
                    tx_hash,
                    0x10,
                )
            })
            .collect();
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> =
            std::iter::once(malicious).chain(honest).collect();

        let (certificate, attempts) = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            CAP,
        )
        .unwrap_or_else(|_| panic!("expected a certificate from the 3 honest votes"));

        assert_eq!(attempts.len(), 4);
        assert!(matches!(
            attempts[0].result,
            Err(ClientError::FastVoteConsensus(ConsensusError::InvalidSignature(id))) if id == signers[0].id
        ));
        assert_eq!(certificate.votes.len(), 3);
        for vote in &certificate.votes {
            assert_ne!(vote.validator, signers[0].id);
        }
    }

    #[test]
    fn collect_fastvote_certificate_rejects_a_fully_valid_quorum_for_an_unrelated_transaction() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(2, [0x20; 32]);
        let unrelated = signed_transfer(3, [0x21; 32]);
        let unrelated_tx_hash = expected_tx_hash(&unrelated);
        assert_ne!(unrelated_tx_hash, expected_tx_hash(&signed));

        // Every endpoint returns a fully valid, correctly self-identified,
        // quorum-forming vote set -- but for `unrelated`, not `signed`. This
        // must never be accepted as this call's certificate merely because
        // the votes are individually genuine.
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..4)
            .map(|index| {
                vote_endpoint(
                    &signers[index],
                    &format!("peer-{index}"),
                    &certifier,
                    unrelated_tx_hash,
                    0x30,
                )
            })
            .collect();

        let error = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            CAP,
        )
        .map(|_| ())
        .unwrap_err();
        let FastVoteQuorumError::InsufficientQuorum(failure) = error else {
            panic!("expected InsufficientQuorum, not a certificate for an unrelated transaction");
        };
        assert_eq!(failure.attempts.len(), 4);
        for attempt in &failure.attempts {
            assert!(matches!(
                attempt.result,
                Err(ClientError::FastVoteUnexpectedTransaction { .. })
            ));
        }
    }

    #[test]
    fn collect_fastvote_certificate_tolerates_one_unreachable_endpoint() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(4, [0x30; 32]);
        let tx_hash = expected_tx_hash(&signed);
        let mut endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..3)
            .map(|index| {
                vote_endpoint(
                    &signers[index],
                    &format!("peer-{index}"),
                    &certifier,
                    tx_hash,
                    0x10,
                )
            })
            .collect();
        endpoints.push(endpoint(
            signers[3].id,
            "peer-3",
            ScriptedTransport::unreachable(),
        ));

        let (certificate, attempts) = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            CAP,
        )
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
        let signed = signed_transfer(5, [0x40; 32]);
        let tx_hash = expected_tx_hash(&signed);
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..2)
            .map(|index| {
                vote_endpoint(
                    &signers[index],
                    &format!("peer-{index}"),
                    &certifier,
                    tx_hash,
                    0x10,
                )
            })
            .collect();

        let error = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            CAP,
        )
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
        let signed = signed_transfer(6, [0x50; 32]);
        let tx_hash = expected_tx_hash(&signed);
        // Endpoint is *configured* for validator 0's identity, but the vote
        // it actually returns is validator 1's -- a spoofed/misrouted
        // endpoint must never be silently credited to validator 0.
        let vote = cast_for(&certifier, &signers[1], tx_hash, 0x10);
        let spoofed = endpoint(
            signers[0].id,
            "peer-0",
            ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, encode_fast_vote(&vote).unwrap()),
        );
        let honest: Vec<FastVoteEndpoint<ScriptedTransport>> = (1..=3)
            .map(|index| {
                vote_endpoint(
                    &signers[index],
                    &format!("peer-{index}"),
                    &certifier,
                    tx_hash,
                    0x10,
                )
            })
            .collect();
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> =
            std::iter::once(spoofed).chain(honest).collect();

        let (_certificate, attempts) = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            CAP,
        )
        .unwrap();
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
    fn collect_fastvote_certificate_bounds_a_slow_first_peer_to_the_per_request_cap_and_still_reaches_quorum()
     {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(7, [0x60; 32]);
        let tx_hash = expected_tx_hash(&signed);
        let per_request_cap = Duration::from_millis(150);
        let overall = Instant::now() + Duration::from_secs(5);

        let slow = Arc::new(RecordingSlowTransport {
            seen_deadline: Mutex::new(None),
        });
        let mut endpoints: Vec<FastVoteEndpoint<MixedTransport>> = vec![FastVoteEndpoint {
            validator_id: signers[0].id,
            endpoint_label: "peer-0".to_string(),
            client: Client::new(MixedTransport::Slow(Arc::clone(&slow))),
        }];
        for (index, signer) in signers.iter().enumerate().take(4).skip(1) {
            let vote = cast_for(&certifier, signer, tx_hash, 0x10);
            let fast = MixedTransport::Scripted(ScriptedTransport::ok(
                NODE_RESULT_MEDIA_TYPE,
                encode_fast_vote(&vote).unwrap(),
            ));
            endpoints.push(FastVoteEndpoint {
                validator_id: signer.id,
                endpoint_label: format!("peer-{index}"),
                client: Client::new(fast),
            });
        }

        let before = Instant::now();
        let (certificate, attempts) = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            overall,
            per_request_cap,
        )
        .unwrap_or_else(|_| panic!("3 honest peers must still reach quorum"));
        assert_eq!(certificate.votes.len(), 3);
        assert!(attempts[0].result.is_err());

        let seen = slow.seen_deadline.lock().unwrap().unwrap();
        assert!(
            seen <= before + per_request_cap + Duration::from_millis(200),
            "expected the slow peer's own deadline to be capped near {per_request_cap:?}, not the full whole-workflow budget"
        );
    }

    /// A uniform transport type over either a slow, deadline-recording peer
    /// or an ordinary scripted peer, so a mixed-behavior endpoint set can
    /// share one concrete `FastVoteEndpoint<T>` type.
    enum MixedTransport {
        Slow(Arc<RecordingSlowTransport>),
        Scripted(ScriptedTransport),
    }
    impl Transport for MixedTransport {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            match self {
                Self::Slow(transport) => transport.send(request),
                Self::Scripted(transport) => transport.send(request),
            }
        }
    }

    #[test]
    fn validate_fastvote_endpoints_rejects_duplicate_validator_ids() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let endpoints = vec![
            endpoint(signers[0].id, "peer-a", ScriptedTransport::unreachable()),
            endpoint(signers[0].id, "peer-b", ScriptedTransport::unreachable()),
        ];
        assert_eq!(
            validate_fastvote_endpoints(&endpoints, &certifier),
            Err(FastVoteEndpointConfigError::DuplicateValidatorId(
                signers[0].id
            ))
        );
    }

    #[test]
    fn validate_fastvote_endpoints_rejects_duplicate_endpoint_labels() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let endpoints = vec![
            endpoint(
                signers[0].id,
                "same-label",
                ScriptedTransport::unreachable(),
            ),
            endpoint(
                signers[1].id,
                "same-label",
                ScriptedTransport::unreachable(),
            ),
        ];
        assert_eq!(
            validate_fastvote_endpoints(&endpoints, &certifier),
            Err(FastVoteEndpointConfigError::DuplicateEndpointLabel(
                "same-label".to_string()
            ))
        );
    }

    #[test]
    fn validate_fastvote_endpoints_rejects_a_validator_absent_from_the_local_pin() {
        let (_signers, infos) = four_validators();
        let certifier = certifier(infos);
        let (rogue, _) = validator(99);
        let endpoints = vec![endpoint(
            rogue.id,
            "peer-x",
            ScriptedTransport::unreachable(),
        )];
        assert_eq!(
            validate_fastvote_endpoints(&endpoints, &certifier),
            Err(FastVoteEndpointConfigError::UnknownValidator(rogue.id))
        );
    }

    #[test]
    fn validate_fastvote_endpoints_rejects_an_empty_configuration() {
        let (_signers, infos) = four_validators();
        let certifier = certifier(infos);
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = Vec::new();
        assert_eq!(
            validate_fastvote_endpoints(&endpoints, &certifier),
            Err(FastVoteEndpointConfigError::NoEndpoints)
        );
    }

    #[test]
    fn validate_fastvote_endpoints_rejects_too_many_endpoints() {
        let (_signers, infos) = four_validators();
        let certifier = certifier(infos);
        let mut endpoints = Vec::new();
        for index in 0..=MAX_FASTVOTE_NETWORK_ENDPOINTS {
            let seed = u8::try_from(index % 250).unwrap() + 5;
            let (signer, _) = validator(seed);
            endpoints.push(endpoint(
                signer.id,
                &format!("peer-{index}"),
                ScriptedTransport::unreachable(),
            ));
        }
        assert!(matches!(
            validate_fastvote_endpoints(&endpoints, &certifier),
            Err(FastVoteEndpointConfigError::TooManyEndpoints { .. })
        ));
    }

    #[test]
    fn apply_fastvote_to_all_rejects_a_certificate_for_an_unrelated_transaction_before_any_post() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(8, [0x70; 32]);
        let unrelated = signed_transfer(9, [0x71; 32]);
        let unrelated_tx_hash = expected_tx_hash(&unrelated);
        let votes: Vec<FastVote> = signers[..3]
            .iter()
            .map(|signer| cast_for(&certifier, signer, unrelated_tx_hash, 0x10))
            .collect();
        let certificate = certifier
            .try_form_certificate(
                unrelated_tx_hash,
                digest(0x10),
                digest(0x11),
                &votes,
                &node_core::fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("3-of-4 quorum for the unrelated transaction");

        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..4)
            .map(|index| {
                endpoint(
                    signers[index].id,
                    &format!("peer-{index}"),
                    ScriptedTransport::unreachable(),
                )
            })
            .collect();
        let error = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &resolver(),
            &certificate,
            deadline(),
            CAP,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteNetworkError::Preflight(ClientError::FastVoteUnexpectedTransaction { .. })
        ));
        // Rejected before any endpoint was ever contacted.
        for endpoint in &endpoints {
            let ScriptedTransport { calls, .. } = &endpoint.client.transport();
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn apply_fastvote_to_all_rejects_an_uncertifiable_certificate_before_any_post() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(10, [0x80; 32]);
        let tx_hash = expected_tx_hash(&signed);
        // Only 2 real votes: not enough for quorum, so this "certificate" is
        // hand-assembled with an insufficient vote set and must fail
        // `verify_certificate` locally.
        let mut votes: Vec<FastVote> = signers[..2]
            .iter()
            .map(|signer| cast_for(&certifier, signer, tx_hash, 0x10))
            .collect();
        votes.sort_by_key(|vote| vote.validator);
        let bogus_certificate = FastCertificate {
            chain_id: chain(),
            protocol_version: protocol_version(),
            epoch: epoch(),
            tx_hash,
            execution_effects_hash: digest(0x10),
            locked_objects_digest: digest(0x11),
            votes,
        };
        let endpoints: Vec<FastVoteEndpoint<ScriptedTransport>> = (0..4)
            .map(|index| {
                endpoint(
                    signers[index].id,
                    &format!("peer-{index}"),
                    ScriptedTransport::unreachable(),
                )
            })
            .collect();
        let error = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &resolver(),
            &bogus_certificate,
            deadline(),
            CAP,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteNetworkError::Preflight(ClientError::FastVoteConsensus(
                ConsensusError::InsufficientQuorum { .. }
            ))
        ));
    }

    #[test]
    fn apply_fastvote_to_all_reports_every_endpoint_independently() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(11, [0x90; 32]);
        let tx_hash = expected_tx_hash(&signed);
        let votes: Vec<FastVote> = signers[..3]
            .iter()
            .map(|signer| cast_for(&certifier, signer, tx_hash, 0x10))
            .collect();
        let certificate = certifier
            .try_form_certificate(
                tx_hash,
                digest(0x10),
                digest(0x11),
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
                    &format!("peer-{index}"),
                    ScriptedTransport::ok(NODE_RESULT_MEDIA_TYPE, mismatched_body.clone()),
                )
            })
            .collect();
        endpoints.push(endpoint(
            signers[2].id,
            "peer-2",
            ScriptedTransport::unreachable(),
        ));

        let attempts = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &resolver(),
            &certificate,
            deadline(),
            CAP,
        )
        .unwrap();
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

    #[test]
    fn bounded_deadline_rejects_zero_and_excessive_cap_and_duration_max_cannot_panic() {
        let overall = Instant::now() + Duration::from_secs(10);

        assert!(matches!(
            bounded_deadline(overall, Duration::ZERO),
            Err(FastVoteNetworkError::ZeroPerRequestCap)
        ));

        // Duration::MAX must not panic and must be rejected as excessive.
        assert!(matches!(
            bounded_deadline(overall, Duration::MAX),
            Err(FastVoteNetworkError::ExcessivePerRequestCap {
                configured,
                maximum,
            }) if configured == Duration::MAX && maximum == MAX_FASTVOTE_PER_REQUEST_CAP
        ));

        let excessive = MAX_FASTVOTE_PER_REQUEST_CAP + Duration::from_secs(1);
        assert!(matches!(
            bounded_deadline(overall, excessive),
            Err(FastVoteNetworkError::ExcessivePerRequestCap {
                configured,
                maximum,
            }) if configured == excessive && maximum == MAX_FASTVOTE_PER_REQUEST_CAP
        ));

        // Elapsed overall deadline must be rejected.
        let elapsed = Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            bounded_deadline(elapsed, Duration::from_secs(1)),
            Err(FastVoteNetworkError::OverallDeadlineElapsed)
        ));

        // Valid cap and future deadline succeeds and never replenishes the caller deadline.
        let valid_cap = Duration::from_secs(2);
        let computed = bounded_deadline(overall, valid_cap).expect("valid deadline should succeed");
        assert!(computed <= Instant::now() + valid_cap);

        let tight_overall = Instant::now() + Duration::from_millis(100);
        let clamped =
            bounded_deadline(tight_overall, valid_cap).expect("tight deadline should succeed");
        assert!(
            clamped <= tight_overall,
            "deadline must not be replenished beyond caller overall budget"
        );
    }

    #[test]
    fn collect_fastvote_certificate_rejects_invalid_or_elapsed_cap_and_budget_without_post() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(12, [0xa0; 32]);

        let make_endpoints = || -> Vec<FastVoteEndpoint<ScriptedTransport>> {
            (0..4)
                .map(|index| {
                    endpoint(
                        signers[index].id,
                        &format!("peer-{index}"),
                        ScriptedTransport::unreachable(),
                    )
                })
                .collect()
        };

        // Zero per_request_cap causes no transport POST.
        let endpoints = make_endpoints();
        let error = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteQuorumError::Network(FastVoteNetworkError::ZeroPerRequestCap)
        ));
        for ep in &endpoints {
            assert_eq!(ep.client.transport().calls.load(Ordering::Relaxed), 0);
        }

        // Duration::MAX per_request_cap causes no transport POST and does not panic.
        let endpoints = make_endpoints();
        let error = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            deadline(),
            Duration::MAX,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteQuorumError::Network(FastVoteNetworkError::ExcessivePerRequestCap { .. })
        ));
        for ep in &endpoints {
            assert_eq!(ep.client.transport().calls.load(Ordering::Relaxed), 0);
        }

        // Elapsed overall deadline causes no transport POST.
        let endpoints = make_endpoints();
        let elapsed = Instant::now() - Duration::from_secs(1);
        let error = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &resolver(),
            &signed,
            elapsed,
            CAP,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteQuorumError::Network(FastVoteNetworkError::OverallDeadlineElapsed)
        ));
        for ep in &endpoints {
            assert_eq!(ep.client.transport().calls.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn apply_fastvote_to_all_rejects_invalid_or_elapsed_cap_and_budget_without_post() {
        let (signers, infos) = four_validators();
        let certifier = certifier(infos);
        let signed = signed_transfer(13, [0xb0; 32]);
        let tx_hash = expected_tx_hash(&signed);
        let votes: Vec<FastVote> = signers[..3]
            .iter()
            .map(|signer| cast_for(&certifier, signer, tx_hash, 0x10))
            .collect();
        let certificate = certifier
            .try_form_certificate(
                tx_hash,
                digest(0x10),
                digest(0x11),
                &votes,
                &node_core::fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("3-of-4 quorum");

        let make_endpoints = || -> Vec<FastVoteEndpoint<ScriptedTransport>> {
            (0..4)
                .map(|index| {
                    endpoint(
                        signers[index].id,
                        &format!("peer-{index}"),
                        ScriptedTransport::unreachable(),
                    )
                })
                .collect()
        };

        // Zero per_request_cap causes no transport POST.
        let endpoints = make_endpoints();
        let error = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &resolver(),
            &certificate,
            deadline(),
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(matches!(error, FastVoteNetworkError::ZeroPerRequestCap));
        for ep in &endpoints {
            assert_eq!(ep.client.transport().calls.load(Ordering::Relaxed), 0);
        }

        // Duration::MAX per_request_cap causes no transport POST and does not panic.
        let endpoints = make_endpoints();
        let error = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &resolver(),
            &certificate,
            deadline(),
            Duration::MAX,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteNetworkError::ExcessivePerRequestCap { .. }
        ));
        for ep in &endpoints {
            assert_eq!(ep.client.transport().calls.load(Ordering::Relaxed), 0);
        }

        // Elapsed overall deadline causes no transport POST.
        let endpoints = make_endpoints();
        let elapsed = Instant::now() - Duration::from_secs(1);
        let error = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &resolver(),
            &certificate,
            elapsed,
            CAP,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FastVoteNetworkError::OverallDeadlineElapsed
        ));
        for ep in &endpoints {
            assert_eq!(ep.client.transport().calls.load(Ordering::Relaxed), 0);
        }
    }
}
