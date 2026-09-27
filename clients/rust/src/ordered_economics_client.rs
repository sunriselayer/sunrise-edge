//! DR-0153 ordered network economics client (SDK half of
//! `native-http::ordered_economics`).
//!
//! Mirrors `fastvote_client.rs`'s trust model: [`load_trusted_ordered_policy`]
//! only trusts a genesis manifest after its exact commitment digest and
//! embedded context match a caller-supplied expected value and its authority
//! signature verifies -- reusing [`node_core::genesis`]'s production trust
//! path unchanged, exactly like [`crate::fastvote_client::load_trusted_fastvote_genesis`].
//! [`validate_ordered_economics_endpoints`] is required, bounded,
//! library-enforced preflight before any network I/O, mirroring
//! [`crate::fastvote_client::validate_fastvote_endpoints`]. Vote/certificate
//! verification reuses [`node_core::fast_path::FastPathEd25519Verifier`]
//! (a generic, stateless Ed25519 `ConsensusVerifier`, not FastVote-specific
//! despite its module home) -- never a hand-rolled reimplementation.
//!
//! [`submit_candidate`] drives the current leader (selected by
//! `policy.engine().validator_set().leader(view)`, from this call's own
//! locally pinned genesis validator set, never a value the network reports)
//! through a real proposal/vote/certificate round carrying the candidate,
//! then two further empty-descendant rounds, persisting every input,
//! proposal, and certificate artifact via the caller-supplied
//! [`ArtifactSink`] *before* the corresponding network call, per DR-0153's
//! "record artifacts before sending" requirement. [`replay_declared_prefix`]
//! resubmits an already-persisted, exact proposal/certificate sequence to
//! every endpoint's signerless `observe`/`certificate` routes, unchanged and
//! without voting.
//!
//! `verify_proposal`/`certificate_from_votes` use the real, delivered
//! `consensus::durable` implementation (`ChainedHotStuff::verify_proposal`
//! is pure context/leader/justify/signature verification, independent of
//! `ConsensusState`) -- `run_one_round` calls it on every returned proposal
//! *before* broadcasting to any peer's vote route. `certificate_from_votes`
//! itself aborts on the first invalid vote in its input, so every collected
//! vote is individually filtered (digest/view/height match plus
//! `verify_vote`) before being offered to it, so one Byzantine or
//! unreachable peer cannot deny a real quorum from the honest remainder.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use consensus::{ConsensusMessage, ConsensusVote, QuorumCertificate};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::MAX_GENESIS_MANIFEST_BYTES;
use node_core::fast_path::FastPathEd25519Verifier;
use node_core::fast_path::records::FastPathValidatorSetRecord;
use node_core::genesis::{
    GenesisManifest, decode_genesis_manifest, genesis_manifest_commitment,
    genesis_manifest_signing_frame,
};
use node_core::ordered_economics::{
    OrderedCandidate, OrderedEconomicsError, OrderedEconomicsPolicy, OrderedEventOutput,
    OrderedOutcome, OrderedStatus, decode_ordered_event_output, decode_ordered_proposal,
    decode_ordered_status, encode_ordered_candidate,
};
use node_wire::ordered_economics::{
    ORDERED_CERTIFICATE_MEDIA_TYPE, ORDERED_ECONOMICS_CERTIFICATE_PATH,
    ORDERED_ECONOMICS_OBSERVE_PATH, ORDERED_ECONOMICS_PROPOSAL_PATH,
    ORDERED_ECONOMICS_PROPOSE_PATH, ORDERED_ECONOMICS_STATUS_PATH, ORDERED_ECONOMICS_TICK_PATH,
    ORDERED_PROPOSAL_MEDIA_TYPE, ORDERED_PROPOSE_REQUEST_MEDIA_TYPE, OrderedProposeRequest,
};
use protocol_types::{AtomicityDomainId, Digest32, SignatureSchemeId, ValidatorId};
use validator_set::{ValidatorInfo, ValidatorSet};

use crate::Client;
use crate::client::expect_success;
use crate::error::ClientError;
use crate::transport::{Method, Transport, WireRequest};

/// Bounded fan-out cap for one configured ordered-economics cohort, mirroring
/// [`crate::fastvote_client::MAX_FASTVOTE_NETWORK_ENDPOINTS`].
pub const MAX_ORDERED_ECONOMICS_ENDPOINTS: usize = 32;

/// Pure profile authentication of the original signed envelope and every leg.
/// This never obtains fresh execution authority or contacts a validator.
pub fn authenticate_ordered_candidate(
    policy: &OrderedEconomicsPolicy,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsNetworkError> {
    policy
        .authenticate_candidate(candidate)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))
}

fn verify_ordered_proposal(
    policy: &OrderedEconomicsPolicy,
    proposal: &node_core::ordered_economics::OrderedProposal,
) -> Result<(), OrderedEconomicsNetworkError> {
    policy
        .engine()
        .verify_proposal(&proposal.proposal, &FastPathEd25519Verifier)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
    let expected: Vec<Digest32> = match &proposal.candidate {
        Some(candidate) => {
            authenticate_ordered_candidate(policy, candidate)?;
            if proposal.proposal.height % 3 != 1 {
                return Err(OrderedEconomicsNetworkError::Rejected(
                    "candidate outside economic window".into(),
                ));
            }
            vec![
                policy
                    .candidate_digest(candidate)
                    .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?,
            ]
        }
        None => Vec::new(),
    };
    if proposal.proposal.transactions != expected {
        return Err(OrderedEconomicsNetworkError::Rejected(
            "proposal does not bind exactly its candidate".into(),
        ));
    }
    Ok(())
}

/// One configured cohort member.
pub struct OrderedEconomicsEndpoint<T> {
    /// The validator identity this endpoint is configured to speak for.
    pub validator_id: ValidatorId,
    /// Caller-chosen label used only for duplicate-endpoint detection.
    pub endpoint_label: String,
    /// The bounded, already-authenticated-transport client for this
    /// endpoint.
    pub client: Client<T>,
}

/// Failures constructing a locally trusted ordered-economics policy pin.
#[derive(Debug)]
pub enum OrderedGenesisTrustError {
    /// The manifest file could not be read or exceeded [`MAX_GENESIS_MANIFEST_BYTES`].
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
    /// The embedded validator-set record was invalid.
    InvalidValidatorSet(String),
    /// `OrderedEconomicsPolicy::new` itself rejected the pinned inputs.
    Policy(OrderedEconomicsError),
}

impl fmt::Display for OrderedGenesisTrustError {
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
            Self::Policy(error) => write!(f, "ordered economics policy rejected: {error}"),
        }
    }
}

impl Error for OrderedGenesisTrustError {}

/// Reads and strictly validates a genesis manifest file exactly like
/// [`crate::fastvote_client::load_trusted_fastvote_genesis`], then builds the
/// [`OrderedEconomicsPolicy`] this call's fixed-epoch profile uses for local
/// verification. `domain` and `genesis_digest` are separate, caller-supplied
/// pins the manifest's own commitment digest is checked against; neither is
/// ever replaced by a value read from any endpoint.
#[allow(clippy::result_large_err)]
pub fn load_trusted_ordered_policy(
    manifest_path: &Path,
    resolver: &HashSuiteResolver,
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
    domain: AtomicityDomainId,
) -> Result<OrderedEconomicsPolicy, OrderedGenesisTrustError> {
    let bytes = crate::fastvote_client::read_bounded(manifest_path, MAX_GENESIS_MANIFEST_BYTES)
        .map_err(OrderedGenesisTrustError::Io)?;
    let manifest: GenesisManifest =
        decode_genesis_manifest(&bytes).map_err(OrderedGenesisTrustError::Decode)?;
    let digest: Digest32 = genesis_manifest_commitment(resolver, &manifest)
        .map_err(OrderedGenesisTrustError::Decode)?;
    if digest.bytes() != expected_digest {
        return Err(OrderedGenesisTrustError::CommitmentMismatch);
    }
    if manifest.context() != expected_context {
        return Err(OrderedGenesisTrustError::ContextMismatch);
    }
    let verifier = crypto::Ed25519Verifier::from_verifying_key_bytes(&manifest.genesis_authority)
        .map_err(|_| OrderedGenesisTrustError::InvalidSignature)?;
    let frame =
        genesis_manifest_signing_frame(&manifest).map_err(OrderedGenesisTrustError::Decode)?;
    use crypto::SignatureVerifier;
    let valid = verifier
        .verify_framed(&frame, &manifest.signature)
        .map_err(|_| OrderedGenesisTrustError::InvalidSignature)?;
    if !valid {
        return Err(OrderedGenesisTrustError::InvalidSignature);
    }
    let validator_set = validator_set_from_record(&manifest.validator_set, expected_context)?;
    OrderedEconomicsPolicy::new(
        expected_context.clone(),
        domain,
        digest,
        validator_set,
        resolver.clone(),
    )
    .map_err(OrderedGenesisTrustError::Policy)
}

#[allow(clippy::result_large_err)]
fn validator_set_from_record(
    record: &FastPathValidatorSetRecord,
    expected_context: &PublicationContext,
) -> Result<ValidatorSet, OrderedGenesisTrustError> {
    if &record.context != expected_context {
        return Err(OrderedGenesisTrustError::InvalidValidatorSet(
            "validator set record context mismatch".to_string(),
        ));
    }
    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(record.validators.len());
    for validator in &record.validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(OrderedGenesisTrustError::InvalidValidatorSet(
                "ordered economics fixed-epoch profile supports only Ed25519 validators"
                    .to_string(),
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
        .map_err(|error| OrderedGenesisTrustError::InvalidValidatorSet(error.to_string()))
}

/// Fail-closed configuration errors [`validate_ordered_economics_endpoints`]
/// rejects before any network I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderedEconomicsEndpointConfigError {
    /// No endpoints configured.
    NoEndpoints,
    /// More endpoints configured than [`MAX_ORDERED_ECONOMICS_ENDPOINTS`].
    TooManyEndpoints { configured: usize, maximum: usize },
    /// Two endpoints share the same configured label.
    DuplicateLabel(String),
    /// Two endpoints claim the same `ValidatorId`.
    DuplicateValidator(ValidatorId),
    /// A configured `ValidatorId` is absent from the local genesis pin.
    UnknownValidator(ValidatorId),
}

impl fmt::Display for OrderedEconomicsEndpointConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEndpoints => f.write_str("no ordered economics endpoints configured"),
            Self::TooManyEndpoints {
                configured,
                maximum,
            } => write!(
                f,
                "{configured} ordered economics endpoints configured, maximum is {maximum}"
            ),
            Self::DuplicateLabel(label) => {
                write!(f, "duplicate ordered economics endpoint label: {label}")
            }
            Self::DuplicateValidator(id) => {
                write!(f, "duplicate ordered economics endpoint validator: {id:?}")
            }
            Self::UnknownValidator(id) => write!(
                f,
                "ordered economics endpoint validator {id:?} is absent from the local genesis pin"
            ),
        }
    }
}

impl Error for OrderedEconomicsEndpointConfigError {}

/// Required preflight, mirroring
/// [`crate::fastvote_client::validate_fastvote_endpoints`]: rejects an empty
/// or oversized cohort, a duplicate label/`ValidatorId`, or any configured
/// `ValidatorId` absent from `validator_set` -- before any network I/O.
/// Takes a plain [`ValidatorSet`] (not the full [`OrderedEconomicsPolicy`])
/// so this check -- and its unit tests -- never depend on
/// `node_core::ordered_economics`.
pub fn validate_ordered_economics_endpoints<T>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    validator_set: &ValidatorSet,
) -> Result<(), OrderedEconomicsEndpointConfigError> {
    if endpoints.is_empty() {
        return Err(OrderedEconomicsEndpointConfigError::NoEndpoints);
    }
    if endpoints.len() > MAX_ORDERED_ECONOMICS_ENDPOINTS {
        return Err(OrderedEconomicsEndpointConfigError::TooManyEndpoints {
            configured: endpoints.len(),
            maximum: MAX_ORDERED_ECONOMICS_ENDPOINTS,
        });
    }
    let mut seen_ids: BTreeSet<ValidatorId> = BTreeSet::new();
    let mut seen_labels: BTreeSet<&str> = BTreeSet::new();
    for endpoint in endpoints {
        if !seen_labels.insert(endpoint.endpoint_label.as_str()) {
            return Err(OrderedEconomicsEndpointConfigError::DuplicateLabel(
                endpoint.endpoint_label.clone(),
            ));
        }
        if !seen_ids.insert(endpoint.validator_id) {
            return Err(OrderedEconomicsEndpointConfigError::DuplicateValidator(
                endpoint.validator_id,
            ));
        }
        if validator_set.get(endpoint.validator_id).is_none() {
            return Err(OrderedEconomicsEndpointConfigError::UnknownValidator(
                endpoint.validator_id,
            ));
        }
    }
    Ok(())
}

/// Failures from a network-driving ordered economics operation.
#[derive(Debug)]
pub enum OrderedEconomicsNetworkError {
    /// [`validate_ordered_economics_endpoints`] rejected the cohort.
    EndpointConfig(OrderedEconomicsEndpointConfigError),
    /// The overall deadline had already elapsed.
    OverallDeadlineElapsed,
    /// No configured endpoint identified as the expected leader for the
    /// current view; this call never substitutes another validator.
    LeaderEndpointMissing(ValidatorId),
    /// A transport/decoding/client failure.
    Client(Box<ClientError>),
    /// The core engine rejected a step (`OrderedEconomicsError`/`ConsensusError`).
    Rejected(String),
    /// A real quorum of votes could not be formed from reachable endpoints.
    QuorumNotFormed,
    /// Persisting a required artifact before sending failed.
    Artifact(std::io::Error),
    /// A quorum certificate formed, but every configured peer own
    /// certificate-apply phase failed: an unsigned HTTP acknowledgement
    /// never arrived from any configured peer for this round. Carries every
    /// peer own per-phase outcome. Never itself a durability proof -- see
    /// SubmissionOutcome for the separate certified-prefix binding and
    /// unsigned request-bound acknowledgement.
    NoReplicaAcknowledgement { peers: Vec<PeerResult> },
    /// Two peer responses reported different committed outcomes bound to the
    /// same candidate digest and request id during this call: a reordered or
    /// conflicting outcome, never silently resolved by picking either one.
    ConflictingCommittedOutcome,
    /// No peer echoed a request/digest/block-bound committed
    /// outcome anywhere across this whole submission. Raw peer HTTP success
    /// is only an acknowledgement, never proof of three-chain commit: this
    /// call fails closed instead of returning an unconfirmed success.
    NoCommittedOutcome,
    /// A replica reported this exact request already completed. This unsigned
    /// hint is not accepted as fresh finality. Reconcile the original saved
    /// proposal/certificate prefix instead of placing or signing a new request.
    CompletedRequestRequiresReplay,
}

impl fmt::Display for OrderedEconomicsNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointConfig(error) => write!(f, "{error}"),
            Self::OverallDeadlineElapsed => f.write_str("overall deadline elapsed"),
            Self::LeaderEndpointMissing(id) => {
                write!(f, "no configured endpoint for current leader {id:?}")
            }
            Self::Client(error) => write!(f, "{error}"),
            Self::Rejected(reason) => write!(f, "ordered economics step rejected: {reason}"),
            Self::QuorumNotFormed => f.write_str("a real quorum certificate could not be formed"),
            Self::Artifact(error) => write!(f, "failed to persist artifact: {error}"),
            Self::NoReplicaAcknowledgement { peers } => write!(
                f,
                "quorum certificate formed but no configured peer acknowledged applying it ({} peers attempted)",
                peers.len()
            ),
            Self::ConflictingCommittedOutcome => f.write_str(
                "peer responses disagree on the committed outcome for this candidate digest and request id",
            ),
            Self::NoCommittedOutcome => f.write_str(
                "no peer acknowledged a committed outcome bound to this candidate's certified prefix",
            ),
            Self::CompletedRequestRequiresReplay => f.write_str("replica reports this request already completed; replay the original saved proposal/certificate manifest, never a fresh request id or nonce"),
        }
    }
}

impl Error for OrderedEconomicsNetworkError {}

impl From<OrderedEconomicsEndpointConfigError> for OrderedEconomicsNetworkError {
    fn from(value: OrderedEconomicsEndpointConfigError) -> Self {
        Self::EndpointConfig(value)
    }
}

impl From<ClientError> for OrderedEconomicsNetworkError {
    fn from(value: ClientError) -> Self {
        Self::Client(Box::new(value))
    }
}

/// Persists one artifact's exact bytes before the corresponding network call.
/// The CLI implementation reserves the destination with `create_new` (never
/// silently overwriting an existing artifact); tests may use an in-memory
/// sink.
pub trait ArtifactSink {
    /// Persists `bytes` under `name` (a caller-defined, ordered artifact
    /// identifier such as `"round-0.candidate"` or `"round-1.certificate"`).
    fn persist(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()>;

    /// Makes the now-complete exact proposal/QC pair discoverable in the
    /// durable replay manifest before broadcasting that certificate.
    fn record_certified_round(&mut self, _round: usize) -> std::io::Result<()> {
        Ok(())
    }

    /// Persists separately attributed replica acknowledgements. An unsigned
    /// acknowledgement is never a substitute for the retained certificate.
    fn record_peer_result(&mut self, _round: usize, _peer: &PeerResult) -> std::io::Result<()> {
        Ok(())
    }
}

/// One peer own outcome for one network phase (vote-collection or
/// certificate-apply). Never conflated: an unreachable peer is not the same
/// as one that authenticated and rejected, which is not the same as one
/// that acknowledged applying it -- an acknowledgement, not a durability
/// proof.
#[derive(Debug, Clone)]
pub enum PeerPhaseOutcome {
    /// The peer acknowledged the request and returned this decoded output.
    Applied(OrderedEventOutput),
    /// The transport call itself failed (offline/timeout/refused).
    Unreachable(String),
    /// The peer responded but rejected the request (bad status/media type/
    /// undecodable body).
    Rejected(String),
    /// This phase was never attempted: an earlier prefix step already
    /// failed for this exact peer, and continuing a later step against an
    /// unhealthy replica would advance it past a missed prerequisite.
    Skipped(String),
}

/// One configured peer's outcome for both phases of one round.
#[derive(Debug)]
pub struct PeerResult {
    pub validator_id: ValidatorId,
    pub endpoint_label: String,
    pub vote_phase: PeerPhaseOutcome,
    pub certificate_phase: PeerPhaseOutcome,
}

/// Result of one round. `qc_formed_from` lists exactly the validators whose
/// votes were included in the aggregated certificate (QC finality); `peers`
/// separately records each configured peer's actual reachability/response
/// for both phases (replica durability) -- the two are never conflated.
pub struct RoundOutcome {
    pub proposal_bytes: Vec<u8>,
    pub certificate_bytes: Vec<u8>,
    /// Height of the exact authenticated proposal this round carried.
    pub height: u64,
    /// Canonical digest of the exact authenticated proposal this round
    /// carried, independently recomputed via the pinned engine, never
    /// trusted from a peer response.
    pub proposal_digest: Digest32,
    pub qc_formed_from: Vec<ValidatorId>,
    pub peers: Vec<PeerResult>,
}

/// Result of the whole submission. `rounds` records every HTTP exchange
/// attempted; `committed_outcome` is an unsigned replica acknowledgement bound
/// to the authenticated candidate and certified three-chain, not a signature
/// over the business result or proof of whole-store durability. It is present because `submit_candidate`
/// itself already failed closed with `NoCommittedOutcome` otherwise, so a
/// caller holding an `Ok(SubmissionOutcome)` never needs to separately
/// test for a missing acknowledgement. A quorum certificate
/// certifies one proposal, not by itself that the network
/// committed this business operation; that distinction is exactly why
/// `committed_outcome` is independently bound to the round-0 proposal
/// height/digest before this function ever returns it.
pub struct SubmissionOutcome {
    pub rounds: Vec<RoundOutcome>,
    pub committed_outcome: OrderedOutcome,
}

fn deadline_remaining(overall_deadline: Instant) -> Result<Duration, OrderedEconomicsNetworkError> {
    let now = Instant::now();
    if now >= overall_deadline {
        return Err(OrderedEconomicsNetworkError::OverallDeadlineElapsed);
    }
    Ok(overall_deadline - now)
}

fn request_deadline(
    overall: Instant,
    cap: Duration,
) -> Result<Instant, OrderedEconomicsNetworkError> {
    let remaining: Duration = deadline_remaining(overall)?;
    Instant::now()
        .checked_add(remaining.min(cap))
        .ok_or(OrderedEconomicsNetworkError::OverallDeadlineElapsed)
}

fn find_leader<T>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    leader: ValidatorId,
) -> Result<&OrderedEconomicsEndpoint<T>, OrderedEconomicsNetworkError> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.validator_id == leader)
        .ok_or(OrderedEconomicsNetworkError::LeaderEndpointMissing(leader))
}

fn query_status<T: Transport>(
    endpoint: &OrderedEconomicsEndpoint<T>,
    deadline: Instant,
) -> Result<OrderedStatus, OrderedEconomicsNetworkError> {
    let request = WireRequest {
        method: Method::Get,
        path: ORDERED_ECONOMICS_STATUS_PATH.to_string(),
        content_type: None,
        body: Vec::new(),
        deadline: Some(deadline),
    };
    let response = endpoint
        .client
        .transport()
        .send(&request)
        .map_err(ClientError::from)?;
    let body = expect_success(
        response,
        node_wire::ordered_economics::ORDERED_STATUS_MEDIA_TYPE,
    )?;
    decode_ordered_status(&body)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))
}

/// Bounded replica-local, unsigned completion acknowledgement. Authenticates
/// the expected candidate locally before I/O and checks request/digest binding.
/// `None` is replica-local only; this API supplies neither network absence nor
/// finality proof. Verify/replay the original certified prefix separately.
pub fn query_replica_outcome<T: Transport>(
    endpoint: &OrderedEconomicsEndpoint<T>,
    policy: &OrderedEconomicsPolicy,
    candidate: &OrderedCandidate,
    deadline: Instant,
) -> Result<Option<OrderedOutcome>, OrderedEconomicsNetworkError> {
    authenticate_ordered_candidate(policy, candidate)?;
    validate_ordered_economics_endpoints(
        std::slice::from_ref(endpoint),
        policy.engine().validator_set(),
    )?;
    let outcome = query_retained_outcome(endpoint, candidate.request_id, deadline)?;
    let Some(outcome) = outcome else {
        return Ok(None);
    };
    let digest = policy
        .candidate_digest(candidate)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
    if outcome.candidate_digest != digest {
        return Err(OrderedEconomicsNetworkError::Rejected(
            "replica outcome does not match the expected candidate".into(),
        ));
    }
    Ok(Some(outcome))
}

// Called only after local candidate authentication and endpoint preflight.
// Do not discard a conflicting digest: agreeing quorum hints must stop a
// completed request-id reuse before routing/Tick changes any replica's view.
fn query_retained_outcome<T: Transport>(
    endpoint: &OrderedEconomicsEndpoint<T>,
    request_id: [u8; 32],
    deadline: Instant,
) -> Result<Option<OrderedOutcome>, OrderedEconomicsNetworkError> {
    let id: String = request_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let response = endpoint
        .client
        .transport()
        .send(&WireRequest {
            method: Method::Get,
            path: format!(
                "{}{id}",
                node_wire::ordered_economics::ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX
            ),
            content_type: None,
            body: Vec::new(),
            deadline: Some(deadline),
        })
        .map_err(ClientError::from)?;
    if response.status == 204 && response.body.is_empty() {
        return Ok(None);
    }
    let bytes = expect_success(
        response,
        node_wire::ordered_economics::ORDERED_OUTCOME_MEDIA_TYPE,
    )?;
    let outcome = node_core::ordered_economics::decode_ordered_outcome(&bytes)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
    if outcome.request_id != request_id {
        return Err(OrderedEconomicsNetworkError::Rejected(
            "replica outcome does not match the expected candidate".into(),
        ));
    }
    Ok(Some(outcome))
}

/// Unsigned status is only a routing hint. Require a configured voting quorum
/// to report the same view; a Byzantine peer's invented maximum cannot select
/// a new leader. Every reported high QC is independently authenticated first.
fn routing_view<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    policy: &OrderedEconomicsPolicy,
    overall: Instant,
    cap: Duration,
) -> Result<Option<u64>, OrderedEconomicsNetworkError> {
    let set: &ValidatorSet = policy.engine().validator_set();
    let mut powers: BTreeMap<u64, u64> = BTreeMap::new();
    for endpoint in endpoints {
        let deadline: Instant = request_deadline(overall, cap)?;
        let Ok(status) = query_status(endpoint, deadline) else {
            continue;
        };
        if status.current_view == 0
            || status.current_view <= status.high_qc.view
            || policy
                .engine()
                .verify_certificate(&status.high_qc, &FastPathEd25519Verifier)
                .is_err()
        {
            continue;
        }
        let info: &ValidatorInfo = set
            .get(endpoint.validator_id)
            .ok_or(OrderedEconomicsNetworkError::QuorumNotFormed)?;
        let power: &mut u64 = powers.entry(status.current_view).or_default();
        *power = power.checked_add(info.voting_power).ok_or_else(|| {
            OrderedEconomicsNetworkError::Rejected("routing power overflow".into())
        })?;
    }
    Ok(powers
        .into_iter()
        .rev()
        .find_map(|(view, power)| (power >= set.quorum_threshold()).then_some(view)))
}

fn clock_progress<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    overall: Instant,
    cap: Duration,
) -> Result<(), OrderedEconomicsNetworkError> {
    // Bounded client waiting is not a protocol timer or a caller timestamp.
    // Only each validator's trusted clock can make its Tick advance a view.
    let remaining: Duration = deadline_remaining(overall)?;
    std::thread::sleep(Duration::from_millis(250).min(remaining));
    broadcast_tick(endpoints, overall, cap)
}

/// Drives the current leader through one real proposal/vote/certificate
/// round carrying `candidate_bytes` (an exact canonical `OrderedCandidate`),
/// then `EMPTY_DESCENDANT_ROUNDS` further empty rounds so the three-chain
/// profile actually commits it. Every proposal/certificate is persisted via
/// `artifacts` before the corresponding POST. Returns every round's outcome
/// in order. `resume_round0_proposal`, when `Some`, is an already-retained,
/// exact authenticated proposal bytes from an interrupted prior attempt for
/// this exact candidate: round 0 verifies and reuses it instead of asking
/// the leader to build a fresh, possibly-conflicting proposal.
pub fn submit_candidate<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    policy: &OrderedEconomicsPolicy,
    candidate_bytes: &[u8],
    resume_round0_proposal: Option<Vec<u8>>,
    overall_deadline: Instant,
    per_request_cap: Duration,
    artifacts: &mut dyn ArtifactSink,
) -> Result<SubmissionOutcome, OrderedEconomicsNetworkError> {
    validate_ordered_economics_endpoints(endpoints, policy.engine().validator_set())?;
    if candidate_bytes.len() > node_wire::ordered_economics::MAX_ORDERED_CANDIDATE_BYTES {
        return Err(OrderedEconomicsNetworkError::Rejected(
            "candidate byte bound".into(),
        ));
    }
    let candidate: OrderedCandidate =
        node_core::ordered_economics::decode_ordered_candidate(candidate_bytes)
            .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
    authenticate_ordered_candidate(policy, &candidate)?;
    let expected_digest: Digest32 = policy
        .candidate_digest(&candidate)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
    artifacts
        .persist("round-0.candidate", candidate_bytes)
        .map_err(OrderedEconomicsNetworkError::Artifact)?;

    // Read-only reconciliation before routing/Tick/propose. A matching quorum
    // of replica-local acknowledgements is a recovery hint, not a new proof.
    // One Byzantine hint cannot suppress submission by itself.
    let mut completed_hints: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    for endpoint in endpoints {
        let deadline = request_deadline(overall_deadline, per_request_cap)?;
        if let Ok(Some(outcome)) = query_retained_outcome(endpoint, candidate.request_id, deadline)
        {
            let bytes = node_core::ordered_economics::encode_ordered_outcome(&outcome)
                .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
            let power = policy
                .engine()
                .validator_set()
                .get(endpoint.validator_id)
                .ok_or(OrderedEconomicsNetworkError::QuorumNotFormed)?
                .voting_power;
            let tally = completed_hints.entry(bytes).or_default();
            *tally = tally.checked_add(power).ok_or_else(|| {
                OrderedEconomicsNetworkError::Rejected("completion hint power overflow".into())
            })?;
            if *tally >= policy.engine().validator_set().quorum_threshold() {
                if outcome.candidate_digest != expected_digest {
                    return Err(OrderedEconomicsNetworkError::Rejected(
                        "request header conflict: a quorum acknowledges different original candidate bytes; use the original manifest".into(),
                    ));
                }
                return Err(OrderedEconomicsNetworkError::CompletedRequestRequiresReplay);
            }
        }
    }

    const EMPTY_DESCENDANT_ROUNDS: usize = 2;
    let mut rounds = Vec::with_capacity(1 + EMPTY_DESCENDANT_ROUNDS);
    let mut committed_outcome: Option<OrderedOutcome> = None;
    let mut round0_binding: Option<(u64, Digest32)> = None;
    let mut expected_parent: Option<QuorumCertificate> = None;
    for round_index in 0..=EMPTY_DESCENDANT_ROUNDS {
        let candidate_for_round = if round_index == 0 {
            Some(candidate_bytes.to_vec())
        } else {
            None
        };
        let outcome = run_one_round(
            endpoints,
            policy,
            candidate_for_round,
            if round_index == 0 {
                resume_round0_proposal.clone()
            } else {
                None
            },
            round_index,
            overall_deadline,
            per_request_cap,
            artifacts,
            expected_parent.as_ref(),
        )?;
        expected_parent = Some(
            consensus::decode_quorum_certificate(&outcome.certificate_bytes)
                .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?,
        );
        if round_index == 0 {
            round0_binding = Some((outcome.height, outcome.proposal_digest));
        }
        let (expected_block_height, expected_block_digest) = round0_binding.ok_or_else(|| {
            OrderedEconomicsNetworkError::Rejected("missing round-0 binding".into())
        })?;
        for peer in &outcome.peers {
            for phase in [&peer.vote_phase, &peer.certificate_phase] {
                if let PeerPhaseOutcome::Applied(output) = phase {
                    for found in &output.committed {
                        if found.candidate_digest != expected_digest
                            || found.request_id != candidate.request_id
                        {
                            continue;
                        }
                        // The committing block a peer echoes back must be
                        // exactly the authenticated round-0 proposal this
                        // call itself submitted -- never trusted merely
                        // because the candidate digest/request id match.
                        if found.block_height != expected_block_height
                            || found.block_digest != expected_block_digest
                        {
                            return Err(OrderedEconomicsNetworkError::Rejected(
                                "committed outcome block binding does not match the authenticated round-0 proposal".into(),
                            ));
                        }
                        match &committed_outcome {
                            Some(current) if current != found => {
                                return Err(
                                    OrderedEconomicsNetworkError::ConflictingCommittedOutcome,
                                );
                            }
                            _ => committed_outcome = Some(found.clone()),
                        }
                    }
                }
            }
        }
        rounds.push(outcome);
    }
    let committed_outcome =
        committed_outcome.ok_or(OrderedEconomicsNetworkError::NoCommittedOutcome)?;
    Ok(SubmissionOutcome {
        rounds,
        committed_outcome,
    })
}

/// Broadcasts a trusted-clock-only `tick` (empty body) to every reachable
/// endpoint so a legitimately expired view can advance through the real
/// pacemaker rule -- never a client-invented view or hand-picked leader.
/// Unreachable endpoints are skipped; this never blocks on one dead peer.
fn broadcast_tick<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    overall: Instant,
    cap: Duration,
) -> Result<(), OrderedEconomicsNetworkError> {
    for endpoint in endpoints {
        let deadline: Instant = request_deadline(overall, cap)?;
        let request = WireRequest {
            method: Method::Post,
            path: ORDERED_ECONOMICS_TICK_PATH.to_string(),
            content_type: None,
            body: Vec::new(),
            deadline: Some(deadline),
        };
        let _ = endpoint.client.transport().send(&request);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_one_round<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    policy: &OrderedEconomicsPolicy,
    candidate_bytes: Option<Vec<u8>>,
    resume_proposal: Option<Vec<u8>>,
    round_index: usize,
    overall_deadline: Instant,
    per_request_cap: Duration,
    artifacts: &mut dyn ArtifactSink,
    expected_parent: Option<&QuorumCertificate>,
) -> Result<RoundOutcome, OrderedEconomicsNetworkError> {
    let verifier = FastPathEd25519Verifier;
    let (proposal_bytes, proposal) = if let Some(resume_bytes) = resume_proposal {
        // Reconciling a retained proposal from an interrupted prior attempt:
        // verify it exactly like a freshly received one, then skip asking
        // any leader to build a fresh (potentially conflicting) proposal.
        let decoded = decode_ordered_proposal(&resume_bytes)
            .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
        verify_ordered_proposal(policy, &decoded)?;
        artifacts
            .persist(&format!("round-{round_index}.proposal"), &resume_bytes)
            .map_err(OrderedEconomicsNetworkError::Artifact)?;
        (resume_bytes, decoded)
    } else {
        loop {
            let Some(view) = routing_view(endpoints, policy, overall_deadline, per_request_cap)?
            else {
                clock_progress(endpoints, overall_deadline, per_request_cap)?;
                continue;
            };
            let leader_id = policy
                .engine()
                .validator_set()
                .leader(view)
                .ok_or(OrderedEconomicsNetworkError::QuorumNotFormed)?;
            let Ok(leader) = find_leader(endpoints, leader_id) else {
                clock_progress(endpoints, overall_deadline, per_request_cap)?;
                continue;
            };

            let propose_request = OrderedProposeRequest {
                candidate: candidate_bytes.clone(),
            };
            let body = propose_request
                .encode()
                .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
            let request = WireRequest {
                method: Method::Post,
                path: ORDERED_ECONOMICS_PROPOSE_PATH.to_string(),
                content_type: Some(ORDERED_PROPOSE_REQUEST_MEDIA_TYPE),
                body,
                deadline: Some(request_deadline(overall_deadline, per_request_cap)?),
            };
            let sent = leader.client.transport().send(&request);
            let proposal_bytes = match sent {
                Ok(response)
                    if response.status == 200
                        && response.content_type.as_deref()
                            == Some(
                                node_wire::ordered_economics::ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
                            ) =>
                {
                    // A completed-request hint cannot become new finality: no
                    // vote/certificate fan-out follows this response.
                    return Err(OrderedEconomicsNetworkError::CompletedRequestRequiresReplay);
                }
                Ok(response) if response.status == 200 => {
                    expect_success(response, ORDERED_PROPOSAL_MEDIA_TYPE)?
                }
                Ok(response) if response.status == 409 => {
                    return Err(OrderedEconomicsNetworkError::Rejected(
                        "request identity conflict or explicit recovery required".into(),
                    ));
                }
                Ok(_) | Err(_) => {
                    // The selected leader is unreachable. Never substitute a
                    // different leader or a client-invented view: broadcast
                    // a trusted-clock tick so the real pacemaker rule can
                    // legitimately expire this leader's view, then re-query
                    // status and recompute the deterministic leader.
                    clock_progress(endpoints, overall_deadline, per_request_cap)?;
                    continue;
                }
            };
            let decoded = decode_ordered_proposal(&proposal_bytes)
                .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
            // Full pure context/leader/justify/signature verification --
            // before this proposal is ever sent to a peer's vote route.
            verify_ordered_proposal(policy, &decoded)?;
            if decoded.proposal.leader != leader_id {
                return Err(OrderedEconomicsNetworkError::Rejected(
                    "proposal leader does not match the locally selected leader".to_string(),
                ));
            }
            artifacts
                .persist(&format!("round-{round_index}.proposal"), &proposal_bytes)
                .map_err(OrderedEconomicsNetworkError::Artifact)?;
            break (proposal_bytes, decoded);
        }
    };
    if let Some(parent) = expected_parent {
        let justify: &QuorumCertificate = &proposal.proposal.justify;
        if justify.proposal_digest != parent.proposal_digest
            || justify.height != parent.height
            || justify.view != parent.view
        {
            return Err(OrderedEconomicsNetworkError::Rejected(
                "descendant does not extend this submission's certified prefix".into(),
            ));
        }
    }

    // Candidate binding: an empty round must carry no candidate; a
    // candidate round must carry a decoded `OrderedCandidate` that
    // re-encodes to exactly the bytes this call submitted.
    match (&candidate_bytes, &proposal.candidate) {
        (None, None) => {}
        (Some(sent), Some(returned)) => {
            let re_encoded = encode_ordered_candidate(returned)
                .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
            if re_encoded.as_slice() != sent.as_slice() {
                return Err(OrderedEconomicsNetworkError::Rejected(
                    "returned proposal candidate binding does not match the submitted candidate"
                        .to_string(),
                ));
            }
        }
        _ => {
            return Err(OrderedEconomicsNetworkError::Rejected(
                "returned proposal candidate presence does not match the submitted round"
                    .to_string(),
            ));
        }
    }
    let expected_digest = policy
        .engine()
        .proposal_digest(&proposal.proposal)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;

    // Collect one candidate vote per peer, filtering each individually --
    // `certificate_from_votes` itself aborts on the *first* invalid vote in
    // its input, so a single Byzantine/unreachable peer must never reach it
    // in the accepted set (that would deny a real three-of-four quorum).
    let mut candidate_votes: Vec<ConsensusVote> = Vec::new();
    let mut peer_vote_phase: Vec<(ValidatorId, String, PeerPhaseOutcome)> =
        Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let request = WireRequest {
            method: Method::Post,
            path: ORDERED_ECONOMICS_PROPOSAL_PATH.to_string(),
            content_type: Some(ORDERED_PROPOSAL_MEDIA_TYPE),
            body: proposal_bytes.clone(),
            deadline: Some(request_deadline(overall_deadline, per_request_cap)?),
        };
        let phase = match endpoint.client.transport().send(&request) {
            Err(error) => PeerPhaseOutcome::Unreachable(error.to_string()),
            Ok(response) => {
                match expect_success(
                    response,
                    node_wire::ordered_economics::ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
                )
                .map_err(|error| error.to_string())
                .and_then(|body| {
                    decode_ordered_event_output(&body).map_err(|error| error.to_string())
                }) {
                    Err(error) => PeerPhaseOutcome::Rejected(error),
                    Ok(output) => {
                        let mut accepted = false;
                        for message in &output.messages {
                            if let ConsensusMessage::Vote(vote) = message
                                && vote.validator == endpoint.validator_id
                                && vote.proposal_digest == expected_digest
                                && vote.view == proposal.proposal.view
                                && vote.height == proposal.proposal.height
                                && policy.engine().verify_vote(vote, &verifier).is_ok()
                            {
                                candidate_votes.push(vote.clone());
                                accepted = true;
                                break;
                            }
                        }
                        if accepted {
                            PeerPhaseOutcome::Applied(output)
                        } else {
                            PeerPhaseOutcome::Rejected(
                                "peer returned no valid vote for this proposal".to_string(),
                            )
                        }
                    }
                }
            }
        };
        artifacts
            .record_peer_result(
                round_index,
                &PeerResult {
                    validator_id: endpoint.validator_id,
                    endpoint_label: endpoint.endpoint_label.clone(),
                    vote_phase: phase.clone(),
                    certificate_phase: PeerPhaseOutcome::Skipped("certificate not sent yet".into()),
                },
            )
            .map_err(OrderedEconomicsNetworkError::Artifact)?;
        peer_vote_phase.push((
            endpoint.validator_id,
            endpoint.endpoint_label.clone(),
            phase,
        ));
    }

    let certificate: QuorumCertificate = policy
        .engine()
        .certificate_from_votes(&proposal.proposal, &candidate_votes, &verifier)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?
        .ok_or(OrderedEconomicsNetworkError::QuorumNotFormed)?;
    let qc_formed_from: Vec<ValidatorId> = certificate
        .votes
        .iter()
        .map(|vote| vote.validator)
        .collect();
    let certificate_bytes = consensus::encode_quorum_certificate(&certificate)
        .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
    artifacts
        .persist(
            &format!("round-{round_index}.certificate"),
            &certificate_bytes,
        )
        .map_err(OrderedEconomicsNetworkError::Artifact)?;
    artifacts
        .record_certified_round(round_index)
        .map_err(OrderedEconomicsNetworkError::Artifact)?;

    let mut peers: Vec<PeerResult> = Vec::with_capacity(endpoints.len());
    let mut any_replica_applied = false;
    for (endpoint, (validator_id, endpoint_label, vote_phase)) in
        endpoints.iter().zip(peer_vote_phase)
    {
        let request = WireRequest {
            method: Method::Post,
            path: ORDERED_ECONOMICS_CERTIFICATE_PATH.to_string(),
            content_type: Some(ORDERED_CERTIFICATE_MEDIA_TYPE),
            body: certificate_bytes.clone(),
            deadline: Some(request_deadline(overall_deadline, per_request_cap)?),
        };
        let certificate_phase = match endpoint.client.transport().send(&request) {
            Err(error) => PeerPhaseOutcome::Unreachable(error.to_string()),
            Ok(response) => {
                match expect_success(
                    response,
                    node_wire::ordered_economics::ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
                )
                .map_err(|error| error.to_string())
                .and_then(|body| {
                    decode_ordered_event_output(&body).map_err(|error| error.to_string())
                }) {
                    Err(error) => PeerPhaseOutcome::Rejected(error),
                    Ok(output) => {
                        any_replica_applied = true;
                        PeerPhaseOutcome::Applied(output)
                    }
                }
            }
        };
        let peer: PeerResult = PeerResult {
            validator_id,
            endpoint_label,
            vote_phase,
            certificate_phase,
        };
        artifacts
            .record_peer_result(round_index, &peer)
            .map_err(OrderedEconomicsNetworkError::Artifact)?;
        peers.push(peer);
    }

    // One QC is not three-chain finality. Nor is a peer HTTP 200 proof that
    // the operation actually committed. Report acknowledgements separately
    // from the request-bound `SubmissionOutcome::committed_outcome` acknowledgement.
    if !any_replica_applied {
        return Err(OrderedEconomicsNetworkError::NoReplicaAcknowledgement { peers });
    }

    Ok(RoundOutcome {
        proposal_bytes,
        certificate_bytes,
        height: proposal.proposal.height,
        proposal_digest: expected_digest,
        qc_formed_from,
        peers,
    })
}

/// Signerless replay of an already-persisted, exact proposal/certificate
/// sequence: resends each proposal to every endpoint's `observe` route (never
/// `proposal`, so no vote is ever produced) and each certificate to every
/// endpoint's `certificate` route, unchanged, in the declared order. Never
/// re-signs or re-derives anything.
/// One replayed round's per-peer outcome, mirroring [`RoundOutcome`]'s
/// vote/certificate-phase attribution.
pub struct ReplayRoundOutcome {
    pub observe_phase: Vec<(ValidatorId, PeerPhaseOutcome)>,
    pub certificate_phase: Vec<(ValidatorId, PeerPhaseOutcome)>,
}

/// A declared prefix may contain multiple complete economic windows. This
/// bounded recovery profile does not claim automatic history discovery.
pub const MAX_REPLAY_ROUNDS: usize = 64;
/// Aggregate canonical proposal/QC bytes accepted before recovery fan-out.
pub const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;

/// An [`ArtifactSink`] that persists nothing, used by [`replay_declared_prefix`]
/// for callers that do not need incremental recording.
struct NoopArtifactSink;

impl ArtifactSink for NoopArtifactSink {
    fn persist(&mut self, _name: &str, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}

/// Thin, backward-compatible wrapper over [`replay_declared_prefix_with_sink`]
/// using a sink that persists nothing.
pub fn replay_declared_prefix<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    policy: &OrderedEconomicsPolicy,
    rounds: &[(Vec<u8>, Vec<u8>)],
    overall_deadline: Instant,
    per_request_cap: Duration,
) -> Result<Vec<ReplayRoundOutcome>, OrderedEconomicsNetworkError> {
    let mut sink = NoopArtifactSink;
    replay_declared_prefix_with_sink(
        endpoints,
        policy,
        rounds,
        overall_deadline,
        per_request_cap,
        &mut sink,
    )
}

/// Verifies every committed outcome a peer response echoes back references
/// a block this call already independently authenticated in phase 1 -- an
/// unknown or mismatched block id is rejected here rather than quietly
/// trusted, even for an outcome that echoes an already-completed historical
/// round.
fn validate_known_blocks(
    output: &OrderedEventOutput,
    known_blocks: &[(u64, Digest32, [u8; 32], Digest32)],
) -> Result<(), String> {
    for outcome in &output.committed {
        let known = known_blocks
            .iter()
            .any(|(height, digest, request_id, candidate_digest)| {
                *height == outcome.block_height
                    && *digest == outcome.block_digest
                    && *request_id == outcome.request_id
                    && *candidate_digest == outcome.candidate_digest
            });
        if !known {
            return Err(
                "committed outcome references a block outside the preverified declared prefix"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Same as [`replay_declared_prefix`], but calls `sink.record_peer_result`
/// immediately after each peer own observe/certificate phases complete for
/// one round -- before moving to the next peer or round -- so an already-
/// acknowledged or already-rejected prefix step is durably recorded even if
/// a LATER round then fails and this call returns `Err`.
pub fn replay_declared_prefix_with_sink<T: Transport>(
    endpoints: &[OrderedEconomicsEndpoint<T>],
    policy: &OrderedEconomicsPolicy,
    rounds: &[(Vec<u8>, Vec<u8>)],
    overall_deadline: Instant,
    per_request_cap: Duration,
    sink: &mut dyn ArtifactSink,
) -> Result<Vec<ReplayRoundOutcome>, OrderedEconomicsNetworkError> {
    validate_ordered_economics_endpoints(endpoints, policy.engine().validator_set())?;
    if rounds.is_empty() || rounds.len() > MAX_REPLAY_ROUNDS {
        return Err(OrderedEconomicsNetworkError::Rejected(format!(
            "declared replay prefix has {} rounds, maximum is {MAX_REPLAY_ROUNDS}",
            rounds.len()
        )));
    }
    let total: Option<usize> = rounds.iter().try_fold(0usize, |sum, (p, q)| {
        sum.checked_add(p.len())?.checked_add(q.len())
    });
    if total.is_none_or(|length| length > MAX_REPLAY_BYTES) {
        return Err(OrderedEconomicsNetworkError::Rejected(
            "declared replay byte bound".into(),
        ));
    }
    let verifier = FastPathEd25519Verifier;

    // Phase 1: decode and verify the COMPLETE declared prefix -- every
    // proposal/certificate signature, each certificate's own binding to its
    // round's proposal (view/height/digest), and the parent-link chain (each
    // non-first round extends the previous certified block). Multiple complete
    // windows are allowed, at most one candidate per closed-profile window,
    // before a single POST. An altered or reordered artifact
    // fails here with zero network I/O.
    let mut decoded: Vec<(
        consensus::ConsensusProposal,
        Option<OrderedCandidate>,
        QuorumCertificate,
    )> = Vec::with_capacity(rounds.len());
    for (index, (proposal_bytes, certificate_bytes)) in rounds.iter().enumerate() {
        let decoded_proposal = decode_ordered_proposal(proposal_bytes)
            .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
        verify_ordered_proposal(policy, &decoded_proposal)?;
        let decoded_certificate = consensus::decode_quorum_certificate(certificate_bytes)
            .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
        policy
            .engine()
            .verify_certificate(&decoded_certificate, &verifier)
            .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
        let expected_digest = policy
            .engine()
            .proposal_digest(&decoded_proposal.proposal)
            .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
        if decoded_certificate.proposal_digest != expected_digest
            || decoded_certificate.view != decoded_proposal.proposal.view
            || decoded_certificate.height != decoded_proposal.proposal.height
        {
            return Err(OrderedEconomicsNetworkError::Rejected(
                "declared certificate does not bind this round's exact proposal".to_string(),
            ));
        }
        if index > 0 {
            let (_, _, previous_certificate) = &decoded[index - 1];
            let parent: &QuorumCertificate = &decoded_proposal.proposal.justify;
            if parent.proposal_digest != previous_certificate.proposal_digest
                || parent.height != previous_certificate.height
                || parent.view != previous_certificate.view
            {
                return Err(OrderedEconomicsNetworkError::Rejected(
                    "declared proposal does not extend the previous round's exact certificate"
                        .to_string(),
                ));
            }
        }
        let has_candidate = decoded_proposal.candidate.is_some();
        if has_candidate != !decoded_proposal.proposal.transactions.is_empty() {
            return Err(OrderedEconomicsNetworkError::Rejected(
                "declared proposal candidate presence does not match its transaction placement"
                    .to_string(),
            ));
        }
        if decoded_proposal.proposal.transactions.len() != usize::from(has_candidate)
            || (has_candidate && decoded_proposal.proposal.height % 3 != 1)
        {
            return Err(OrderedEconomicsNetworkError::Rejected(
                "declared proposal violates the closed scheduling profile".into(),
            ));
        }
        decoded.push((
            decoded_proposal.proposal,
            decoded_proposal.candidate,
            decoded_certificate,
        ));
    }
    let mut known_blocks: Vec<(u64, Digest32, [u8; 32], Digest32)> = Vec::new();
    for (index, (proposal, candidate, certificate)) in decoded.iter().enumerate() {
        if index + 2 < decoded.len()
            && let Some(candidate) = candidate
        {
            let digest = policy
                .candidate_digest(candidate)
                .map_err(|error| OrderedEconomicsNetworkError::Rejected(error.to_string()))?;
            known_blocks.push((
                proposal.height,
                certificate.proposal_digest,
                candidate.request_id,
                digest,
            ));
        }
    }
    let mut acknowledged: BTreeMap<[u8; 32], OrderedOutcome> = BTreeMap::new();

    // Phase 2: every artifact in the prefix is authenticated and internally
    // consistent -- only now does this function perform any network I/O.
    let mut round_outcomes = Vec::with_capacity(rounds.len());
    let mut unhealthy: BTreeSet<ValidatorId> = BTreeSet::new();
    for (round_index, (proposal_bytes, certificate_bytes)) in rounds.iter().enumerate() {
        let mut observe_phase = Vec::with_capacity(endpoints.len());
        let mut certificate_phase = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let (observe_result, certificate_result): (PeerPhaseOutcome, PeerPhaseOutcome) =
                if unhealthy.contains(&endpoint.validator_id) {
                    let skip = "skipped: this peer already failed an earlier declared prefix step";
                    (
                        PeerPhaseOutcome::Skipped(skip.to_string()),
                        PeerPhaseOutcome::Skipped(skip.to_string()),
                    )
                } else {
                    let request = WireRequest {
                        method: Method::Post,
                        path: ORDERED_ECONOMICS_OBSERVE_PATH.to_string(),
                        content_type: Some(ORDERED_PROPOSAL_MEDIA_TYPE),
                        body: proposal_bytes.clone(),
                        deadline: Some(request_deadline(overall_deadline, per_request_cap)?),
                    };
                    let mut observe_result = match endpoint.client.transport().send(&request) {
                        Err(error) => PeerPhaseOutcome::Unreachable(error.to_string()),
                        Ok(response) => {
                            match expect_success(
                                response,
                                node_wire::ordered_economics::ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
                            )
                            .map_err(|error| error.to_string())
                            .and_then(|body| {
                                decode_ordered_event_output(&body)
                                    .map_err(|error| error.to_string())
                            }) {
                                Ok(output) => PeerPhaseOutcome::Applied(output),
                                Err(error) => PeerPhaseOutcome::Rejected(error),
                            }
                        }
                    };
                    if let PeerPhaseOutcome::Applied(output) = &observe_result
                        && let Err(reason) = validate_known_blocks(output, &known_blocks)
                    {
                        observe_result = PeerPhaseOutcome::Rejected(reason);
                    }
                    if !matches!(observe_result, PeerPhaseOutcome::Applied(_)) {
                        // Never send a certificate to a peer whose own
                        // observe step for this exact round just failed.
                        let skip = "skipped: this peer own observe step failed this round";
                        (observe_result, PeerPhaseOutcome::Skipped(skip.to_string()))
                    } else {
                        sink.record_peer_result(
                            round_index,
                            &PeerResult {
                                validator_id: endpoint.validator_id,
                                endpoint_label: endpoint.endpoint_label.clone(),
                                vote_phase: observe_result.clone(),
                                certificate_phase: PeerPhaseOutcome::Skipped(
                                    "certificate not sent yet".into(),
                                ),
                            },
                        )
                        .map_err(OrderedEconomicsNetworkError::Artifact)?;
                        let request = WireRequest {
                            method: Method::Post,
                            path: ORDERED_ECONOMICS_CERTIFICATE_PATH.to_string(),
                            content_type: Some(ORDERED_CERTIFICATE_MEDIA_TYPE),
                            body: certificate_bytes.clone(),
                            deadline: Some(request_deadline(overall_deadline, per_request_cap)?),
                        };
                        let mut certificate_result =
                            match endpoint.client.transport().send(&request) {
                                Err(error) => PeerPhaseOutcome::Unreachable(error.to_string()),
                                Ok(response) => {
                                    match expect_success(
                                    response,
                                    node_wire::ordered_economics::ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
                                )
                                .map_err(|error| error.to_string())
                                .and_then(|body| {
                                    decode_ordered_event_output(&body)
                                        .map_err(|error| error.to_string())
                                }) {
                                    Ok(output) => PeerPhaseOutcome::Applied(output),
                                    Err(error) => PeerPhaseOutcome::Rejected(error),
                                }
                                }
                            };
                        if let PeerPhaseOutcome::Applied(output) = &certificate_result
                            && let Err(reason) = validate_known_blocks(output, &known_blocks)
                        {
                            certificate_result = PeerPhaseOutcome::Rejected(reason);
                        }
                        (observe_result, certificate_result)
                    }
                };
            if !matches!(observe_result, PeerPhaseOutcome::Applied(_))
                || !matches!(certificate_result, PeerPhaseOutcome::Applied(_))
            {
                unhealthy.insert(endpoint.validator_id);
            }
            let peer = PeerResult {
                validator_id: endpoint.validator_id,
                endpoint_label: endpoint.endpoint_label.clone(),
                vote_phase: observe_result,
                certificate_phase: certificate_result,
            };
            // Synced before moving to the next peer or round: an already-
            // acknowledged or already-rejected step survives a later round
            // failure, even though this call itself still returns `Err`.
            sink.record_peer_result(round_index, &peer)
                .map_err(OrderedEconomicsNetworkError::Artifact)?;
            for phase in [&peer.vote_phase, &peer.certificate_phase] {
                if let PeerPhaseOutcome::Applied(output) = phase {
                    for found in &output.committed {
                        if let Some(original) = acknowledged.get(&found.request_id)
                            && original != found
                        {
                            return Err(OrderedEconomicsNetworkError::ConflictingCommittedOutcome);
                        }
                        acknowledged.insert(found.request_id, found.clone());
                    }
                }
            }
            observe_phase.push((peer.validator_id, peer.vote_phase.clone()));
            certificate_phase.push((peer.validator_id, peer.certificate_phase.clone()));
        }
        if !certificate_phase
            .iter()
            .any(|(_, phase)| matches!(phase, PeerPhaseOutcome::Applied(_)))
        {
            return Err(OrderedEconomicsNetworkError::Rejected(
                "no replica acknowledged this declared recovery step".into(),
            ));
        }
        round_outcomes.push(ReplayRoundOutcome {
            observe_phase,
            certificate_phase,
        });
    }
    Ok(round_outcomes)
}

#[cfg(test)]
mod endpoint_preflight_tests {
    use super::*;
    use crate::transport::{TransportError, WireResponse};
    use protocol_types::Epoch;

    /// A transport that panics if ever dialed -- proves the preflight
    /// checks below reject before any network I/O, not merely "eventually".
    struct NeverTransport;
    impl Transport for NeverTransport {
        fn send(&self, _request: &WireRequest) -> Result<WireResponse, TransportError> {
            panic!("preflight must reject before any transport call");
        }
    }

    fn validator(id: u8) -> ValidatorInfo {
        ValidatorInfo {
            id: ValidatorId::new([id; 32]),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![id; 32],
        }
    }

    fn endpoint(id: u8, label: &str) -> OrderedEconomicsEndpoint<NeverTransport> {
        OrderedEconomicsEndpoint {
            validator_id: ValidatorId::new([id; 32]),
            endpoint_label: label.to_string(),
            client: Client::new(NeverTransport),
        }
    }

    #[test]
    fn rejects_an_empty_cohort_without_dialing_anything() {
        let set = ValidatorSet::new(Epoch::new(1), vec![validator(1)]).unwrap();
        let endpoints: Vec<OrderedEconomicsEndpoint<NeverTransport>> = Vec::new();
        assert_eq!(
            validate_ordered_economics_endpoints(&endpoints, &set),
            Err(OrderedEconomicsEndpointConfigError::NoEndpoints)
        );
    }

    #[test]
    fn rejects_a_duplicate_validator_id_without_dialing_anything() {
        let set = ValidatorSet::new(Epoch::new(1), vec![validator(1), validator(2)]).unwrap();
        let endpoints = vec![endpoint(1, "a"), endpoint(1, "b")];
        assert_eq!(
            validate_ordered_economics_endpoints(&endpoints, &set),
            Err(OrderedEconomicsEndpointConfigError::DuplicateValidator(
                ValidatorId::new([1; 32])
            ))
        );
    }

    #[test]
    fn rejects_a_duplicate_endpoint_label_without_dialing_anything() {
        let set = ValidatorSet::new(Epoch::new(1), vec![validator(1), validator(2)]).unwrap();
        let endpoints = vec![endpoint(1, "same"), endpoint(2, "same")];
        assert_eq!(
            validate_ordered_economics_endpoints(&endpoints, &set),
            Err(OrderedEconomicsEndpointConfigError::DuplicateLabel(
                "same".to_string()
            ))
        );
    }

    #[test]
    fn rejects_a_validator_absent_from_the_local_genesis_pin_without_dialing_anything() {
        let set = ValidatorSet::new(Epoch::new(1), vec![validator(1)]).unwrap();
        let endpoints = vec![endpoint(9, "unregistered")];
        assert_eq!(
            validate_ordered_economics_endpoints(&endpoints, &set),
            Err(OrderedEconomicsEndpointConfigError::UnknownValidator(
                ValidatorId::new([9; 32])
            ))
        );
    }

    #[test]
    fn accepts_a_well_formed_cohort() {
        let set = ValidatorSet::new(Epoch::new(1), vec![validator(1), validator(2)]).unwrap();
        let endpoints = vec![endpoint(1, "a"), endpoint(2, "b")];
        assert_eq!(
            validate_ordered_economics_endpoints(&endpoints, &set),
            Ok(())
        );
    }
}

#[cfg(test)]
mod recovery_preflight_tests {
    use super::*;
    use crate::transport::{TransportError, WireResponse};
    use consensus::{ConsensusEngine, ConsensusEvent, ConsensusSigner};
    use ed25519_zebra::{SigningKey, VerificationKey};
    use protocol_types::{
        ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Signer {
        id: ValidatorId,
        key: SigningKey,
    }
    impl ConsensusSigner for Signer {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.key.sign(bytes).to_bytes().to_vec())
        }
    }
    fn fixture() -> (OrderedEconomicsPolicy, Vec<Signer>) {
        let chain: ChainId = ChainId::new("ordered-client-test").unwrap();
        let protocol: ProtocolVersion = ProtocolVersion::new(3);
        let epoch: Epoch = Epoch::new(0);
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain.clone(),
            protocol,
            vec![HashSuiteSchedule {
                activation_epoch: epoch,
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let signers: Vec<Signer> = (1u8..=4)
            .map(|id| Signer {
                id: ValidatorId::new([id; 32]),
                key: SigningKey::from([id; 32]),
            })
            .collect();
        let set: ValidatorSet = ValidatorSet::new(
            epoch,
            signers
                .iter()
                .map(|s| ValidatorInfo {
                    id: s.id,
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: <[u8; 32]>::from(VerificationKey::from(&s.key)).to_vec(),
                })
                .collect(),
        )
        .unwrap();
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
            PublicationContext::new(chain, protocol, epoch).unwrap(),
            AtomicityDomainId::new([0x11; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
            set,
            resolver,
        )
        .unwrap();
        (policy, signers)
    }

    fn empty_prefix(
        policy: &OrderedEconomicsPolicy,
        signers: &[Signer],
        count: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let engine = policy.engine();
        let mut state: consensus::ConsensusState = engine.genesis_state(0);
        let mut rounds: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for _ in 0..count {
            let leader: ValidatorId = engine.validator_set().leader(state.current_view).unwrap();
            let proposal = engine
                .propose(
                    &state,
                    Vec::new(),
                    signers.iter().find(|s| s.id == leader).unwrap(),
                )
                .unwrap();
            let votes: Vec<ConsensusVote> = signers
                .iter()
                .map(|signer| {
                    engine
                        .on_event(
                            &state,
                            ConsensusEvent::Proposal(proposal.clone()),
                            signer,
                            &FastPathEd25519Verifier,
                        )
                        .unwrap()
                        .outbound_messages
                        .into_iter()
                        .find_map(|message| match message {
                            ConsensusMessage::Vote(vote) => Some(vote),
                            _ => None,
                        })
                        .unwrap()
                })
                .collect();
            let qc: QuorumCertificate = engine
                .certificate_from_votes(&proposal, &votes, &FastPathEd25519Verifier)
                .unwrap()
                .unwrap();
            state = engine
                .on_observer_event(
                    &state,
                    ConsensusEvent::Proposal(proposal.clone()),
                    &FastPathEd25519Verifier,
                )
                .unwrap()
                .state;
            state = engine
                .on_observer_event(
                    &state,
                    ConsensusEvent::Certificate(qc.clone()),
                    &FastPathEd25519Verifier,
                )
                .unwrap()
                .state;
            rounds.push((
                node_core::ordered_economics::encode_ordered_proposal(
                    &node_core::ordered_economics::OrderedProposal {
                        proposal,
                        candidate: None,
                    },
                )
                .unwrap(),
                consensus::encode_quorum_certificate(&qc).unwrap(),
            ));
        }
        rounds
    }

    struct Mock {
        status: Option<Vec<u8>>,
        calls: Arc<AtomicUsize>,
        panic_on_post: bool,
        /// When set, every POST whose 1-based call count reaches this
        /// threshold or later fails as unreachable -- simulates a peer
        /// going offline partway through a multi-round recovery.
        fail_posts_from: Option<usize>,
        /// When set, every successful POST response echoes this exact
        /// committed outcome, to exercise response-binding validation.
        post_committed: Option<OrderedOutcome>,
    }
    impl Transport for Mock {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if request.method == Method::Post {
                assert!(
                    !self.panic_on_post,
                    "complete prefix must reject before the first POST"
                );
                if let Some(threshold) = self.fail_posts_from
                    && count >= threshold
                {
                    return Err(TransportError::RequestDeadlineExceeded);
                }
                let output = OrderedEventOutput {
                    messages: Vec::new(),
                    committed: self.post_committed.clone().into_iter().collect(),
                };
                return Ok(WireResponse {
                    status: 200,
                    content_type: Some(
                        node_wire::ordered_economics::ORDERED_EVENT_OUTPUT_MEDIA_TYPE.into(),
                    ),
                    body: node_core::ordered_economics::encode_ordered_event_output(&output)
                        .unwrap(),
                });
            }
            match &self.status {
                Some(bytes) => Ok(WireResponse {
                    status: 200,
                    content_type: Some(
                        node_wire::ordered_economics::ORDERED_STATUS_MEDIA_TYPE.into(),
                    ),
                    body: bytes.clone(),
                }),
                None => Err(TransportError::RequestDeadlineExceeded),
            }
        }
    }
    fn endpoints(
        policy: &OrderedEconomicsPolicy,
        views: &[Option<u64>],
        panic_on_post: bool,
    ) -> (Vec<OrderedEconomicsEndpoint<Mock>>, Arc<AtomicUsize>) {
        endpoints_full(policy, views, panic_on_post, None, None)
    }
    fn endpoints_with_post_failure(
        policy: &OrderedEconomicsPolicy,
        views: &[Option<u64>],
        panic_on_post: bool,
        fail_posts_from: Option<usize>,
    ) -> (Vec<OrderedEconomicsEndpoint<Mock>>, Arc<AtomicUsize>) {
        endpoints_full(policy, views, panic_on_post, fail_posts_from, None)
    }
    fn endpoints_with_committed(
        policy: &OrderedEconomicsPolicy,
        views: &[Option<u64>],
        panic_on_post: bool,
        post_committed: OrderedOutcome,
    ) -> (Vec<OrderedEconomicsEndpoint<Mock>>, Arc<AtomicUsize>) {
        endpoints_full(policy, views, panic_on_post, None, Some(post_committed))
    }
    fn endpoints_full(
        policy: &OrderedEconomicsPolicy,
        views: &[Option<u64>],
        panic_on_post: bool,
        fail_posts_from: Option<usize>,
        post_committed: Option<OrderedOutcome>,
    ) -> (Vec<OrderedEconomicsEndpoint<Mock>>, Arc<AtomicUsize>) {
        let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let genesis = policy.engine().genesis_state(0);
        let values: Vec<OrderedEconomicsEndpoint<Mock>> = views
            .iter()
            .enumerate()
            .map(|(index, view)| OrderedEconomicsEndpoint {
                validator_id: ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
                endpoint_label: format!("peer-{index}"),
                client: Client::new(Mock {
                    status: view.map(|current_view| {
                        node_core::ordered_economics::encode_ordered_status(&OrderedStatus {
                            current_view,
                            high_qc: genesis.high_qc.clone(),
                            committed_height: 0,
                        })
                        .unwrap()
                    }),
                    calls: calls.clone(),
                    panic_on_post,
                    fail_posts_from,
                    post_committed: post_committed.clone(),
                }),
            })
            .collect();
        (values, calls)
    }
    #[test]
    fn unreachable_first_peer_does_not_control_routing() {
        let (policy, _) = fixture();
        let (peers, _) = endpoints(&policy, &[None, Some(1), Some(1), Some(1)], true);
        assert_eq!(
            routing_view(
                &peers,
                &policy,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50)
            )
            .unwrap(),
            Some(1)
        );
    }
    #[test]
    fn one_invented_maximum_view_is_not_a_routing_quorum() {
        let (policy, _) = fixture();
        let (peers, _) = endpoints(&policy, &[Some(1), Some(1), Some(1), Some(u64::MAX)], true);
        assert_eq!(
            routing_view(
                &peers,
                &policy,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50)
            )
            .unwrap(),
            Some(1)
        );
    }
    #[test]
    fn authentic_early_rounds_do_not_post_before_invalid_last_proof() {
        let (policy, signers) = fixture();
        let (peers, calls) = endpoints(&policy, &[Some(1)], true);
        let mut rounds = empty_prefix(&policy, &signers, 6);
        rounds.last_mut().unwrap().1[0] ^= 1;
        assert!(
            replay_declared_prefix(
                &peers,
                &policy,
                &rounds,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn reordered_authentic_prefix_rejects_before_post() {
        let (policy, signers) = fixture();
        let (peers, calls) = endpoints(&policy, &[Some(1)], true);
        let mut rounds = empty_prefix(&policy, &signers, 6);
        rounds.swap(3, 4);
        assert!(
            replay_declared_prefix(
                &peers,
                &policy,
                &rounds,
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn multiple_complete_windows_are_not_limited_to_one_operation() {
        let (policy, signers) = fixture();
        let (peers, calls) = endpoints(&policy, &[Some(1)], false);
        let rounds = empty_prefix(&policy, &signers, 6);
        assert_eq!(
            replay_declared_prefix(
                &peers,
                &policy,
                &rounds,
                Instant::now() + Duration::from_secs(2),
                Duration::from_millis(50)
            )
            .unwrap()
            .len(),
            6
        );
        assert_eq!(calls.load(Ordering::SeqCst), 12);
    }
    #[test]
    fn empty_recovery_and_expired_budget_are_not_success() {
        let (policy, signers) = fixture();
        let (peers, calls) = endpoints(&policy, &[Some(1)], true);
        assert!(
            replay_declared_prefix(
                &peers,
                &policy,
                &[],
                Instant::now() + Duration::from_secs(1),
                Duration::from_millis(50)
            )
            .is_err()
        );
        let rounds = empty_prefix(&policy, &signers, 1);
        assert!(
            replay_declared_prefix(
                &peers,
                &policy,
                &rounds,
                Instant::now(),
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// An `ArtifactSink` that records every per-peer replay result as it
    /// happens, in call order -- proves incremental sync, not a batched
    /// report built only after the whole call returns.
    struct RecordingSink {
        records: Vec<(usize, ValidatorId, bool, bool)>,
    }
    impl ArtifactSink for RecordingSink {
        fn persist(&mut self, _name: &str, _bytes: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn record_peer_result(&mut self, round: usize, peer: &PeerResult) -> std::io::Result<()> {
            self.records.push((
                round,
                peer.validator_id,
                matches!(peer.vote_phase, PeerPhaseOutcome::Applied(_)),
                matches!(peer.certificate_phase, PeerPhaseOutcome::Applied(_)),
            ));
            Ok(())
        }
    }

    #[test]
    fn a_later_round_failure_still_records_earlier_rounds_before_returning_err() {
        let (policy, signers) = fixture();
        // Real signed empty HotStuff rounds, real mock transport: two
        // successful rounds (4 POSTs: observe+certificate each), then the
        // third round own observe call fails as unreachable.
        let (peers, calls) = endpoints_with_post_failure(&policy, &[Some(1)], false, Some(5));
        let rounds = empty_prefix(&policy, &signers, 4);
        let mut sink = RecordingSink {
            records: Vec::new(),
        };
        let result = replay_declared_prefix_with_sink(
            &peers,
            &policy,
            &rounds,
            Instant::now() + Duration::from_secs(2),
            Duration::from_millis(50),
            &mut sink,
        );
        assert!(
            result.is_err(),
            "round 2 own observe failure must surface as Err"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert!(
            sink.records
                .iter()
                .any(|(round, _, vote, cert)| *round == 0 && *vote && *cert),
            "round 0 must be recorded as fully acknowledged before the later failure"
        );
        assert!(
            sink.records
                .iter()
                .any(|(round, _, vote, cert)| *round == 1 && *vote && *cert),
            "round 1 must be recorded as fully acknowledged before the later failure"
        );
        assert!(
            sink.records
                .iter()
                .any(|(round, _, vote, _)| *round == 2 && !vote),
            "round 2 own failed observe step must still be recorded, not silently dropped"
        );
        assert!(
            sink.records.iter().all(|(round, ..)| *round <= 2),
            "no step past the first failure was ever attempted"
        );
    }

    #[test]
    fn replay_rejects_a_peer_response_echoing_an_unknown_committed_block() {
        let (policy, signers) = fixture();
        let rounds = empty_prefix(&policy, &signers, 2);
        // A structurally well-formed committed outcome, but bound to a
        // block height/digest that never appeared in this preverified
        // declared prefix -- must be rejected, not quietly trusted.
        let poisoned = OrderedOutcome {
            candidate_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
            request_id: [0x44; 32],
            block_height: 999,
            block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
            output: node_core::NodeOutput::default(),
        };
        let (peers, _) = endpoints_with_committed(&policy, &[Some(1)], false, poisoned);
        let result = replay_declared_prefix(
            &peers,
            &policy,
            &rounds,
            Instant::now() + Duration::from_secs(2),
            Duration::from_millis(50),
        );
        assert!(
            result.is_err(),
            "an unknown committed block reference must fail closed, not be silently accepted"
        );
    }
}
