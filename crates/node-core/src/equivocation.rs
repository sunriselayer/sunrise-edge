//! DR-0133 (FastVote Phase 2 Slice 3): durable, idempotent submission of
//! canonical FastVote/EpochTransitionVote equivocation evidence.
//!
//! Every `submit_*` function is an in-process, local-operator-invoked
//! node-core function -- the same authorization class as
//! [`crate::fast_path::prepare`]/[`crate::fast_path::apply`] and
//! [`crate::epoch_transition::propose_and_vote`]/[`crate::epoch_transition::activate`]
//! -- with no new externally reachable event family. Cryptographic validity
//! against the historical validator set is the only authorization needed;
//! `native-http` gains nothing from this module. No `submit_*` function
//! signs anything: evidence submission only re-verifies already-signed
//! statements.
//!
//! Evidence is durably keyed by a normalized, signature-excluding identity
//! (§6), never by full statement bytes, so the identical logical conflict
//! submitted any number of times, in any signature encoding, resolves to
//! exactly one row. Evidence rows are permanent and deliberately excluded
//! from [`crate::genesis::install_genesis_with_history`]'s restart-verify
//! chain (§9): they never fence against anything, so folding an unbounded,
//! ever-growing evidence set into a chain re-walked on every restart would
//! add startup cost for no safety benefit. Structural decode alone can never
//! detect a well-formed-but-wrong signature; a consumer that needs live
//! cryptographic assurance must explicitly call `verify_*` again.
#![allow(clippy::result_large_err)]
use super::*;
use consensus::{ConsensusError, EpochTransitionVote, FastVote};
use execution::publication::{PublicationContext, PublicationError};
use protocol_types::ValidatorId;
use validator_set::ValidatorSet;

const FASTPATH_EQUIVOCATION_EVIDENCE_RECORD_TYPE: u16 = 0x6429;
const ENCODING_VERSION: u16 = 1;

/// Fail-closed DR-0133 equivocation-evidence errors.
#[derive(Debug)]
pub enum EquivocationEvidenceError {
    /// Storage or node boundary failure.
    Node(NodeCoreError),
    /// `consensus::equivocation` build/decode/verify failure.
    Consensus(ConsensusError),
    /// The shared validator-row decoder (`fast_path::decode_validator_set_row`)
    /// failed.
    FastPath(fast_path::FastPathError),
    /// Publication context construction failed.
    Publication(PublicationError),
    /// Equivocation-evidence-specific invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for EquivocationEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::Consensus(error) => error.fmt(f),
            Self::FastPath(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for EquivocationEvidenceError {}
impl From<NodeCoreError> for EquivocationEvidenceError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<ConsensusError> for EquivocationEvidenceError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}
impl From<fast_path::FastPathError> for EquivocationEvidenceError {
    fn from(error: fast_path::FastPathError) -> Self {
        Self::FastPath(error)
    }
}
impl From<PublicationError> for EquivocationEvidenceError {
    fn from(error: PublicationError) -> Self {
        Self::Publication(error)
    }
}
impl From<DurableReadError> for EquivocationEvidenceError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for EquivocationEvidenceError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for EquivocationEvidenceError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for EquivocationEvidenceError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(error))
    }
}
impl From<HashingError> for EquivocationEvidenceError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}

type EqResult<T> = Result<T, EquivocationEvidenceError>;

fn invalid<T>(message: &'static str) -> EqResult<T> {
    Err(EquivocationEvidenceError::Invalid(message))
}

/// Outcome of one `submit_*` call: a freshly persisted row, or the
/// pre-existing row for the identical normalized identity (no
/// re-verification, matching `epoch_transition::activate`'s own
/// already-activated precedent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EquivocationEvidenceOutcome<T> {
    /// This call durably persisted a new row.
    Recorded(T),
    /// The identical normalized identity was already durably recorded.
    AlreadyRecorded(T),
}

/// Frame `0x6429/v1`: one durable, permanent, append-only equivocation
/// evidence row, keyed by
/// [`local_instance_state::fastpath_equivocation_evidence_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathEquivocationEvidenceRecord {
    /// The exact encoded `0xD00D`/`0xD00E`/`0xD00F` frame; self-describing
    /// via its own nested type id, no separate family field.
    pub evidence_bytes: Vec<u8>,
    /// Local-per-node checkpoint marker, excluded from `conflict_digest`,
    /// the same convention `FastPathEpochTransitionRecord.activated_at_checkpoint`
    /// uses.
    pub recorded_at_checkpoint: u64,
}

/// Encodes Frame `0x6429/v1`.
pub fn encode_fastpath_equivocation_evidence_record(
    record: &FastPathEquivocationEvidenceRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_EQUIVOCATION_EVIDENCE_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, record.evidence_bytes.clone())?;
    frame.field_u64(2, record.recorded_at_checkpoint)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x6429/v1`.
pub fn decode_fastpath_equivocation_evidence_record(
    bytes: &[u8],
) -> Result<FastPathEquivocationEvidenceRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_EQUIVOCATION_EVIDENCE_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
        evidence_bytes: frame.required_field(1)?.to_vec(),
        recorded_at_checkpoint: frame.required_u64(2)?,
    };
    if encode_fastpath_equivocation_evidence_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fastpath equivocation evidence record",
        ));
    }
    Ok(record)
}

/// One decoded equivocation-evidence envelope, dispatched by nested type id
/// (`0xD00D`/`0xD00E`/`0xD00F`) without the caller needing to already know
/// which class a stored row holds. Shared by this module's own
/// already-recorded resolution and by
/// [`crate::query::query_fastpath_equivocation_evidence`]'s cross-check.
pub(crate) enum DecodedEquivocationEvidence {
    FastVote(consensus::FastVoteEquivocationEvidence),
    ObjectConflict(consensus::FastVoteObjectConflictEvidence),
    EpochTransition(consensus::EpochTransitionEquivocationEvidence),
}

impl DecodedEquivocationEvidence {
    pub(crate) fn chain_id(&self) -> &ChainId {
        match self {
            Self::FastVote(evidence) => &evidence.chain_id,
            Self::ObjectConflict(evidence) => &evidence.chain_id,
            Self::EpochTransition(evidence) => &evidence.chain_id,
        }
    }
    pub(crate) fn epoch(&self) -> Epoch {
        match self {
            Self::FastVote(evidence) => evidence.epoch,
            Self::ObjectConflict(evidence) => evidence.epoch,
            Self::EpochTransition(evidence) => evidence.epoch,
        }
    }
    pub(crate) fn validator(&self) -> ValidatorId {
        match self {
            Self::FastVote(evidence) => evidence.validator,
            Self::ObjectConflict(evidence) => evidence.validator,
            Self::EpochTransition(evidence) => evidence.validator,
        }
    }
}

/// Decodes `evidence_bytes` by trying each class's own strict decoder in
/// turn; canonical framing's self-describing type id means exactly one ever
/// succeeds for well-formed input.
pub(crate) fn decode_dispatched(evidence_bytes: &[u8]) -> EqResult<DecodedEquivocationEvidence> {
    if let Ok(evidence) = consensus::decode_fast_vote_equivocation_evidence(evidence_bytes) {
        return Ok(DecodedEquivocationEvidence::FastVote(evidence));
    }
    if let Ok(evidence) = consensus::decode_fast_vote_object_conflict_evidence(evidence_bytes) {
        return Ok(DecodedEquivocationEvidence::ObjectConflict(evidence));
    }
    let evidence = consensus::decode_epoch_transition_equivocation_evidence(evidence_bytes)?;
    Ok(DecodedEquivocationEvidence::EpochTransition(evidence))
}

fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Class (a) normalized identity preimage (DR-0133 §6): excludes every
/// signature. Domain tag `"fastvote-equivocation-identity-v1"`.
fn fast_vote_evidence_normalized_identity(
    evidence: &consensus::FastVoteEquivocationEvidence,
) -> EqResult<Vec<u8>> {
    let mut out: Vec<u8> = b"fastvote-equivocation-identity-v1".to_vec();
    out.extend_from_slice(evidence.chain_id.as_str().as_bytes());
    out.extend_from_slice(&evidence.protocol_version.get().to_be_bytes());
    out.extend_from_slice(&evidence.epoch.get().to_be_bytes());
    out.extend_from_slice(evidence.validator.as_bytes());
    out.extend_from_slice(&evidence.tx_hash.bytes());
    push_length_prefixed(
        &mut out,
        &consensus::encode_fast_vote_payload(&evidence.low)?,
    );
    push_length_prefixed(
        &mut out,
        &consensus::encode_fast_vote_payload(&evidence.high)?,
    );
    Ok(out)
}

/// Class (b) normalized identity preimage (DR-0133 §6): excludes every
/// signature and both raw preimages (already anchored via
/// `locked_objects_digest`, itself inside each payload). Domain tag
/// `"fastvote-object-conflict-identity-v1"`.
fn fast_vote_object_conflict_normalized_identity(
    evidence: &consensus::FastVoteObjectConflictEvidence,
) -> EqResult<Vec<u8>> {
    let mut out: Vec<u8> = b"fastvote-object-conflict-identity-v1".to_vec();
    out.extend_from_slice(evidence.chain_id.as_str().as_bytes());
    out.extend_from_slice(&evidence.protocol_version.get().to_be_bytes());
    out.extend_from_slice(&evidence.epoch.get().to_be_bytes());
    out.extend_from_slice(evidence.validator.as_bytes());
    out.extend_from_slice(evidence.conflicting_object_id.as_bytes());
    out.extend_from_slice(&evidence.conflicting_version.to_be_bytes());
    push_length_prefixed(
        &mut out,
        &consensus::encode_fast_vote_payload(&evidence.low)?,
    );
    push_length_prefixed(
        &mut out,
        &consensus::encode_fast_vote_payload(&evidence.high)?,
    );
    Ok(out)
}

/// Class (c) normalized identity preimage (DR-0133 §6): excludes every
/// signature. Domain tag `"epoch-transition-equivocation-identity-v1"`.
fn epoch_transition_evidence_normalized_identity(
    evidence: &consensus::EpochTransitionEquivocationEvidence,
) -> EqResult<Vec<u8>> {
    let mut out: Vec<u8> = b"epoch-transition-equivocation-identity-v1".to_vec();
    out.extend_from_slice(evidence.chain_id.as_str().as_bytes());
    out.extend_from_slice(&evidence.protocol_version.get().to_be_bytes());
    out.extend_from_slice(&evidence.epoch.get().to_be_bytes());
    out.extend_from_slice(evidence.validator.as_bytes());
    push_length_prefixed(
        &mut out,
        &consensus::encode_epoch_transition_vote_payload(&evidence.low)?,
    );
    push_length_prefixed(
        &mut out,
        &consensus::encode_epoch_transition_vote_payload(&evidence.high)?,
    );
    Ok(out)
}

/// Recomputes the normalized-identity digest of one already-decoded
/// evidence envelope, dispatched by class. Shared by this module's
/// already-recorded resolution and by
/// [`crate::query::query_fastpath_equivocation_evidence`]'s cross-check.
pub(crate) fn normalized_identity_digest(
    resolver: &HashSuiteResolver,
    decoded: &DecodedEquivocationEvidence,
) -> EqResult<Digest32> {
    let (epoch, identity_bytes) = match decoded {
        DecodedEquivocationEvidence::FastVote(evidence) => (
            evidence.epoch,
            fast_vote_evidence_normalized_identity(evidence)?,
        ),
        DecodedEquivocationEvidence::ObjectConflict(evidence) => (
            evidence.epoch,
            fast_vote_object_conflict_normalized_identity(evidence)?,
        ),
        DecodedEquivocationEvidence::EpochTransition(evidence) => (
            evidence.epoch,
            epoch_transition_evidence_normalized_identity(evidence)?,
        ),
    };
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, &identity_bytes)?)
}

/// Requires `resolver`'s bound chain/protocol context to match the caller's
/// declared parameters, the same check `authenticated_object_effects.rs`,
/// `object_snapshots.rs`, and `local_execution.rs` already make before
/// trusting a caller-supplied resolver (DR-0133 §6).
fn require_resolver_context(
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
) -> EqResult<()> {
    if resolver.chain_id() != chain || resolver.protocol_version() != protocol_version {
        return invalid("resolver does not match declared chain/protocol context");
    }
    Ok(())
}

/// Decodes a stored evidence row and requires its own recomputed
/// normalized-identity digest equal `conflict_digest`: the content-
/// self-consistency check the key's digest protects (DR-0133 §6). A row
/// whose decoded content disagrees with its own key digest is
/// tampered/corrupt and rejected outright, never silently returned.
fn resolve_existing(
    resolver: &HashSuiteResolver,
    existing_bytes: &[u8],
    conflict_digest: Digest32,
) -> EqResult<FastPathEquivocationEvidenceRecord> {
    let existing: FastPathEquivocationEvidenceRecord =
        decode_fastpath_equivocation_evidence_record(existing_bytes)?;
    let decoded: DecodedEquivocationEvidence = decode_dispatched(&existing.evidence_bytes)?;
    let existing_identity_digest: Digest32 = normalized_identity_digest(resolver, &decoded)?;
    if existing_identity_digest == conflict_digest {
        Ok(existing)
    } else {
        Err(EquivocationEvidenceError::Node(
            NodeCoreError::PersistenceInvariant(
                "evidence record does not match its own key digest",
            ),
        ))
    }
}

/// The shared, idempotent, content-addressed `Put` commit every `submit_*`
/// class ends with (DR-0133 §8): a benign same-content race resolves to
/// `AlreadyRecorded` by re-reading, never a raw conflict; any other
/// rejection or an indeterminate outcome is a real, safely retryable
/// [`NodeCoreError`], mirroring `epoch_transition::activate`'s own real
/// `DurableCommitOutcome`/`DurableCommitRejection` mapping.
#[allow(clippy::too_many_arguments)]
fn commit_new_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    key: Vec<u8>,
    observed_revision: StateRevision,
    checkpoint: u64,
    evidence_bytes: Vec<u8>,
    conflict_digest: Digest32,
) -> EqResult<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>> {
    let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
        evidence_bytes,
        recorded_at_checkpoint: checkpoint,
    };
    let record_bytes: Vec<u8> = encode_fastpath_equivocation_evidence_record(&record)?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![StateReadAssertion::new(
            key.clone(),
            observed_revision,
        )?])?,
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(
            key.clone(),
            StateMutation::Put(record_bytes),
        )?])?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(EquivocationEvidenceOutcome::Recorded(record)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: conflicting,
            ..
        }) if conflicting == key => {
            let re_observed: VersionedStateValue =
                store.get_versioned_durable(context, domain, &key)?;
            let re_existing_bytes: &[u8] = re_observed.value().ok_or(
                EquivocationEvidenceError::Node(NodeCoreError::PersistenceInvariant(
                    "evidence row vanished after a reported conflict",
                )),
            )?;
            let existing: FastPathEquivocationEvidenceRecord =
                resolve_existing(resolver, re_existing_bytes, conflict_digest)?;
            Ok(EquivocationEvidenceOutcome::AlreadyRecorded(existing))
        }
        DurableCommitOutcome::Rejected(reason) => Err(EquivocationEvidenceError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        DurableCommitOutcome::Indeterminate(reason) => Err(EquivocationEvidenceError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}

/// Reads (unfenced) the live [`local_instance_state::FastPathEpochRecord`]
/// and the historical [`epoch_transition::FastPathEpochTransitionRecord`]
/// chain to determine the chain-anchored trusted validator-set digest for
/// `evidence_epoch`, then loads and validates the historical
/// [`fast_path::records::FastPathValidatorSetRecord`] row for that epoch and
/// requires its digest match that anchor (DR-0133 §7). Relies on, without
/// repeating, DR-0132 §7's restart-verify chain, which has already
/// cryptographically re-verified every historical validator-set row and
/// every transition record through the live epoch before this node was
/// considered started.
///
/// `protocol_version` is an explicit parameter, not inferred from
/// `resolver.protocol_version()`: this function is a `pub(crate)` boundary
/// of its own and must not silently assume a caller threading a resolver
/// through without also passing the value it addresses
/// `PublicationContext::new` with.
fn load_historical_validator_set_with_revisions<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    evidence_epoch: Epoch,
) -> EqResult<(ValidatorSet, BTreeMap<Vec<u8>, StateRevision>)> {
    let mut revisions: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(chain)?;
    let epoch_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &epoch_key)?;
    revisions.insert(epoch_key, epoch_observed.revision());
    let live: local_instance_state::FastPathEpochRecord =
        local_instance_state::decode_fastpath_epoch_record(epoch_observed.value().ok_or(
            EquivocationEvidenceError::Invalid("fast-path epoch record not installed"),
        )?)?;

    let trusted_anchor: Digest32 = if evidence_epoch == live.current_epoch {
        live.current_validator_set_digest
    } else if evidence_epoch.get() < live.current_epoch.get() {
        let next_epoch: Epoch = Epoch::new(evidence_epoch.get().checked_add(1).ok_or(
            EquivocationEvidenceError::Invalid("evidence epoch overflow"),
        )?);
        let transition_key: Vec<u8> =
            local_instance_state::fastpath_epoch_transition_key(chain, next_epoch)?;
        let transition_observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &transition_key)?;
        revisions.insert(transition_key, transition_observed.revision());
        let record: epoch_transition::FastPathEpochTransitionRecord =
            epoch_transition::decode_fastpath_epoch_transition_record(
                transition_observed
                    .value()
                    .ok_or(EquivocationEvidenceError::Invalid(
                        "no transition record for the evidence epoch",
                    ))?,
            )?;
        if record.from_epoch != evidence_epoch {
            return invalid("no transition record for the evidence epoch");
        }
        record.previous_validator_set_digest
    } else {
        return invalid("evidence epoch is not yet committed");
    };

    let validator_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, evidence_epoch)?;
    let key: Vec<u8> = local_instance_state::fastpath_validator_set_key(&validator_context)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    revisions.insert(key, observed.revision());
    let bytes: &[u8] = observed.value().ok_or(EquivocationEvidenceError::Invalid(
        "no committed validator set for the evidence epoch",
    ))?;
    let validator_set: ValidatorSet =
        fast_path::decode_validator_set_row(bytes, &validator_context)?;
    let digest: Digest32 = validator_set.digest(resolver).map_err(|_| {
        EquivocationEvidenceError::Invalid("historical validator set digest computation failed")
    })?;
    if digest != trusted_anchor {
        return invalid(
            "historical validator set does not match the restart-verified transition chain",
        );
    }
    Ok((validator_set, revisions))
}

/// Loads the chain-anchored historical validator set without carrying CAS
/// assertions into a later mutation. Evidence-only callers do not write the
/// loaded rows; fee claims use [`load_historical_validator_set_fenced`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_historical_validator_set<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    evidence_epoch: Epoch,
) -> EqResult<ValidatorSet> {
    Ok(load_historical_validator_set_with_revisions(
        store,
        context,
        domain,
        resolver,
        chain,
        protocol_version,
        evidence_epoch,
    )?
    .0)
}

/// Loads the same historical set while fencing every epoch/transition/set
/// revision that established its chain-anchored digest. A fee claim must
/// include these assertions in the same CAS as its escrow payout.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_historical_validator_set_fenced<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    evidence_epoch: Epoch,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> EqResult<ValidatorSet> {
    let (set, revisions): (ValidatorSet, BTreeMap<Vec<u8>, StateRevision>) =
        load_historical_validator_set_with_revisions(
            store,
            context,
            domain,
            resolver,
            chain,
            protocol_version,
            evidence_epoch,
        )?;
    for (key, revision) in revisions {
        if let Some(previous) = reads.insert(key, revision)
            && previous != revision
        {
            return Err(EquivocationEvidenceError::Node(
                NodeCoreError::StateConflict,
            ));
        }
    }
    Ok(set)
}

/// Class (a): the same validator signed two [`FastVote`]s for the identical
/// `tx_hash` with a differing payload (DR-0133 §1/§8).
#[allow(clippy::too_many_arguments)]
pub fn submit_fast_vote_equivocation_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    statement_a: &[u8],
    statement_b: &[u8],
    checkpoint: u64,
) -> EqResult<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>> {
    require_resolver_context(resolver, chain, protocol_version)?;
    let a: FastVote = consensus::decode_fast_vote(statement_a)?;
    let b: FastVote = consensus::decode_fast_vote(statement_b)?;
    if &a.chain_id != chain || a.protocol_version != protocol_version {
        return invalid("statement does not match the declared chain/protocol context");
    }
    let evidence: consensus::FastVoteEquivocationEvidence =
        consensus::build_fast_vote_equivocation_evidence(&a, &b)?;

    let identity_bytes: Vec<u8> = fast_vote_evidence_normalized_identity(&evidence)?;
    let conflict_digest: Digest32 =
        resolver.hash_for_purpose(evidence.epoch, HashPurpose::NodeEvent, &identity_bytes)?;
    let key: Vec<u8> = local_instance_state::fastpath_equivocation_evidence_key(
        chain,
        evidence.epoch,
        *evidence.validator.as_bytes(),
        conflict_digest,
    )?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(existing_bytes) = observed.value() {
        let existing: FastPathEquivocationEvidenceRecord =
            resolve_existing(resolver, existing_bytes, conflict_digest)?;
        return Ok(EquivocationEvidenceOutcome::AlreadyRecorded(existing));
    }

    let evidence_bytes: Vec<u8> = consensus::encode_fast_vote_equivocation_evidence(&evidence)?;
    let validator_set: ValidatorSet = load_historical_validator_set(
        store,
        context,
        domain,
        resolver,
        chain,
        protocol_version,
        evidence.epoch,
    )?;
    consensus::verify_fast_vote_equivocation_evidence(
        &evidence,
        validator_set,
        &fast_path::FastPathEd25519Verifier,
    )?;
    commit_new_evidence(
        store,
        context,
        domain,
        resolver,
        key,
        observed.revision(),
        checkpoint,
        evidence_bytes,
        conflict_digest,
    )
}

/// Class (b): the same validator signed two [`FastVote`]s for *different*
/// transactions whose locked-object sets share an identical `(ObjectId,
/// version)` pair (DR-0133 §1/§8).
///
/// The mandatory preimage-hash-to-signed-digest check (step 4) runs before
/// the identity/key derivation, the already-recorded lookup, or
/// [`load_historical_validator_set`]/`verify_*` are ever reached: an
/// attached preimage is untrusted bytes until proven to hash to the exact
/// digest its own vote signed.
#[allow(clippy::too_many_arguments)]
pub fn submit_fast_vote_object_conflict_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    statement_a: &[u8],
    statement_b: &[u8],
    preimage_a: &[u8],
    preimage_b: &[u8],
    checkpoint: u64,
) -> EqResult<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>> {
    require_resolver_context(resolver, chain, protocol_version)?;
    let a: FastVote = consensus::decode_fast_vote(statement_a)?;
    let b: FastVote = consensus::decode_fast_vote(statement_b)?;
    let a_preimage: consensus::LockedObjectSetPreimage =
        consensus::decode_locked_object_set_preimage(preimage_a)?;
    let b_preimage: consensus::LockedObjectSetPreimage =
        consensus::decode_locked_object_set_preimage(preimage_b)?;
    if &a.chain_id != chain || a.protocol_version != protocol_version {
        return invalid("statement does not match the declared chain/protocol context");
    }
    let evidence: consensus::FastVoteObjectConflictEvidence =
        consensus::build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage)?;

    // Mandatory, fail-closed, before either preimage is trusted for
    // anything else (DR-0133 §8 step 4).
    let low_hash: Digest32 = resolver.hash_for_purpose(
        evidence.low.epoch,
        HashPurpose::ExecutionEffects,
        &consensus::encode_locked_object_set_preimage(&evidence.low_preimage)?,
    )?;
    if low_hash != evidence.low.locked_objects_digest {
        return invalid("attached preimage does not hash to its FastVote locked_objects_digest");
    }
    let high_hash: Digest32 = resolver.hash_for_purpose(
        evidence.high.epoch,
        HashPurpose::ExecutionEffects,
        &consensus::encode_locked_object_set_preimage(&evidence.high_preimage)?,
    )?;
    if high_hash != evidence.high.locked_objects_digest {
        return invalid("attached preimage does not hash to its FastVote locked_objects_digest");
    }

    let identity_bytes: Vec<u8> = fast_vote_object_conflict_normalized_identity(&evidence)?;
    let conflict_digest: Digest32 =
        resolver.hash_for_purpose(evidence.epoch, HashPurpose::NodeEvent, &identity_bytes)?;
    let key: Vec<u8> = local_instance_state::fastpath_equivocation_evidence_key(
        chain,
        evidence.epoch,
        *evidence.validator.as_bytes(),
        conflict_digest,
    )?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(existing_bytes) = observed.value() {
        let existing: FastPathEquivocationEvidenceRecord =
            resolve_existing(resolver, existing_bytes, conflict_digest)?;
        return Ok(EquivocationEvidenceOutcome::AlreadyRecorded(existing));
    }

    let evidence_bytes: Vec<u8> = consensus::encode_fast_vote_object_conflict_evidence(&evidence)?;
    let validator_set: ValidatorSet = load_historical_validator_set(
        store,
        context,
        domain,
        resolver,
        chain,
        protocol_version,
        evidence.epoch,
    )?;
    consensus::verify_fast_vote_object_conflict_evidence(
        &evidence,
        validator_set,
        &fast_path::FastPathEd25519Verifier,
    )?;
    commit_new_evidence(
        store,
        context,
        domain,
        resolver,
        key,
        observed.revision(),
        checkpoint,
        evidence_bytes,
        conflict_digest,
    )
}

/// Class (c): the same outgoing-epoch validator signed two
/// [`EpochTransitionVote`]s with a differing activation target (DR-0133
/// §1/§8). The identical algorithm to class (a), substituting its own
/// build/verify/encode functions and normalized-identity preimage.
#[allow(clippy::too_many_arguments)]
pub fn submit_epoch_transition_equivocation_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    statement_a: &[u8],
    statement_b: &[u8],
    checkpoint: u64,
) -> EqResult<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>> {
    require_resolver_context(resolver, chain, protocol_version)?;
    let a: EpochTransitionVote = consensus::decode_epoch_transition_vote(statement_a)?;
    let b: EpochTransitionVote = consensus::decode_epoch_transition_vote(statement_b)?;
    if &a.chain_id != chain || a.protocol_version != protocol_version {
        return invalid("statement does not match the declared chain/protocol context");
    }
    let evidence: consensus::EpochTransitionEquivocationEvidence =
        consensus::build_epoch_transition_equivocation_evidence(&a, &b)?;

    let identity_bytes: Vec<u8> = epoch_transition_evidence_normalized_identity(&evidence)?;
    let conflict_digest: Digest32 =
        resolver.hash_for_purpose(evidence.epoch, HashPurpose::NodeEvent, &identity_bytes)?;
    let key: Vec<u8> = local_instance_state::fastpath_equivocation_evidence_key(
        chain,
        evidence.epoch,
        *evidence.validator.as_bytes(),
        conflict_digest,
    )?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(existing_bytes) = observed.value() {
        let existing: FastPathEquivocationEvidenceRecord =
            resolve_existing(resolver, existing_bytes, conflict_digest)?;
        return Ok(EquivocationEvidenceOutcome::AlreadyRecorded(existing));
    }

    let evidence_bytes: Vec<u8> =
        consensus::encode_epoch_transition_equivocation_evidence(&evidence)?;
    let validator_set: ValidatorSet = load_historical_validator_set(
        store,
        context,
        domain,
        resolver,
        chain,
        protocol_version,
        evidence.epoch,
    )?;
    consensus::verify_epoch_transition_equivocation_evidence(
        &evidence,
        validator_set,
        &fast_path::FastPathEd25519Verifier,
    )?;
    commit_new_evidence(
        store,
        context,
        domain,
        resolver,
        key,
        observed.revision(),
        checkpoint,
        evidence_bytes,
        conflict_digest,
    )
}

#[cfg(test)]
mod tests;
