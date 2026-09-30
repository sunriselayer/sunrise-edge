//! DR-0161: bounded resumable drain-completion state machine.
//!
//! This module answers one narrow question a future Seal barrier will need:
//! has *every* member of the exact locally committed [`super::DrainSetRecord`]
//! actually been applied, and can that be proven without re-scanning every
//! member on every call? It never selects, chooses or accepts a caller-given
//! member list -- [`advance_drain_completion`] always re-derives
//! `selected_votes` from the one immutable, one-per-epoch committed record
//! ([`super::drain_set::read_drain_set_record`]'s own key,
//! [`super::drain_set_record_key`]), exactly like
//! [`crate::fast_path::drain_apply`]'s own independent re-verification does,
//! never from a request argument.
//!
//! It reuses two existing primitives unmodified:
//! [`super::drain_union::verify_drain_ready_into`] re-verifies this replica's
//! own local union readiness for the committed record's exact selected
//! votes, folding the committed Freeze, current epoch, outgoing set and the
//! immutable local `drain-union-ready/` marker into the caller's CAS read
//! set; [`super::drain_union::next_union_member_after`] selects the exact
//! next canonical union member (ascending by request id, deterministically
//! merged across every selected signer's confirmed entries) after a cursor,
//! the same deterministic algorithm [`super::drain_union::advance_drain_union`]
//! itself used to build that exact ready marker.
//!
//! One invocation advances *at most one* member. Advancing a member does not
//! apply it, execute it or create a receipt -- it only recognizes that a
//! separate committed [`runtime::DurableRequestReceipt`] already exists for
//! that member's exact request id and carries that member's exact certified
//! signed-intent digest ([`consensus::AvailabilityIdentity::signed_intent_digest`],
//! which every genuine drain application binds to its certificate's
//! `tx_hash`/event digest -- see [`crate::fast_path::drain_apply`]). A
//! missing receipt is declared catch-up ([`DrainCompletionError::NotReady`]):
//! some other path (ordinarily
//! [`crate::fast_path::drain_apply::apply_drain_member`]) has not yet
//! applied that member on this replica. A receipt that exists under a
//! *different* digest is never trusted as this member's completion --
//! [`DrainCompletionError::Invalid`] fails closed instead. A receipt is
//! immutable in the runtime storage contract once committed
//! ([`runtime::DurableRequestReceipt`]'s own type), so once a member's
//! receipt has been positively matched here it can never later disagree;
//! this alone proves only that *this replica* observed that application, not
//! that a future portable, cross-replica cut has verified or carried it.
//!
//! The CAS-committed progress row retains a running canonical
//! [`DrainUnionAccumulator`] identity, including its semantic member count
//! and digest. Each receipt-confirmed member advances that accumulator.
//! Merely exhausting the signer-entry scan is not proof of completeness: a
//! missing or skipped entry could produce a false terminal step. The
//! terminal step therefore compares the independently accumulated full
//! identity, count and digest with both the locally ready union and the
//! committed DrainSet before persisting `drain-completion/` atomically with
//! the CAS assertions over the observed prerequisites and progress.
//!
//! [`verify_drain_complete_into`] independently checks the committed DrainSet,
//! local ready union and terminal marker, folding all reads into a future
//! Seal vote or proposal's atomic commit. It is not itself wired into any
//! consensus path by this module.
//!
//! Scope: this does not select a DrainSet, apply a member, prove a portable
//! cut, or implement Seal, next-set readiness or activation. It is local
//! progress and audit history, exactly like every other row this crate's
//! `drain-*` families already are (DR-0157/DR-0159/DR-0160); a future
//! portable cut must independently reconstruct and verify member completion
//! from authenticated receipts and the committed record, never import this
//! replica-local marker as authority.
use super::drain_union;
use super::*;
use consensus::{
    AvailabilityIdentity, DrainUnionAccumulator, DrainUnionIdentity, FrozenFrontierIdentity,
    decode_drain_union_identity, encode_drain_union_identity,
};
use execution::publication::PublicationContext;
use protocol_types::ValidatorId;
use runtime::portable::DurablePortableRepository;

const DRAIN_COMPLETION_PROGRESS_TYPE: u16 = 0x6461;
const DRAIN_COMPLETION_RECORD_TYPE: u16 = 0x6462;
const ENCODING_VERSION: u16 = 1;
const MAX_DRAIN_COMPLETION_ROW_BYTES: usize = 5 * 1024;

/// One invocation's outcome for [`advance_drain_completion`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainCompletionStep {
    /// The exact member confirmed and folded into local completion progress
    /// this call.
    Advanced { request_id: [u8; 32] },
    /// Every selected signer's confirmed entries are exhausted and this
    /// replica's re-derived union identity matches the committed record; the
    /// immutable local completion marker is now persisted.
    Complete(Box<DrainUnionIdentity>),
}

/// A storage, proof, record or receipt prerequisite failure. None of these
/// permits recording progress or declaring completion.
#[derive(Debug)]
pub enum DrainCompletionError {
    Node(NodeCoreError),
    NotReady(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for DrainCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::NotReady(reason) | Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for DrainCompletionError {}

impl From<NodeCoreError> for DrainCompletionError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<RuntimeError> for DrainCompletionError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for DrainCompletionError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalEncodingError> for DrainCompletionError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalDecodingError> for DrainCompletionError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<consensus::FrontierError> for DrainCompletionError {
    fn from(_value: consensus::FrontierError) -> Self {
        Self::Invalid("invalid drain union identity encoding")
    }
}
impl From<drain_union::DrainSignerError> for DrainCompletionError {
    fn from(value: drain_union::DrainSignerError) -> Self {
        match value {
            drain_union::DrainSignerError::Node(inner) => Self::Node(inner),
            drain_union::DrainSignerError::NotReady(message) => Self::NotReady(message),
            drain_union::DrainSignerError::Invalid(message) => Self::Invalid(message),
            drain_union::DrainSignerError::Frontier(_)
            | drain_union::DrainSignerError::Publication(_) => {
                Self::Invalid("drain union readiness could not be independently reverified")
            }
        }
    }
}

fn put_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), DrainCompletionError> {
    if reads
        .insert(key, revision)
        .is_some_and(|prior| prior != revision)
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

fn commit_row<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    mutations: Vec<StateMutationEntry>,
) -> Result<(), DrainCompletionError> {
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(reason) => {
            Err(NodeCoreError::DurableCommitRejected(reason).into())
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason).into())
        }
    }
}

/// CAS-fenced, bounded, resumable cursor into the deterministic canonical
/// union member sequence: the exact next member after `last_request_id` this
/// replica has already confirmed a matching completion receipt for. Never
/// carries a physical storage revision counter. The running identity's
/// canonical member count and digest are compared with the committed union
/// at exhaustion, so a skipped signer entry cannot falsely complete it.
pub fn drain_completion_progress_key(
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Vec<u8>, DrainCompletionError> {
    let mut key: Vec<u8> = engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-completion-progress/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Immutable local marker: every selected signer's confirmed entries were
/// exhausted and this replica's independently re-derived union identity
/// matched the committed [`super::DrainSetRecord`]'s own
/// `drain_union_identity`. Never a signed vote, never a portable cut fact,
/// and never itself proof that a receipt this call matched remains durable
/// -- see the module documentation.
pub fn drain_completion_key(
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Vec<u8>, DrainCompletionError> {
    let mut key: Vec<u8> = engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-completion/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DrainCompletionProgressRecord {
    drain_set_request_id: [u8; 32],
    running_identity: DrainUnionIdentity,
    last_request_id: Option<[u8; 32]>,
}

fn encode_completion_progress(
    record: &DrainCompletionProgressRecord,
) -> Result<Vec<u8>, DrainCompletionError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(DRAIN_COMPLETION_PROGRESS_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, record.drain_set_request_id.to_vec())?;
    frame.field_bytes(2, encode_drain_union_identity(&record.running_identity)?)?;
    frame.field_bytes(
        3,
        record
            .last_request_id
            .map_or_else(Vec::new, |id| id.to_vec()),
    )?;
    let encoded: Vec<u8> = frame.finish()?;
    if encoded.len() > MAX_DRAIN_COMPLETION_ROW_BYTES {
        return Err(DrainCompletionError::Invalid(
            "drain completion progress exceeds row bound",
        ));
    }
    Ok(encoded)
}

fn decode_completion_progress(
    input: &[u8],
) -> Result<DrainCompletionProgressRecord, DrainCompletionError> {
    if input.len() > MAX_DRAIN_COMPLETION_ROW_BYTES {
        return Err(DrainCompletionError::Invalid(
            "drain completion progress exceeds row bound",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(DRAIN_COMPLETION_PROGRESS_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let drain_set_request_id: [u8; 32] = frame.required_field(1)?.try_into().map_err(|_| {
        DrainCompletionError::Invalid("drain completion progress request id length")
    })?;
    let last_request_id: Option<[u8; 32]> = match frame.required_field(3)? {
        [] => None,
        bytes => Some(bytes.try_into().map_err(|_| {
            DrainCompletionError::Invalid("drain completion progress cursor length")
        })?),
    };
    let record = DrainCompletionProgressRecord {
        drain_set_request_id,
        running_identity: decode_drain_union_identity(frame.required_field(2)?)?,
        last_request_id,
    };
    if (record.running_identity.member_count == 0) != record.last_request_id.is_none()
        || record.last_request_id == Some([0; 32])
    {
        return Err(DrainCompletionError::Invalid(
            "drain completion progress count and cursor disagree",
        ));
    }
    if encode_completion_progress(&record)?.as_slice() != input {
        return Err(DrainCompletionError::Invalid(
            "noncanonical drain completion progress",
        ));
    }
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DrainCompletionRecord {
    drain_set_request_id: [u8; 32],
    drain_union_identity: DrainUnionIdentity,
}

fn encode_completion_record(
    record: &DrainCompletionRecord,
) -> Result<Vec<u8>, DrainCompletionError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(DRAIN_COMPLETION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, record.drain_set_request_id.to_vec())?;
    frame.field_bytes(
        2,
        encode_drain_union_identity(&record.drain_union_identity)?,
    )?;
    let encoded: Vec<u8> = frame.finish()?;
    if encoded.len() > MAX_DRAIN_COMPLETION_ROW_BYTES {
        return Err(DrainCompletionError::Invalid(
            "drain completion marker exceeds row bound",
        ));
    }
    Ok(encoded)
}

fn decode_completion_record(input: &[u8]) -> Result<DrainCompletionRecord, DrainCompletionError> {
    if input.len() > MAX_DRAIN_COMPLETION_ROW_BYTES {
        return Err(DrainCompletionError::Invalid(
            "drain completion marker exceeds row bound",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(DRAIN_COMPLETION_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let drain_set_request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| DrainCompletionError::Invalid("drain completion record request id length"))?;
    let record = DrainCompletionRecord {
        drain_set_request_id,
        drain_union_identity: decode_drain_union_identity(frame.required_field(2)?)?,
    };
    if encode_completion_record(&record)?.as_slice() != input {
        return Err(DrainCompletionError::Invalid(
            "noncanonical drain completion record",
        ));
    }
    Ok(record)
}

/// Reads the committed, immutable, one-per-epoch [`super::DrainSetRecord`]
/// for `expected`'s exact `(chain, epoch)`, folding the read into `reads`.
/// Never a caller-selected member list: this is the *only* source this
/// module trusts for which selected votes and union identity are authority.
fn read_committed_drain_set<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<DrainSetRecord, DrainCompletionError> {
    let chain: &ChainId = expected.chain_id();
    let epoch: Epoch = expected.epoch();
    let record_key: Vec<u8> = drain_set_record_key(chain, epoch)?;
    let record_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &record_key)?;
    put_read(reads, record_key, record_row.revision())?;
    let record: DrainSetRecord = match record_row.value() {
        Some(bytes) => decode_drain_set_record(bytes)?,
        None if record_row.revision() == StateRevision::INITIAL => {
            return Err(DrainCompletionError::NotReady(
                "drain set is not committed for this epoch",
            ));
        }
        None => {
            return Err(DrainCompletionError::Invalid(
                "drain set record is tombstoned",
            ));
        }
    };
    if record.closed_epoch != epoch || record.drain_union_identity.chain_id != *chain {
        return Err(DrainCompletionError::Invalid(
            "drain set record context mismatch",
        ));
    }
    Ok(record)
}

/// Advances the local drain-completion state machine by exactly one
/// canonical union member of the exact locally committed
/// [`super::DrainSetRecord`], or -- once every selected signer's confirmed
/// entries are exhausted and this replica's re-derived union identity
/// matches the committed record -- commits the immutable local completion
/// marker. See the module documentation for the complete authority argument.
pub fn advance_drain_completion<
    S: DurablePortableRepository + StructuredDurableDomainStateStore,
>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
) -> Result<DrainCompletionStep, DrainCompletionError> {
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();

    let record: DrainSetRecord =
        read_committed_drain_set(store, context, domain, expected, &mut reads)?;

    // Freeze, epoch, set and ready marker: this replica's own fresh
    // re-verification of local readiness for the record's exact selected
    // votes. Equality with the committed record's identity is the foreign
    // union guard; the terminal step separately compares the receipt-backed
    // running accumulator with that same identity.
    let reconstructed: DrainUnionIdentity = drain_union::verify_drain_ready_into(
        store,
        context,
        domain,
        resolver,
        expected,
        &record.selected_votes,
        &mut reads,
    )?;
    if reconstructed != record.drain_union_identity {
        return Err(DrainCompletionError::Invalid(
            "drain union readiness disagrees with the committed drain set",
        ));
    }

    let completion_key: Vec<u8> = drain_completion_key(&chain, epoch)?;
    let completion_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &completion_key)?;
    put_read(
        &mut reads,
        completion_key.clone(),
        completion_row.revision(),
    )?;
    if let Some(bytes) = completion_row.value() {
        let completion: DrainCompletionRecord = decode_completion_record(bytes)?;
        if completion.drain_set_request_id != record.request_id
            || completion.drain_union_identity != record.drain_union_identity
        {
            return Err(DrainCompletionError::Invalid(
                "drain completion marker disagrees with the committed drain set",
            ));
        }
        return Ok(DrainCompletionStep::Complete(Box::new(
            completion.drain_union_identity,
        )));
    }
    if completion_row.revision() != StateRevision::INITIAL {
        return Err(DrainCompletionError::Invalid(
            "drain completion marker is tombstoned",
        ));
    }

    let progress_key: Vec<u8> = drain_completion_progress_key(&chain, epoch)?;
    let progress_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &progress_key)?;
    put_read(&mut reads, progress_key.clone(), progress_row.revision())?;
    let selected_pairs: Vec<(ValidatorId, FrozenFrontierIdentity)> = record
        .selected_votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let mut accumulator: DrainUnionAccumulator = match progress_row.value() {
        Some(bytes) => {
            let progress: DrainCompletionProgressRecord = decode_completion_progress(bytes)?;
            if progress.drain_set_request_id != record.request_id
                || progress.running_identity.chain_id != chain
                || progress.running_identity.protocol_version != expected.protocol_version()
                || progress.running_identity.epoch != epoch
                || progress.running_identity.domain != domain
                || progress.running_identity.closure_request_id
                    != record.drain_union_identity.closure_request_id
                || progress.running_identity.closure_height
                    != record.drain_union_identity.closure_height
                || progress.running_identity.member_count > record.drain_union_identity.member_count
            {
                return Err(DrainCompletionError::Invalid(
                    "drain completion progress disagrees with the committed drain set",
                ));
            }
            DrainUnionAccumulator::resume(
                resolver,
                progress.running_identity,
                progress.last_request_id,
                &selected_pairs,
            )
            .map_err(|_| DrainCompletionError::Invalid("invalid drain completion accumulator"))?
        }
        None if progress_row.revision() == StateRevision::INITIAL => DrainUnionAccumulator::new(
            resolver,
            chain.clone(),
            expected.protocol_version(),
            epoch,
            domain,
            record.drain_union_identity.closure_request_id,
            record.drain_union_identity.closure_height,
            &selected_pairs,
        )
        .map_err(|_| DrainCompletionError::Invalid("invalid drain completion seed"))?,
        None => {
            return Err(DrainCompletionError::Invalid(
                "drain completion progress is tombstoned",
            ));
        }
    };

    let selected_signers: Vec<ValidatorId> = record
        .selected_votes
        .iter()
        .map(|vote| vote.validator)
        .collect();
    let next: Option<AvailabilityIdentity> = drain_union::next_union_member_after(
        store,
        context,
        domain,
        expected,
        &selected_signers,
        accumulator.last_request_id(),
        &mut reads,
    )?;

    match next {
        Some(identity) => {
            // Never mark completion on a missing or mismatched receipt: a
            // typed original receipt must exist for this exact member's
            // request id and carry its exact certified signed-intent digest.
            let durable_id: DurableRequestId = DurableRequestId::new(identity.request_id)
                .map_err(|_| DrainCompletionError::Invalid("invalid drain member request id"))?;
            let receipt: DurableRequestReceipt = store
                .get_request_receipt(context, domain, durable_id)?
                .ok_or(DrainCompletionError::NotReady(
                    "drain member has no local completion receipt yet",
                ))?;
            if receipt.request_id() != durable_id {
                return Err(DrainCompletionError::Invalid(
                    "receipt lookup returned another request",
                ));
            }
            if receipt.event_digest() != identity.signed_intent_digest {
                return Err(DrainCompletionError::Invalid(
                    "drain member receipt digest disagrees with its certified signed intent",
                ));
            }
            accumulator
                .push_member(resolver, &identity)
                .map_err(|_| DrainCompletionError::Invalid("invalid drain completion member"))?;
            if accumulator.identity().member_count > record.drain_union_identity.member_count {
                return Err(DrainCompletionError::Invalid(
                    "drain completion exceeds committed union count",
                ));
            }
            let progress: DrainCompletionProgressRecord = DrainCompletionProgressRecord {
                drain_set_request_id: record.request_id,
                running_identity: accumulator.identity().clone(),
                last_request_id: accumulator.last_request_id(),
            };
            commit_row(
                store,
                context,
                domain,
                reads,
                vec![StateMutationEntry::new(
                    progress_key,
                    StateMutation::Put(encode_completion_progress(&progress)?),
                )?],
            )?;
            Ok(DrainCompletionStep::Advanced {
                request_id: identity.request_id,
            })
        }
        None => {
            // Scanning to exhaustion is not enough: a missing or skipped
            // signer entry could otherwise turn an incomplete walk into a
            // false completion. Compare the independently accumulated count
            // and digest with the committed, ready union before persisting.
            if accumulator.identity() != &record.drain_union_identity {
                return Err(DrainCompletionError::Invalid(
                    "drain completion does not match the committed union",
                ));
            }
            let completion: DrainCompletionRecord = DrainCompletionRecord {
                drain_set_request_id: record.request_id,
                drain_union_identity: record.drain_union_identity,
            };
            commit_row(
                store,
                context,
                domain,
                reads,
                vec![StateMutationEntry::new(
                    completion_key,
                    StateMutation::Put(encode_completion_record(&completion)?),
                )?],
            )?;
            Ok(DrainCompletionStep::Complete(Box::new(
                completion.drain_union_identity,
            )))
        }
    }
}

/// Read-only re-verification of the immutable local drain-completion marker,
/// folding every read into the caller-owned `reads` CAS read set instead of
/// a fresh, standalone one -- the variant a future Seal vote or proposal
/// must use, exactly like [`drain_union::verify_drain_ready_into`] already
/// lets `DrainSet` voting fold ready-marker reads into its own signed
/// identity's atomic commit. A pristine (never written) marker refuses as
/// not-ready; a tombstoned one fails closed instead.
pub fn verify_drain_complete_into<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<DrainUnionIdentity, DrainCompletionError> {
    let chain: &ChainId = expected.chain_id();
    let epoch: Epoch = expected.epoch();
    let record: DrainSetRecord = read_committed_drain_set(store, context, domain, expected, reads)?;
    let ready: DrainUnionIdentity = drain_union::verify_drain_ready_into(
        store,
        context,
        domain,
        resolver,
        expected,
        &record.selected_votes,
        reads,
    )?;
    if ready != record.drain_union_identity {
        return Err(DrainCompletionError::Invalid(
            "drain union readiness disagrees with the committed drain set",
        ));
    }
    let completion_key: Vec<u8> = drain_completion_key(chain, epoch)?;
    let completion_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &completion_key)?;
    put_read(reads, completion_key, completion_row.revision())?;
    let bytes: &[u8] = match completion_row.value() {
        Some(value) => value,
        None if completion_row.revision() == StateRevision::INITIAL => {
            return Err(DrainCompletionError::NotReady(
                "drain completion is not locally ready",
            ));
        }
        None => {
            return Err(DrainCompletionError::Invalid(
                "drain completion marker is tombstoned",
            ));
        }
    };
    let completion: DrainCompletionRecord = decode_completion_record(bytes)?;
    if completion.drain_set_request_id != record.request_id
        || completion.drain_union_identity != record.drain_union_identity
    {
        return Err(DrainCompletionError::Invalid(
            "drain completion marker context mismatch",
        ));
    }
    Ok(completion.drain_union_identity)
}

/// Same check as [`verify_drain_complete_into`], for a caller with no CAS
/// read set of its own; every read is folded into a fresh one and discarded.
pub fn verify_drain_complete<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
) -> Result<DrainUnionIdentity, DrainCompletionError> {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    verify_drain_complete_into(store, context, domain, resolver, expected, &mut reads)
}

#[cfg(test)]
mod tests;
