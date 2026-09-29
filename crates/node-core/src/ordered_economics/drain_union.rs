//! Bounded post-Freeze signer-frontier import and deterministic DrainSet
//! union reconstruction (DR-0154 / DR-0156).
//!
//! This module is local progress only, layered strictly on top of two
//! already-owned primitives it never bypasses: [`consensus::frontier`]'s pure
//! page verifier/accumulator authenticates one registered signer's *complete*
//! frozen frontier, and [`crate::fast_path::drain_publication`]'s
//! `retain_drain_publication`/`verify_drain_possession` atomically import and
//! re-verify one full publication proof. Nothing here creates a signature, an
//! ACK, an application effect, a fee, a nonce, or a receipt.
//!
//! Per-signer progress is staged one bounded page at a time
//! ([`ingest_drain_signer_page`]): a page is only accepted once the prior
//! staged page's every entry has been individually confirmed
//! ([`confirm_drain_signer_entry`]), and confirmation always re-derives the
//! expected identity from the locally staged page -- never from a caller
//! argument -- then re-verifies the complete imported proof and possession
//! marker from storage in the *same* atomic commit as the progress update
//! and the new immutable per-`(signer, request_id)` entry row. A crash
//! between [`import_staged_drain_publication`] committing and
//! [`confirm_drain_signer_entry`] committing leaves only a harmless extra
//! retained proof, never partial signer progress: the two are independent
//! atomic commits, and confirmation re-verifies fully from storage every
//! time regardless of when the proof was imported. A pristine missing
//! signer-entry row is exactly the ordinary not-yet-confirmed case and is
//! rebuilt by the very next successful confirmation; a tombstoned one, or a
//! tombstoned/missing drain-publication or possession marker, fails closed
//! instead.
//!
//! [`advance_drain_union`] then reconstructs the deterministic union of
//! confirmed signer entries -- never raw drain-publication proof rows, which
//! carry no per-signer attribution -- across a caller-selected, ascending,
//! unique, quorum-verified set of complete signers bound to the exact
//! committed Freeze. It merges at most one request ID per call, deduping an
//! identical cross-signer identity and refusing a same-request-ID conflict
//! with a different identity. The resulting local `drain-union-ready/` marker
//! is never signed, never cuts history, and is verified read-only by
//! [`verify_drain_ready`].
use super::freeze::{admission_closure_key, decode_admission_closure_record};
use super::*;
use crate::fast_path::FastPathEd25519Verifier;
use crate::fast_path::drain_publication::{
    fence_closed_epoch, retain_drain_publication, verify_drain_possession_into,
};
use canonical_encoding::{decode_canonical_frame, encode_chain_id};
use consensus::{
    AvailabilityIdentity, DrainUnionAccumulator, DrainUnionIdentity, FrozenFrontierAccumulator,
    FrozenFrontierCertifier, FrozenFrontierIdentity, FrozenFrontierPage,
    FrozenFrontierPageVerifier, FrozenFrontierVote, decode_availability_identity,
    decode_drain_union_identity, decode_frozen_frontier_identity, decode_frozen_frontier_page,
    decode_frozen_frontier_vote, encode_availability_identity, encode_drain_union_identity,
    encode_frozen_frontier_identity, encode_frozen_frontier_page, encode_frozen_frontier_vote,
    verify_frozen_frontier_quorum,
};
use execution::publication::PublicationContext;
use protocol_types::ValidatorId;
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurableRecordKey, DurableRecordScan,
};
use std::num::NonZeroUsize;
use validator_set::ValidatorSet;

const SIGNER_PROGRESS_TYPE: u16 = 0x645B;
const UNION_PROGRESS_TYPE: u16 = 0x645C;
const UNION_READY_TYPE: u16 = 0x645D;
const ENCODING_VERSION: u16 = 1;

/// Matches `validator_set::MAX_VALIDATORS` / `consensus::MAX_DRAIN_UNION_SIGNERS`.
pub use consensus::MAX_DRAIN_UNION_SIGNERS;
/// Matches [`consensus::MAX_FROZEN_FRONTIER_PAGE_ENTRIES`]; the accumulator
/// itself has no separate cap, but every entry that can ever appear on one
/// staged page is already bounded there.
pub use consensus::MAX_FROZEN_FRONTIER_PAGE_ENTRIES as MAX_DRAIN_SIGNER_PAGE_ENTRIES;

/// One invocation's confirmed outcome for [`ingest_drain_signer_page`] and
/// [`confirm_drain_signer_entry`] respectively use their own direct return
/// values; this enum is only for the multi-step union reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainUnionStep {
    Advanced { member_count: u64 },
    Ready(Box<DrainUnionIdentity>),
}

/// A storage, proof, profile, quorum or Freeze prerequisite failure. None of
/// these conditions permits recording progress, confirming an entry, or
/// declaring readiness.
#[derive(Debug)]
pub enum DrainSignerError {
    Node(NodeCoreError),
    Frontier(consensus::FrontierError),
    Publication(Box<crate::fast_path::publication::PublicationRetentionError>),
    NotReady(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for DrainSignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::Frontier(error) => error.fmt(formatter),
            Self::Publication(error) => error.fmt(formatter),
            Self::NotReady(reason) | Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for DrainSignerError {}

impl From<NodeCoreError> for DrainSignerError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<consensus::FrontierError> for DrainSignerError {
    fn from(value: consensus::FrontierError) -> Self {
        Self::Frontier(value)
    }
}
impl From<consensus::ConsensusError> for DrainSignerError {
    fn from(value: consensus::ConsensusError) -> Self {
        Self::Frontier(consensus::FrontierError::from(value))
    }
}
impl From<crate::fast_path::publication::PublicationRetentionError> for DrainSignerError {
    fn from(value: crate::fast_path::publication::PublicationRetentionError) -> Self {
        Self::Publication(Box::new(value))
    }
}
impl From<crate::fast_path::FastPathError> for DrainSignerError {
    fn from(value: crate::fast_path::FastPathError) -> Self {
        Self::Publication(Box::new(value.into()))
    }
}
impl From<RuntimeError> for DrainSignerError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for DrainSignerError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalEncodingError> for DrainSignerError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalDecodingError> for DrainSignerError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Node(value.into())
    }
}

fn signer_key(
    chain: &ChainId,
    epoch: Epoch,
    suffix: &[u8],
    signer: ValidatorId,
) -> Result<Vec<u8>, DrainSignerError> {
    let mut key: Vec<u8> = engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(suffix);
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key.extend_from_slice(signer.as_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Bounded, CAS-fenced per-signer local progress: at most one staged page
/// awaiting per-entry confirmation, plus every confirmed cursor field needed
/// to resume [`consensus::FrozenFrontierAccumulator`] exactly.
pub fn drain_signer_progress_key(
    chain: &ChainId,
    epoch: Epoch,
    signer: ValidatorId,
) -> Result<Vec<u8>, DrainSignerError> {
    signer_key(chain, epoch, b"drain-signer-progress/", signer)
}

fn drain_signer_entry_prefix(
    chain: &ChainId,
    epoch: Epoch,
    signer: ValidatorId,
) -> Result<Vec<u8>, DrainSignerError> {
    signer_key(chain, epoch, b"drain-signer-entry/", signer)
}

/// One immutable, per-`(signer, request_id)` confirmed availability identity.
/// Written exactly once by [`confirm_drain_signer_entry`]; a later selection
/// union reads these rows, never the shared content-addressed
/// `drain-publication/` proof rows, since those carry no per-signer
/// attribution.
pub fn drain_signer_entry_key(
    chain: &ChainId,
    epoch: Epoch,
    signer: ValidatorId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, DrainSignerError> {
    let mut key: Vec<u8> = drain_signer_entry_prefix(chain, epoch, signer)?;
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// CAS-fenced local progress of one in-flight DrainSet union merge, pinned
/// to one exact selected-signer roster.
pub fn drain_union_progress_key(
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Vec<u8>, DrainSignerError> {
    let mut key: Vec<u8> = engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-union-progress/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Immutable local DrainSet-ready marker: never a signed vote, never cut
/// history, and never itself a proof that the referenced proofs still exist.
pub fn drain_union_ready_key(chain: &ChainId, epoch: Epoch) -> Result<Vec<u8>, DrainSignerError> {
    let mut key: Vec<u8> = engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-union-ready/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignerProgressRecord {
    vote: FrozenFrontierVote,
    confirmed_identity: FrozenFrontierIdentity,
    confirmed_last_request_id: Option<[u8; 32]>,
    staged_page: Option<FrozenFrontierPage>,
    complete: bool,
}

fn encode_signer_progress(record: &SignerProgressRecord) -> Result<Vec<u8>, DrainSignerError> {
    if record.complete && record.confirmed_identity != record.vote.identity {
        return Err(DrainSignerError::Invalid(
            "signer progress complete without terminal match",
        ));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(SIGNER_PROGRESS_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_frozen_frontier_vote(&record.vote)?)?;
    frame.field_bytes(
        2,
        encode_frozen_frontier_identity(&record.confirmed_identity)?,
    )?;
    frame.field_bytes(
        3,
        record
            .confirmed_last_request_id
            .map_or_else(Vec::new, |id| id.to_vec()),
    )?;
    frame.field_bytes(
        4,
        match &record.staged_page {
            Some(page) => encode_frozen_frontier_page(page)?,
            None => Vec::new(),
        },
    )?;
    frame.field_u16(5, u16::from(record.complete))?;
    Ok(frame.finish()?)
}

fn decode_signer_progress(input: &[u8]) -> Result<SignerProgressRecord, DrainSignerError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(SIGNER_PROGRESS_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let confirmed_last_request_id: Option<[u8; 32]> = match frame.required_field(3)? {
        [] => None,
        bytes => Some(
            bytes
                .try_into()
                .map_err(|_| DrainSignerError::Invalid("signer progress cursor length"))?,
        ),
    };
    let staged_page: Option<FrozenFrontierPage> = match frame.required_field(4)? {
        [] => None,
        bytes => Some(decode_frozen_frontier_page(bytes)?),
    };
    let complete: bool = match frame.required_u16(5)? {
        0 => false,
        1 => true,
        _ => return Err(DrainSignerError::Invalid("signer progress complete flag")),
    };
    let record = SignerProgressRecord {
        vote: decode_frozen_frontier_vote(frame.required_field(1)?)?,
        confirmed_identity: decode_frozen_frontier_identity(frame.required_field(2)?)?,
        confirmed_last_request_id,
        staged_page,
        complete,
    };
    if encode_signer_progress(&record)?.as_slice() != input {
        return Err(DrainSignerError::Invalid("noncanonical signer progress"));
    }
    Ok(record)
}

fn put_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), DrainSignerError> {
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
) -> Result<(), DrainSignerError> {
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

struct DrainContext {
    chain: ChainId,
    epoch: Epoch,
    validators: ValidatorSet,
    closure_request_id: [u8; 32],
    closure_height: u64,
    reads: BTreeMap<Vec<u8>, StateRevision>,
}

/// Fences the installed logical profile, current epoch, outgoing set and
/// committed Freeze exactly once for every function in this module.
fn fence_drain_context<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
) -> Result<DrainContext, DrainSignerError> {
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let validators: ValidatorSet =
        fence_closed_epoch(store, context, domain, resolver, expected, &mut reads)?;
    let closure_key: Vec<u8> = admission_closure_key(&chain, epoch)?;
    let closure_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &closure_key)?;
    put_read(&mut reads, closure_key, closure_row.revision())?;
    let closure_bytes: &[u8] = closure_row.value().ok_or(DrainSignerError::NotReady(
        "ordered Freeze is not committed",
    ))?;
    let closure = decode_admission_closure_record(closure_bytes)?;
    if closure.closed_epoch != epoch || closure.closed_at_block_height == 0 {
        return Err(DrainSignerError::Invalid(
            "invalid committed Freeze identity",
        ));
    }
    Ok(DrainContext {
        chain,
        epoch,
        validators,
        closure_request_id: closure.request_id,
        closure_height: closure.closed_at_block_height,
        reads,
    })
}

/// Stages at most one bounded page of a registered signer's complete frozen
/// frontier, CAS-fenced by the installed logical profile, current epoch,
/// outgoing set, committed Freeze and this signer's own prior progress. The
/// page is checked against the signer's real signed vote using
/// [`FrozenFrontierPageVerifier::resume`] before it is ever staged: a wrong
/// vote, mixed-Freeze vote, forged signature, gap, reorder or premature
/// terminal page fails closed here, before any per-entry work. Only one page
/// may be staged at a time; the next page is refused until every entry of the
/// currently staged one has been confirmed.
#[allow(clippy::too_many_arguments)]
pub fn ingest_drain_signer_page<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    signer: ValidatorId,
    vote: FrozenFrontierVote,
    page: FrozenFrontierPage,
) -> Result<(), DrainSignerError> {
    let mut drain: DrainContext = fence_drain_context(store, context, domain, resolver, expected)?;
    if vote.identity.chain_id != drain.chain
        || vote.identity.protocol_version != expected.protocol_version()
        || vote.identity.epoch != drain.epoch
        || vote.identity.domain != domain
        || vote.identity.closure_request_id != drain.closure_request_id
        || vote.identity.closure_height != drain.closure_height
    {
        return Err(DrainSignerError::Invalid(
            "frontier vote disagrees with committed Freeze",
        ));
    }
    if vote.validator != signer {
        return Err(DrainSignerError::Invalid("frontier vote signer mismatch"));
    }
    drain
        .validators
        .get(signer)
        .ok_or(DrainSignerError::Invalid("signer not in outgoing set"))?;
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        drain.chain.clone(),
        expected.protocol_version(),
        drain.epoch,
        drain.validators.clone(),
    )?;

    let progress_key: Vec<u8> = drain_signer_progress_key(&drain.chain, drain.epoch, signer)?;
    let progress_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &progress_key)?;
    put_read(
        &mut drain.reads,
        progress_key.clone(),
        progress_row.revision(),
    )?;
    let existing: Option<SignerProgressRecord> = match progress_row.value() {
        Some(bytes) => Some(decode_signer_progress(bytes)?),
        None if progress_row.revision() == StateRevision::INITIAL => None,
        None => return Err(DrainSignerError::Invalid("signer progress is tombstoned")),
    };
    let (confirmed_identity, confirmed_last_request_id): (
        FrozenFrontierIdentity,
        Option<[u8; 32]>,
    ) = match &existing {
        Some(record) => {
            if record.complete {
                return Err(DrainSignerError::NotReady(
                    "signer frontier is already complete",
                ));
            }
            if record.vote != vote {
                return Err(DrainSignerError::Invalid(
                    "signer vote disagrees with prior progress",
                ));
            }
            if record.staged_page.is_some() {
                return Err(DrainSignerError::NotReady(
                    "prior staged page is not fully confirmed",
                ));
            }
            (
                record.confirmed_identity.clone(),
                record.confirmed_last_request_id,
            )
        }
        None => (
            FrozenFrontierAccumulator::new(
                resolver,
                drain.chain.clone(),
                expected.protocol_version(),
                drain.epoch,
                domain,
                drain.closure_request_id,
                drain.closure_height,
            )?
            .into_identity(),
            None,
        ),
    };
    // A genuinely empty signed frontier is already terminal before any page
    // is ever pushed: `FrozenFrontierPageVerifier` correctly refuses *any*
    // page once terminal, so this boundary case is handled directly rather
    // than through a dry-run push.
    let (staged_page, complete): (Option<FrozenFrontierPage>, bool) =
        if confirmed_identity == vote.identity {
            if page.after_request_id != confirmed_last_request_id
                || !page.entries.is_empty()
                || !page.terminal
            {
                return Err(DrainSignerError::Invalid(
                    "page after terminal frontier page",
                ));
            }
            (None, true)
        } else {
            let accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::resume(
                resolver,
                confirmed_identity.clone(),
                confirmed_last_request_id,
            )?;
            // Dry-run only: this never persists the advanced accumulator.
            // Each entry is folded into the durable one at confirmation time
            // instead, one at a time, so a partially confirmed page resumes
            // exactly.
            let mut verifier: FrozenFrontierPageVerifier = FrozenFrontierPageVerifier::resume(
                resolver,
                &certifier,
                vote.clone(),
                accumulator,
                &FastPathEd25519Verifier,
            )?;
            verifier.push_page(resolver, &page)?;
            if page.entries.is_empty() {
                // An empty terminal page proves the signer's confirmed
                // progress already equals their signed vote; there is
                // nothing left to confirm.
                (None, page.terminal)
            } else {
                (Some(page), false)
            }
        };
    let record: SignerProgressRecord = SignerProgressRecord {
        vote,
        confirmed_identity,
        confirmed_last_request_id,
        staged_page,
        complete,
    };
    commit_row(
        store,
        context,
        domain,
        drain.reads,
        vec![StateMutationEntry::new(
            progress_key,
            StateMutation::Put(encode_signer_progress(&record)?),
        )?],
    )
}

/// Read-only accessor for the exact next unconfirmed identity of a signer's
/// currently staged page, derived entirely from durable storage. This is the
/// only source [`import_staged_drain_publication`] and
/// [`confirm_drain_signer_entry`] trust for "which identity is expected
/// next" -- a caller-supplied identity is never accepted as authority.
pub fn staged_drain_signer_identity<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    signer: ValidatorId,
) -> Result<AvailabilityIdentity, DrainSignerError> {
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let progress_key: Vec<u8> = drain_signer_progress_key(&chain, epoch, signer)?;
    let progress_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &progress_key)?;
    let bytes: &[u8] = progress_row
        .value()
        .ok_or(DrainSignerError::NotReady("no staged signer page"))?;
    let record: SignerProgressRecord = decode_signer_progress(bytes)?;
    if record.vote.identity.chain_id != chain
        || record.vote.identity.protocol_version != expected.protocol_version()
        || record.vote.identity.epoch != epoch
        || record.vote.identity.domain != domain
        || record.vote.validator != signer
    {
        return Err(DrainSignerError::Invalid(
            "signer progress context mismatch",
        ));
    }
    let page: &FrozenFrontierPage = record
        .staged_page
        .as_ref()
        .ok_or(DrainSignerError::NotReady("no staged signer page"))?;
    page.entries
        .iter()
        .find(|entry| {
            record
                .confirmed_last_request_id
                .is_none_or(|last| entry.request_id > last)
        })
        .cloned()
        .ok_or(DrainSignerError::NotReady(
            "staged page already fully confirmed",
        ))
}

/// Re-verifies the complete imported proof and possession marker from
/// storage against the exact next staged identity, then atomically commits
/// the advanced signer progress together with a new immutable
/// `(signer, request_id)` entry row -- in the same CAS as every artifact,
/// publication and marker revision this re-verification read. Confirming an
/// entry that is not the exact next staged one, or confirming when nothing is
/// staged, fails closed without writing anything.
pub fn confirm_drain_signer_entry<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    signer: ValidatorId,
) -> Result<AvailabilityIdentity, DrainSignerError> {
    let mut drain: DrainContext = fence_drain_context(store, context, domain, resolver, expected)?;
    let progress_key: Vec<u8> = drain_signer_progress_key(&drain.chain, drain.epoch, signer)?;
    let progress_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &progress_key)?;
    put_read(
        &mut drain.reads,
        progress_key.clone(),
        progress_row.revision(),
    )?;
    let bytes: &[u8] = progress_row
        .value()
        .ok_or(DrainSignerError::NotReady("no staged signer page"))?;
    let mut record: SignerProgressRecord = decode_signer_progress(bytes)?;
    if record.vote.identity.chain_id != drain.chain
        || record.vote.identity.protocol_version != expected.protocol_version()
        || record.vote.identity.epoch != drain.epoch
        || record.vote.identity.domain != domain
        || record.vote.validator != signer
    {
        return Err(DrainSignerError::Invalid(
            "signer progress context mismatch",
        ));
    }
    let page: FrozenFrontierPage = record
        .staged_page
        .clone()
        .ok_or(DrainSignerError::NotReady("no staged signer page"))?;
    let pending: AvailabilityIdentity = page
        .entries
        .iter()
        .find(|entry| {
            record
                .confirmed_last_request_id
                .is_none_or(|last| entry.request_id > last)
        })
        .cloned()
        .ok_or(DrainSignerError::NotReady(
            "staged page already fully confirmed",
        ))?;

    let reconfirmed: AvailabilityIdentity = verify_drain_possession_into(
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        &drain.validators,
        &pending,
        &mut drain.reads,
    )?;
    if reconfirmed != pending {
        return Err(DrainSignerError::Invalid(
            "confirmed identity differs from staged entry",
        ));
    }

    let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::resume(
        resolver,
        record.confirmed_identity.clone(),
        record.confirmed_last_request_id,
    )?;
    accumulator.push(resolver, &pending)?;
    let new_last: [u8; 32] = pending.request_id;
    let new_identity: FrozenFrontierIdentity = accumulator.into_identity();

    let page_last: [u8; 32] = page
        .entries
        .last()
        .map(|entry| entry.request_id)
        .ok_or(DrainSignerError::Invalid("staged page has no entries"))?;
    let (staged_page, complete): (Option<FrozenFrontierPage>, bool) = if new_last == page_last {
        (None, page.terminal && new_identity == record.vote.identity)
    } else {
        (Some(page), false)
    };
    record.confirmed_identity = new_identity;
    record.confirmed_last_request_id = Some(new_last);
    record.staged_page = staged_page;
    record.complete = complete;

    let entry_key: Vec<u8> = drain_signer_entry_key(&drain.chain, drain.epoch, signer, &new_last)?;
    let entry_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &entry_key)?;
    let entry_bytes: Vec<u8> = encode_availability_identity(&pending)?;
    if let Some(existing_bytes) = entry_row.value() {
        if existing_bytes != entry_bytes.as_slice() {
            return Err(DrainSignerError::Invalid(
                "conflicting immutable signer entry",
            ));
        }
    } else if entry_row.revision() != StateRevision::INITIAL {
        return Err(DrainSignerError::Invalid("signer entry is tombstoned"));
    }
    put_read(&mut drain.reads, entry_key.clone(), entry_row.revision())?;

    commit_row(
        store,
        context,
        domain,
        drain.reads,
        vec![
            StateMutationEntry::new(
                progress_key,
                StateMutation::Put(encode_signer_progress(&record)?),
            )?,
            StateMutationEntry::new(entry_key, StateMutation::Put(entry_bytes))?,
        ],
    )?;
    Ok(pending)
}

/// Derives the expected identity from the locally staged page and calls
/// [`retain_drain_publication`] with it: a caller-supplied identity is never
/// trusted as authority for what this import atomically retains. This is a
/// thin wrapper; the underlying atomic import remains exactly
/// `retain_drain_publication`'s own, unmodified, separate commit.
#[allow(clippy::too_many_arguments)]
pub fn import_staged_drain_publication<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    signer: ValidatorId,
    bundle_bytes: &[u8],
) -> Result<AvailabilityIdentity, DrainSignerError> {
    let expected_identity: AvailabilityIdentity =
        staged_drain_signer_identity(store, context, domain, expected, signer)?;
    Ok(retain_drain_publication(
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        &expected_identity,
        bundle_bytes,
    )?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnionProgressRecord {
    identity: DrainUnionIdentity,
    selected_signers: Vec<ValidatorId>,
    last_request_id: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnionReadyRecord {
    identity: DrainUnionIdentity,
    selected_signers: Vec<ValidatorId>,
}

fn encode_signer_roster(
    frame: &mut CanonicalStruct,
    base_field: u16,
    selected_signers: &[ValidatorId],
) -> Result<(), DrainSignerError> {
    let count: u16 = u16::try_from(selected_signers.len())
        .map_err(|_| DrainSignerError::Invalid("drain union signer count overflow"))?;
    frame.field_u16(base_field, count)?;
    for (index, signer) in selected_signers.iter().enumerate() {
        let offset: u16 = u16::try_from(index + 1)
            .map_err(|_| DrainSignerError::Invalid("drain union signer field overflow"))?;
        let field: u16 = base_field
            .checked_add(offset)
            .ok_or(DrainSignerError::Invalid(
                "drain union signer field overflow",
            ))?;
        frame.field_bytes(field, signer.as_bytes())?;
    }
    Ok(())
}

fn encode_union_progress(record: &UnionProgressRecord) -> Result<Vec<u8>, DrainSignerError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(UNION_PROGRESS_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_drain_union_identity(&record.identity)?)?;
    frame.field_bytes(
        2,
        record
            .last_request_id
            .map_or_else(Vec::new, |id| id.to_vec()),
    )?;
    encode_signer_roster(&mut frame, 3, &record.selected_signers)?;
    Ok(frame.finish()?)
}

fn decode_union_progress(input: &[u8]) -> Result<UnionProgressRecord, DrainSignerError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(UNION_PROGRESS_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let last_request_id: Option<[u8; 32]> = match frame.required_field(2)? {
        [] => None,
        bytes => Some(
            bytes
                .try_into()
                .map_err(|_| DrainSignerError::Invalid("drain union cursor length"))?,
        ),
    };
    let count: usize = usize::from(frame.required_u16(3)?);
    if count == 0 || count > MAX_DRAIN_UNION_SIGNERS || frame.field_count() != count + 3 {
        return Err(DrainSignerError::Invalid("drain union signer count"));
    }
    let mut selected_signers: Vec<ValidatorId> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 = u16::try_from(index + 4)
            .map_err(|_| DrainSignerError::Invalid("drain union signer field overflow"))?;
        let bytes: [u8; 32] = frame
            .required_field(field)?
            .try_into()
            .map_err(|_| DrainSignerError::Invalid("drain union signer id length"))?;
        selected_signers.push(ValidatorId::new(bytes));
    }
    let record = UnionProgressRecord {
        identity: decode_drain_union_identity(frame.required_field(1)?)?,
        selected_signers,
        last_request_id,
    };
    if encode_union_progress(&record)?.as_slice() != input {
        return Err(DrainSignerError::Invalid(
            "noncanonical drain union progress",
        ));
    }
    Ok(record)
}

fn encode_union_ready(record: &UnionReadyRecord) -> Result<Vec<u8>, DrainSignerError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(UNION_READY_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_drain_union_identity(&record.identity)?)?;
    encode_signer_roster(&mut frame, 2, &record.selected_signers)?;
    Ok(frame.finish()?)
}

fn decode_union_ready(input: &[u8]) -> Result<UnionReadyRecord, DrainSignerError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(UNION_READY_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let count: usize = usize::from(frame.required_u16(2)?);
    if count == 0 || count > MAX_DRAIN_UNION_SIGNERS || frame.field_count() != count + 2 {
        return Err(DrainSignerError::Invalid("drain union signer count"));
    }
    let mut selected_signers: Vec<ValidatorId> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 = u16::try_from(index + 3)
            .map_err(|_| DrainSignerError::Invalid("drain union signer field overflow"))?;
        let bytes: [u8; 32] = frame
            .required_field(field)?
            .try_into()
            .map_err(|_| DrainSignerError::Invalid("drain union signer id length"))?;
        selected_signers.push(ValidatorId::new(bytes));
    }
    let record = UnionReadyRecord {
        identity: decode_drain_union_identity(frame.required_field(1)?)?,
        selected_signers,
    };
    if encode_union_ready(&record)?.as_slice() != input {
        return Err(DrainSignerError::Invalid("noncanonical drain union ready"));
    }
    Ok(record)
}

/// Verifies that `selected_votes` form an ascending, unique, quorum-weighted
/// set bound to the exact locally committed Freeze and atomicity domain, and
/// returns their validator IDs in that same ascending, unique order.
fn verify_selection(
    drain: &DrainContext,
    expected: &PublicationContext,
    domain: AtomicityDomainId,
    selected_votes: &[FrozenFrontierVote],
) -> Result<Vec<ValidatorId>, DrainSignerError> {
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        drain.chain.clone(),
        expected.protocol_version(),
        drain.epoch,
        drain.validators.clone(),
    )?;
    verify_frozen_frontier_quorum(
        &certifier,
        selected_votes,
        domain,
        drain.closure_request_id,
        drain.closure_height,
        &FastPathEd25519Verifier,
    )?;
    Ok(selected_votes.iter().map(|vote| vote.validator).collect())
}

/// Every selected signer must have independently, locally verified its own
/// *complete* frozen frontier and reached this exact selected vote before it
/// may count toward the union; a caller cannot substitute a different signed
/// vote for the same validator than what was actually confirmed locally.
fn require_selected_signers_complete<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    drain: &mut DrainContext,
    selected_votes: &[FrozenFrontierVote],
) -> Result<(), DrainSignerError> {
    for vote in selected_votes {
        let progress_key: Vec<u8> =
            drain_signer_progress_key(&drain.chain, drain.epoch, vote.validator)?;
        let progress_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &progress_key)?;
        put_read(&mut drain.reads, progress_key, progress_row.revision())?;
        let bytes: &[u8] = progress_row.value().ok_or(DrainSignerError::NotReady(
            "selected signer has no local progress",
        ))?;
        let record: SignerProgressRecord = decode_signer_progress(bytes)?;
        if !record.complete || record.vote != *vote {
            return Err(DrainSignerError::NotReady(
                "selected signer is not locally complete",
            ));
        }
    }
    Ok(())
}

/// Advances the deterministic local DrainSet union by exactly one merged
/// request ID, or -- once every selected signer's confirmed entries are
/// exhausted -- commits the immutable local ready marker. Callers must
/// resubmit the identical `selected_votes` roster on every call; a changed
/// selection fails closed rather than silently starting a new merge.
pub fn advance_drain_union<S: DurablePortableRepository + StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    selected_votes: &[FrozenFrontierVote],
) -> Result<DrainUnionStep, DrainSignerError> {
    let mut drain: DrainContext = fence_drain_context(store, context, domain, resolver, expected)?;
    let selected_signers: Vec<ValidatorId> =
        verify_selection(&drain, expected, domain, selected_votes)?;
    require_selected_signers_complete(store, context, domain, &mut drain, selected_votes)?;

    let ready_key: Vec<u8> = drain_union_ready_key(&drain.chain, drain.epoch)?;
    let ready_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &ready_key)?;
    put_read(&mut drain.reads, ready_key.clone(), ready_row.revision())?;
    if let Some(bytes) = ready_row.value() {
        let ready: UnionReadyRecord = decode_union_ready(bytes)?;
        if ready.selected_signers != selected_signers
            || ready.identity.chain_id != drain.chain
            || ready.identity.protocol_version != expected.protocol_version()
            || ready.identity.epoch != drain.epoch
            || ready.identity.domain != domain
            || ready.identity.closure_request_id != drain.closure_request_id
            || ready.identity.closure_height != drain.closure_height
        {
            return Err(DrainSignerError::Invalid(
                "drain union ready disagrees with selection",
            ));
        }
        return Ok(DrainUnionStep::Ready(Box::new(ready.identity)));
    }
    if ready_row.revision() != StateRevision::INITIAL {
        return Err(DrainSignerError::Invalid("drain union ready is tombstoned"));
    }

    let progress_key: Vec<u8> = drain_union_progress_key(&drain.chain, drain.epoch)?;
    let progress_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &progress_key)?;
    put_read(
        &mut drain.reads,
        progress_key.clone(),
        progress_row.revision(),
    )?;
    let accumulator: DrainUnionAccumulator = match progress_row.value() {
        Some(bytes) => {
            let record: UnionProgressRecord = decode_union_progress(bytes)?;
            if record.selected_signers != selected_signers
                || record.identity.chain_id != drain.chain
                || record.identity.protocol_version != expected.protocol_version()
                || record.identity.epoch != drain.epoch
                || record.identity.domain != domain
                || record.identity.closure_request_id != drain.closure_request_id
                || record.identity.closure_height != drain.closure_height
            {
                return Err(DrainSignerError::Invalid(
                    "drain union progress disagrees with selection or Freeze",
                ));
            }
            DrainUnionAccumulator::resume(
                resolver,
                record.identity,
                record.last_request_id,
                &selected_signers,
            )?
        }
        None if progress_row.revision() == StateRevision::INITIAL => DrainUnionAccumulator::new(
            resolver,
            drain.chain.clone(),
            expected.protocol_version(),
            drain.epoch,
            domain,
            drain.closure_request_id,
            drain.closure_height,
            &selected_signers,
        )?,
        None => {
            return Err(DrainSignerError::Invalid(
                "drain union progress is tombstoned",
            ));
        }
    };

    // Bounded (one scan per selected signer) collection of every signer's
    // exact next unmerged candidate, then a single in-memory pass to find
    // the canonical ascending minimum and check every same-request-ID tie
    // for a cross-signer identity conflict before ever folding one in.
    let mut candidates: Vec<AvailabilityIdentity> = Vec::with_capacity(selected_signers.len());
    for signer in &selected_signers {
        let entry_prefix: Vec<u8> = drain_signer_entry_prefix(&drain.chain, drain.epoch, *signer)?;
        let after_key: Vec<u8> = match accumulator.last_request_id() {
            Some(last) => drain_signer_entry_key(&drain.chain, drain.epoch, *signer, &last)?,
            None => entry_prefix.clone(),
        };
        let one: NonZeroUsize = NonZeroUsize::new(1)
            .ok_or(DrainSignerError::Invalid("invalid drain union scan limit"))?;
        let scan: DurableRecordScan = DurableRecordScan::new(
            DurableCollection::State,
            Some(DurableRecordKey::State(after_key)),
            one,
        )?;
        let scanned = store.scan_portable_keys(context, domain, &scan)?;
        let Some(DurableRecordKey::State(candidate_key)) = scanned.keys().first() else {
            continue;
        };
        if !candidate_key.starts_with(&entry_prefix) {
            continue;
        }
        let candidate_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, candidate_key)?;
        put_read(
            &mut drain.reads,
            candidate_key.clone(),
            candidate_row.revision(),
        )?;
        let candidate_bytes: &[u8] = candidate_row
            .value()
            .ok_or(DrainSignerError::Invalid("missing signer entry"))?;
        candidates.push(decode_availability_identity(candidate_bytes)?);
    }

    match candidates.iter().map(|entry| entry.request_id).min() {
        Some(min_request_id) => {
            let mut winner: Option<&AvailabilityIdentity> = None;
            for candidate in &candidates {
                if candidate.request_id != min_request_id {
                    continue;
                }
                match winner {
                    None => winner = Some(candidate),
                    Some(existing) if existing != candidate => {
                        return Err(DrainSignerError::Invalid(
                            "cross-signer drain union identity conflict",
                        ));
                    }
                    Some(_) => {}
                }
            }
            let identity: AvailabilityIdentity = winner
                .ok_or(DrainSignerError::Invalid("drain union candidate vanished"))?
                .clone();
            let mut next: DrainUnionAccumulator = accumulator;
            next.push_member(resolver, &identity)?;
            let member_count: u64 = next.identity().member_count;
            let record: UnionProgressRecord = UnionProgressRecord {
                identity: next.into_identity(),
                selected_signers,
                last_request_id: Some(identity.request_id),
            };
            commit_row(
                store,
                context,
                domain,
                drain.reads,
                vec![StateMutationEntry::new(
                    progress_key,
                    StateMutation::Put(encode_union_progress(&record)?),
                )?],
            )?;
            Ok(DrainUnionStep::Advanced { member_count })
        }
        None => {
            let identity: DrainUnionIdentity = accumulator.into_identity();
            let ready: UnionReadyRecord = UnionReadyRecord {
                identity: identity.clone(),
                selected_signers,
            };
            commit_row(
                store,
                context,
                domain,
                drain.reads,
                vec![StateMutationEntry::new(
                    ready_key,
                    StateMutation::Put(encode_union_ready(&ready)?),
                )?],
            )?;
            Ok(DrainUnionStep::Ready(Box::new(identity)))
        }
    }
}

/// Read-only re-verification of the immutable local DrainSet-ready marker
/// against the exact currently committed Freeze and a fresh quorum check of
/// `selected_votes`. This never re-scans every retained proof: it trusts the
/// marker's own CAS-committed history, exactly like every other local
/// progress/final row in this crate. A pristine (never written) marker
/// refuses as not-ready; a tombstoned one fails closed instead.
pub fn verify_drain_ready<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    selected_votes: &[FrozenFrontierVote],
) -> Result<DrainUnionIdentity, DrainSignerError> {
    let drain: DrainContext = fence_drain_context(store, context, domain, resolver, expected)?;
    let selected_signers: Vec<ValidatorId> =
        verify_selection(&drain, expected, domain, selected_votes)?;
    let ready_key: Vec<u8> = drain_union_ready_key(&drain.chain, drain.epoch)?;
    let ready_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &ready_key)?;
    let bytes: &[u8] = ready_row
        .value()
        .ok_or(DrainSignerError::NotReady("drain union is not ready"))?;
    let ready: UnionReadyRecord = decode_union_ready(bytes)?;
    if ready.selected_signers != selected_signers
        || ready.identity.chain_id != drain.chain
        || ready.identity.protocol_version != expected.protocol_version()
        || ready.identity.epoch != drain.epoch
        || ready.identity.domain != domain
        || ready.identity.closure_request_id != drain.closure_request_id
        || ready.identity.closure_height != drain.closure_height
    {
        return Err(DrainSignerError::Invalid(
            "drain union ready disagrees with selection",
        ));
    }
    Ok(ready.identity)
}

#[cfg(test)]
mod tests;
