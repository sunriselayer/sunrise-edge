//! One bounded step of the frozen publication frontier (DR-0154).
//!
//! This does not select a quorum union or authorize DrainSet. A local signer
//! advances only after ordered Freeze, verifies each retained full proof and
//! all its artifact bytes, and persists a CAS-fenced cursor. It exposes a
//! signed immutable final descriptor only after the complete prefix scan has
//! ended and the descriptor and vote have committed atomically.

use super::freeze::{admission_closure_key, decode_admission_closure_record};
use super::*;
use crate::fast_path::publication::{
    PublicationRetentionError, fastpath_publication_key, verify_retained_publication,
};
use crate::fast_path::{FastPathError, load_validator_set};
use canonical_encoding::{decode_canonical_frame, encode_chain_id};
use consensus::{
    AvailabilityIdentity, ConsensusSigner, FrontierError, FrozenFrontierAccumulator,
    FrozenFrontierCertifier, FrozenFrontierIdentity, FrozenFrontierPage, FrozenFrontierVote,
    MAX_FROZEN_FRONTIER_PAGE_ENTRIES, decode_availability_identity,
    decode_frozen_frontier_identity, decode_frozen_frontier_vote, encode_availability_identity,
    encode_frozen_frontier_identity, encode_frozen_frontier_vote,
};
use protocol_types::ValidatorId;
use runtime::outbox_guard::StructuredOutboxExclusionGuard;
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurableRecordKey, DurableRecordScan,
};
use std::num::NonZeroUsize;
use validator_set::ValidatorSet;

const FRONTIER_CURSOR_TYPE: u16 = 0x6459;
const FRONTIER_FINAL_TYPE: u16 = 0x645A;
// Swept across all crates, apps, clients, scripts and accepted design: this
// previously unused local metadata frame does not change any public bytes.
const FRONTIER_ENTRY_TYPE: u16 = 0x6452;
const ENCODING_VERSION: u16 = 1;
const INDEXED_ENCODING_VERSION: u16 = 2;
const FRONTIER_PROGRESS_PREFIX: &[u8] = b"frontier-progress/";
const FRONTIER_FINAL_PREFIX: &[u8] = b"frontier/";
const FRONTIER_ENTRY_PREFIX: &[u8] = b"frontier-entry/";

/// One invocation's confirmed outcome. `Advanced` is not a vote or a cut;
/// callers repeat until `Finalized` returns a durably retained exact vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrozenFrontierStep {
    Advanced { entry_count: u64 },
    Finalized(Box<FrozenFrontierVote>),
}

/// A storage, proof, profile or Freeze prerequisite failure. None of these
/// conditions permits signing or importing a partial frontier.
#[derive(Debug)]
pub enum FrozenFrontierError {
    Node(NodeCoreError),
    Frontier(FrontierError),
    Publication(Box<PublicationRetentionError>),
    NotReady(&'static str),
    InvalidCursor(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for FrozenFrontierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::Frontier(error) => error.fmt(formatter),
            Self::Publication(error) => error.fmt(formatter),
            Self::NotReady(reason) | Self::InvalidCursor(reason) => formatter.write_str(reason),
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for FrozenFrontierError {}

impl From<crate::EnvelopeError> for FrozenFrontierError {
    fn from(value: crate::EnvelopeError) -> Self {
        <Self as From<NodeCoreError>>::from(NodeCoreError::from(value))
    }
}

impl From<NodeCoreError> for FrozenFrontierError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<FrontierError> for FrozenFrontierError {
    fn from(value: FrontierError) -> Self {
        Self::Frontier(value)
    }
}
impl From<PublicationRetentionError> for FrozenFrontierError {
    fn from(value: PublicationRetentionError) -> Self {
        Self::Publication(Box::new(value))
    }
}
impl From<FastPathError> for FrozenFrontierError {
    fn from(value: FastPathError) -> Self {
        Self::Publication(Box::new(value.into()))
    }
}
impl From<RuntimeError> for FrozenFrontierError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for FrozenFrontierError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalEncodingError> for FrozenFrontierError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalDecodingError> for FrozenFrontierError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Node(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrontierCursor {
    pub(super) identity: FrozenFrontierIdentity,
    pub(super) last_request_id: Option<[u8; 32]>,
    pub(super) physical_last_request_id: [u8; 32],
    pub(super) indexed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FinalFrontier {
    pub(super) identity: FrozenFrontierIdentity,
    pub(super) vote: FrozenFrontierVote,
    pub(super) indexed: bool,
}

/// Locator metadata only. Its ordinal, Freeze and current publication are
/// validated by the owning readers; no index row grants availability or
/// DrainSet authority. The real publication remains at its unchanged key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrontierEntry {
    pub(super) closure_request_id: [u8; 32],
    pub(super) closure_height: u64,
    pub(super) ordinal: u64,
    pub(super) publication: AvailabilityIdentity,
}

pub(super) fn key(
    chain: &ChainId,
    epoch: Epoch,
    suffix: &[u8],
) -> Result<Vec<u8>, FrozenFrontierError> {
    let mut result: Vec<u8> = engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    result.extend_from_slice(suffix);
    result.extend(encode_chain_id(chain)?);
    result.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&result)?;
    Ok(result)
}

fn encode_cursor(cursor: &FrontierCursor) -> Result<Vec<u8>, FrozenFrontierError> {
    if (cursor.identity.entry_count == 0) != cursor.last_request_id.is_none()
        || cursor.last_request_id == Some([0; 32])
        || cursor.physical_last_request_id == [0; 32]
        || cursor
            .last_request_id
            .is_some_and(|last: [u8; 32]| last > cursor.physical_last_request_id)
        || (!cursor.indexed && cursor.last_request_id != Some(cursor.physical_last_request_id))
    {
        return Err(FrozenFrontierError::Invalid("invalid frontier cursor"));
    }
    let version: u16 = if cursor.indexed {
        INDEXED_ENCODING_VERSION
    } else {
        ENCODING_VERSION
    };
    let mut frame: CanonicalStruct = CanonicalStruct::new(FRONTIER_CURSOR_TYPE, version);
    frame.field_bytes(1, encode_frozen_frontier_identity(&cursor.identity)?)?;
    frame.field_bytes(
        2,
        cursor
            .last_request_id
            .map_or_else(Vec::new, |last: [u8; 32]| last.to_vec()),
    )?;
    if cursor.indexed {
        frame.field_bytes(3, cursor.physical_last_request_id.to_vec())?;
    }
    Ok(frame.finish()?)
}

pub(super) fn decode_cursor(input: &[u8]) -> Result<FrontierCursor, FrozenFrontierError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_CURSOR_TYPE)?;
    let indexed: bool = match frame.version() {
        ENCODING_VERSION => {
            frame.require_only_fields(&[1, 2])?;
            false
        }
        INDEXED_ENCODING_VERSION => {
            frame.require_only_fields(&[1, 2, 3])?;
            true
        }
        _ => {
            return Err(FrozenFrontierError::Invalid(
                "unsupported frontier cursor version",
            ));
        }
    };
    let last_request_id: Option<[u8; 32]> = match frame.required_field(2)? {
        [] if indexed => None,
        bytes => Some(
            bytes
                .try_into()
                .map_err(|_| FrozenFrontierError::Invalid("frontier cursor request id length"))?,
        ),
    };
    let physical_last_request_id: [u8; 32] = if indexed {
        frame.required_field(3)?.try_into().map_err(|_| {
            FrozenFrontierError::Invalid("frontier physical cursor request id length")
        })?
    } else {
        last_request_id.ok_or(FrozenFrontierError::Invalid(
            "legacy frontier cursor is empty",
        ))?
    };
    let cursor: FrontierCursor = FrontierCursor {
        identity: decode_frozen_frontier_identity(frame.required_field(1)?)?,
        last_request_id,
        physical_last_request_id,
        indexed,
    };
    if encode_cursor(&cursor)?.as_slice() != input {
        return Err(FrozenFrontierError::Invalid("noncanonical frontier cursor"));
    }
    Ok(cursor)
}

fn encode_final(record: &FinalFrontier) -> Result<Vec<u8>, FrozenFrontierError> {
    if record.vote.identity != record.identity {
        return Err(FrozenFrontierError::Invalid(
            "frontier vote identity mismatch",
        ));
    }
    let version: u16 = if record.indexed {
        INDEXED_ENCODING_VERSION
    } else {
        ENCODING_VERSION
    };
    let mut frame: CanonicalStruct = CanonicalStruct::new(FRONTIER_FINAL_TYPE, version);
    frame.field_bytes(1, encode_frozen_frontier_identity(&record.identity)?)?;
    frame.field_bytes(2, encode_frozen_frontier_vote(&record.vote)?)?;
    Ok(frame.finish()?)
}

pub(super) fn decode_final(input: &[u8]) -> Result<FinalFrontier, FrozenFrontierError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_FINAL_TYPE)?;
    let indexed: bool = match frame.version() {
        ENCODING_VERSION => false,
        INDEXED_ENCODING_VERSION => true,
        _ => {
            return Err(FrozenFrontierError::Invalid(
                "unsupported final frontier version",
            ));
        }
    };
    frame.require_only_fields(&[1, 2])?;
    let record: FinalFrontier = FinalFrontier {
        identity: decode_frozen_frontier_identity(frame.required_field(1)?)?,
        vote: decode_frozen_frontier_vote(frame.required_field(2)?)?,
        indexed,
    };
    if encode_final(&record)?.as_slice() != input {
        return Err(FrozenFrontierError::Invalid("noncanonical final frontier"));
    }
    Ok(record)
}

pub(super) fn entry_key(
    chain: &ChainId,
    epoch: Epoch,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, FrozenFrontierError> {
    if *request_id == [0; 32] {
        return Err(FrozenFrontierError::Invalid("zero frontier entry request"));
    }
    let mut result: Vec<u8> = key(chain, epoch, FRONTIER_ENTRY_PREFIX)?;
    result.extend_from_slice(request_id);
    validate_transactional_state_key(&result)?;
    Ok(result)
}

pub(super) fn encode_entry(entry: &FrontierEntry) -> Result<Vec<u8>, FrozenFrontierError> {
    if entry.closure_request_id == [0; 32] || entry.closure_height == 0 || entry.ordinal == 0 {
        return Err(FrozenFrontierError::Invalid(
            "invalid frontier entry progress",
        ));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(FRONTIER_ENTRY_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, entry.closure_request_id.to_vec())?;
    frame.field_u64(2, entry.closure_height)?;
    frame.field_u64(3, entry.ordinal)?;
    frame.field_bytes(
        4,
        encode_availability_identity(&entry.publication)
            .map_err(PublicationRetentionError::from)?,
    )?;
    Ok(frame.finish()?)
}

pub(super) fn decode_entry(input: &[u8]) -> Result<FrontierEntry, FrozenFrontierError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_ENTRY_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let entry: FrontierEntry = FrontierEntry {
        closure_request_id: frame
            .required_field(1)?
            .try_into()
            .map_err(|_| FrozenFrontierError::Invalid("frontier entry closure id length"))?,
        closure_height: frame.required_u64(2)?,
        ordinal: frame.required_u64(3)?,
        publication: decode_availability_identity(frame.required_field(4)?)
            .map_err(PublicationRetentionError::from)?,
    };
    if encode_entry(&entry)?.as_slice() != input {
        return Err(FrozenFrontierError::Invalid("noncanonical frontier entry"));
    }
    Ok(entry)
}

pub(super) fn validate_entry(
    entry: &FrontierEntry,
    expected: &execution::publication::PublicationContext,
    domain: AtomicityDomainId,
    closure: &super::AdmissionClosureRecord,
) -> Result<(), FrozenFrontierError> {
    if entry.publication.chain_id != *expected.chain_id()
        || entry.publication.protocol_version != expected.protocol_version()
        || entry.publication.epoch != expected.epoch()
        || entry.publication.domain != domain
        || entry.closure_request_id != closure.request_id
        || entry.closure_height != closure.closed_at_block_height
        || closure.closed_epoch != expected.epoch()
    {
        return Err(FrozenFrontierError::Invalid(
            "frontier entry scope or Freeze differs",
        ));
    }
    Ok(())
}

fn put_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), FrozenFrontierError> {
    if reads
        .insert(key, revision)
        .is_some_and(|prior| prior != revision)
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

fn commit_rows<S: StructuredDurableDomainStateStore>(
    gate: crate::serving_authority::ServingGate<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    mutations: Vec<StateMutationEntry>,
) -> Result<(), FrozenFrontierError> {
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match gate.commit_durable(store, context, transaction) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(reason) => {
            Err(NodeCoreError::DurableCommitRejected(reason).into())
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason).into())
        }
    }
}

/// Preserves the original chain/request publication addresses and scans the
/// complete chain prefix. Each retained row must authenticate the expected
/// epoch and protocol context; foreign, corrupt, or unsupported history fails
/// closed rather than being excluded or silently skipped.
fn publication_prefix(chain: &ChainId) -> Result<Vec<u8>, FrozenFrontierError> {
    let mut prefix: Vec<u8> = fastpath_publication_key(chain, &[0; 32])?;
    let prefix_length: usize = prefix
        .len()
        .checked_sub(32)
        .ok_or(FrozenFrontierError::Invalid("publication prefix length"))?;
    prefix.truncate(prefix_length);
    Ok(prefix)
}

/// A paired step is the only index producer. Before any new fold or final
/// signature, reject a prefix-slot tombstone or an orphan index entry beyond
/// the existing logical tail. This is one bounded scan, not a history fold.
fn require_index_tail<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &execution::publication::PublicationContext,
    last: Option<[u8; 32]>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), FrozenFrontierError> {
    let prefix: Vec<u8> = key(expected.chain_id(), expected.epoch(), FRONTIER_ENTRY_PREFIX)?;
    let prefix_row: VersionedStateValue = store.get_versioned_durable(context, domain, &prefix)?;
    put_read(reads, prefix.clone(), prefix_row.revision())?;
    if prefix_row.value().is_some() || prefix_row.revision() != StateRevision::INITIAL {
        return Err(FrozenFrontierError::Invalid(
            "frontier index prefix slot is not virgin",
        ));
    }
    let after: Vec<u8> = match last {
        None => prefix.clone(),
        Some(last) => entry_key(expected.chain_id(), expected.epoch(), &last)?,
    };
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        Some(DurableRecordKey::State(after)),
        NonZeroUsize::MIN,
    )?;
    let page: runtime::portable::DurableRecordPage =
        store.scan_portable_keys(context, domain, &scan)?;
    match page.keys().first() {
        Some(DurableRecordKey::State(key)) if key.starts_with(&prefix) => {
            Err(FrozenFrontierError::Invalid(
                "frontier index entry is orphaned beyond the logical tail",
            ))
        }
        Some(DurableRecordKey::State(_)) | None => Ok(()),
        Some(_) => Err(FrozenFrontierError::Invalid(
            "non-state frontier index tail",
        )),
    }
}

#[derive(Debug)]
struct PhysicalPublicationPage {
    current_keys: Vec<Vec<u8>>,
    last_request_id: Option<[u8; 32]>,
    terminal: bool,
}

/// One bounded physical step, not a logical current-frontier page. The next
/// verified prior key and the next physically present key are merged, so
/// missing historical rows cannot silently disappear. Every visited row
/// consumes the limit and its deciding revision is fenced by the caller's
/// same gated cursor/index commit. The supplied lookup is private read-only
/// plumbing; only the gate's exact verified base supplies it in production.
#[allow(clippy::too_many_arguments)]
fn physical_publication_page<'p, S, P>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    prefix: &[u8],
    after: Vec<u8>,
    limit: NonZeroUsize,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    next_prior: &P,
) -> Result<PhysicalPublicationPage, FrozenFrontierError>
where
    S: DurablePortableRepository,
    P: Fn(&[u8]) -> Option<(&'p [u8], Option<&'p [u8]>)>,
{
    if limit.get() > MAX_FROZEN_FRONTIER_PAGE_ENTRIES {
        return Err(FrozenFrontierError::Invalid(
            "physical frontier step limit exceeded",
        ));
    }
    let one: NonZeroUsize = NonZeroUsize::MIN;
    let mut cursor: Vec<u8> = after;
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(limit.get());
    let mut last_request_id: Option<[u8; 32]> = None;
    for _ in 0..limit.get() {
        let scan: DurableRecordScan = DurableRecordScan::new(
            DurableCollection::State,
            Some(DurableRecordKey::State(cursor.clone())),
            one,
        )?;
        let page: runtime::portable::DurableRecordPage =
            store.scan_portable_keys(context, domain, &scan)?;
        let stored: Option<&[u8]> = match page.keys().first() {
            None => None,
            Some(DurableRecordKey::State(key)) if key.starts_with(prefix) => Some(key.as_slice()),
            Some(DurableRecordKey::State(_)) => None,
            Some(_) => return Err(FrozenFrontierError::Invalid("non-state frontier scan row")),
        };
        let prior: Option<(&[u8], Option<&[u8]>)> = next_prior(&cursor);
        let key: &[u8] = match (stored, prior) {
            (None, None) => {
                return Ok(PhysicalPublicationPage {
                    current_keys: keys,
                    last_request_id,
                    terminal: true,
                });
            }
            (Some(key), None) => key,
            (None, Some((key, _))) => key,
            (Some(stored), Some((prior, _))) => stored.min(prior),
        };
        if !key.starts_with(prefix) || key <= cursor.as_slice() {
            return Err(FrozenFrontierError::Invalid(
                "physical frontier key order or prefix",
            ));
        }
        if key.len()
            != prefix
                .len()
                .checked_add(32)
                .ok_or(FrozenFrontierError::Invalid("frontier key length overflow"))?
        {
            return Err(FrozenFrontierError::Invalid(
                "malformed frozen publication key",
            ));
        }
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, key)?;
        put_read(reads, key.to_vec(), observed.revision())?;
        if let Some((prior_key, prior_bytes)) = prior
            && prior_key == key
        {
            if prior_bytes.is_none() || observed.value() != prior_bytes {
                return Err(FrozenFrontierError::Invalid(
                    "prior frozen publication is missing or altered",
                ));
            }
        } else {
            if observed.value().is_none() {
                return Err(FrozenFrontierError::Invalid(
                    "current frozen publication is absent or tombstoned",
                ));
            }
            keys.push(key.to_vec());
        }
        last_request_id =
            Some(key[prefix.len()..].try_into().map_err(|_| {
                FrozenFrontierError::Invalid("physical frontier request id length")
            })?);
        cursor = key.to_vec();
    }
    Ok(PhysicalPublicationPage {
        current_keys: keys,
        last_request_id,
        terminal: false,
    })
}

/// Advances at most one retained full-certificate row. A caller can safely
/// repeat this one-event operation after a confirmed prior step. A failed or
/// ambiguous commit exposes no new signature; an exact finalized retry
/// returns only the already committed vote.
#[allow(clippy::too_many_arguments)]
pub fn advance_frozen_frontier<S, C>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &execution::publication::PublicationContext,
    signer: &C,
) -> Result<FrozenFrontierStep, FrozenFrontierError>
where
    S: DurablePortableRepository + StructuredOutboxExclusionGuard,
    C: ConsensusSigner,
{
    advance_frozen_frontier_gated(
        crate::serving_authority::ServingGate::Original,
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        signer,
    )
}

/// Advances the SAME frontier owner under a freshly resolved invocation.
#[allow(clippy::too_many_arguments)]
pub fn advance_frozen_frontier_successor<S, C>(
    warrant: &crate::serving_authority::LiveWarrant<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &execution::publication::PublicationContext,
    signer: &C,
) -> Result<FrozenFrontierStep, FrozenFrontierError>
where
    S: DurablePortableRepository + StructuredOutboxExclusionGuard,
    C: ConsensusSigner,
{
    advance_frozen_frontier_gated(
        crate::serving_authority::ServingGate::Successor(warrant),
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_frozen_frontier_gated<S, C>(
    gate: crate::serving_authority::ServingGate<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &execution::publication::PublicationContext,
    signer: &C,
) -> Result<FrozenFrontierStep, FrozenFrontierError>
where
    S: DurablePortableRepository + StructuredOutboxExclusionGuard,
    C: ConsensusSigner,
{
    // The ordinary entry never grants successor signing authority.
    if matches!(gate, crate::serving_authority::ServingGate::Original) {
        mutation_fence::refuse_successor_serving(store, context, domain)?;
    }
    gate.require_local_signer(store, signer.validator_id())?;
    gate.require_live(store, context, domain)?;
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let installed =
        logical_generation::fence_commitment_profile(store, context, domain, &chain, &mut reads)?;
    if installed
        .logical()
        .is_none_or(|profile| profile.minimum_freeze_block_height == 0)
    {
        return Err(FrozenFrontierError::NotReady(
            "historical profile has no frozen frontier",
        ));
    }
    let epoch_record =
        mutation_fence::fence_epoch_state(store, context, domain, &chain, &mut reads)?;
    if epoch_record.current_epoch != epoch {
        return Err(NodeCoreError::EpochMismatch {
            expected: epoch_record.current_epoch,
            actual: epoch,
        }
        .into());
    }
    let validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        expected,
        &epoch_record,
        &mut reads,
    )?;
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        chain.clone(),
        expected.protocol_version(),
        epoch,
        validator_set.clone(),
    )?;

    let closure_key: Vec<u8> = admission_closure_key(&chain, epoch)?;
    let observed_closure: VersionedStateValue =
        store.get_versioned_durable(context, domain, &closure_key)?;
    put_read(&mut reads, closure_key, observed_closure.revision())?;
    let closure_bytes: &[u8] = match observed_closure.value() {
        Some(bytes) => bytes,
        None if observed_closure.revision() == StateRevision::INITIAL => {
            return Err(FrozenFrontierError::NotReady(
                "ordered Freeze is not committed",
            ));
        }
        None => return Err(FrozenFrontierError::Invalid("Freeze is tombstoned")),
    };
    let closure = decode_admission_closure_record(closure_bytes)?;
    if closure.closed_epoch != epoch || closure.closed_at_block_height == 0 {
        return Err(FrozenFrontierError::Invalid(
            "invalid committed Freeze identity",
        ));
    }

    // The initial handoff profile excludes every outbound obligation. No
    // later ordinary v2 mutation may create one after the Freeze fence.
    let inventory = store.inspect_outbox_exclusion(context, domain)?;
    if inventory.blocks_exclusion() {
        return Err(FrozenFrontierError::NotReady(
            "outbox obligation blocks frontier",
        ));
    }
    let one: NonZeroUsize =
        NonZeroUsize::new(1).ok_or(FrozenFrontierError::Invalid("invalid frontier page limit"))?;
    // The legacy `se/<chain>/vN/outbox/` family belongs to plain StateStore
    // implementations, not this structured-store profile. Its bare-key
    // portable scan would neither address that namespace nor be a valid
    // exclusion proof. Only the structured outbox inventory above governs
    // this store; v2 generic transitions cannot create new obligations.

    let final_key: Vec<u8> = key(&chain, epoch, FRONTIER_FINAL_PREFIX)?;
    let observed_final: VersionedStateValue =
        store.get_versioned_durable(context, domain, &final_key)?;
    put_read(&mut reads, final_key.clone(), observed_final.revision())?;
    if let Some(bytes) = observed_final.value() {
        let final_record: FinalFrontier = decode_final(bytes)?;
        if !final_record.indexed {
            return Err(FrozenFrontierError::Invalid(
                "pre-index final frontier is not complete indexed material",
            ));
        }
        if final_record.identity.chain_id != chain
            || final_record.identity.protocol_version != expected.protocol_version()
            || final_record.identity.closure_request_id != closure.request_id
            || final_record.identity.closure_height != closure.closed_at_block_height
            || final_record.identity.domain != domain
            || final_record.identity.epoch != epoch
        {
            return Err(FrozenFrontierError::Invalid(
                "final frontier disagrees with Freeze",
            ));
        }
        if final_record.vote.validator != signer.validator_id()
            || final_record.vote.signature_scheme != signer.signature_scheme()
        {
            return Err(FrozenFrontierError::Invalid(
                "final frontier signer mismatch",
            ));
        }
        certifier.verify_vote(
            &final_record.vote,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )?;
        return Ok(FrozenFrontierStep::Finalized(Box::new(final_record.vote)));
    }
    if observed_final.revision() != StateRevision::INITIAL {
        return Err(FrozenFrontierError::Invalid("final frontier is tombstoned"));
    }

    let cursor_key: Vec<u8> = key(&chain, epoch, FRONTIER_PROGRESS_PREFIX)?;
    let observed_cursor: VersionedStateValue =
        store.get_versioned_durable(context, domain, &cursor_key)?;
    put_read(&mut reads, cursor_key.clone(), observed_cursor.revision())?;
    let (accumulator, physical_last): (FrozenFrontierAccumulator, Option<[u8; 32]>) =
        if let Some(bytes) = observed_cursor.value() {
            let cursor: FrontierCursor = decode_cursor(bytes)?;
            if !cursor.indexed {
                return Err(FrozenFrontierError::Invalid(
                    "pre-index frontier cursor has no complete current index",
                ));
            }
            if cursor.identity.chain_id != chain
                || cursor.identity.protocol_version != expected.protocol_version()
                || cursor.identity.closure_request_id != closure.request_id
                || cursor.identity.closure_height != closure.closed_at_block_height
                || cursor.identity.domain != domain
                || cursor.identity.epoch != epoch
            {
                return Err(FrozenFrontierError::Invalid(
                    "frontier cursor disagrees with Freeze",
                ));
            }
            let physical_key: Vec<u8> =
                fastpath_publication_key(&chain, &cursor.physical_last_request_id)?;
            let physical_row: VersionedStateValue =
                store.get_versioned_durable(context, domain, &physical_key)?;
            put_read(&mut reads, physical_key.clone(), physical_row.revision())?;
            if physical_row.value().is_none()
                || gate
                    .prior_state_row(&physical_key)
                    .is_some_and(|prior: &[u8]| physical_row.value() != Some(prior))
            {
                return Err(FrozenFrontierError::Invalid(
                    "frontier physical cursor carrier disappeared or changed",
                ));
            }
            let accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::resume(
                resolver,
                cursor.identity,
                cursor.last_request_id,
            )?;
            if let Some(last) = accumulator.last_request_id() {
                let indexed_key: Vec<u8> = entry_key(&chain, epoch, &last)?;
                let indexed_row: VersionedStateValue =
                    store.get_versioned_durable(context, domain, &indexed_key)?;
                put_read(&mut reads, indexed_key, indexed_row.revision())?;
                let entry: FrontierEntry = decode_entry(indexed_row.value().ok_or(
                    FrozenFrontierError::Invalid("frontier logical tail has no index"),
                )?)?;
                validate_entry(&entry, expected, domain, &closure)?;
                if entry.ordinal != accumulator.identity().entry_count
                    || entry.publication.request_id != last
                {
                    return Err(FrozenFrontierError::Invalid(
                        "frontier cursor and indexed logical tail differ",
                    ));
                }
            }
            (accumulator, Some(cursor.physical_last_request_id))
        } else if observed_cursor.revision() == StateRevision::INITIAL {
            (
                FrozenFrontierAccumulator::new(
                    resolver,
                    chain.clone(),
                    expected.protocol_version(),
                    epoch,
                    domain,
                    closure.request_id,
                    closure.closed_at_block_height,
                )?,
                None,
            )
        } else {
            return Err(FrozenFrontierError::Invalid(
                "frontier cursor is tombstoned",
            ));
        };

    require_index_tail(
        store,
        context,
        domain,
        expected,
        accumulator.last_request_id(),
        &mut reads,
    )?;

    let prefix: Vec<u8> = publication_prefix(&chain)?;
    let after_key: Vec<u8> = match physical_last {
        Some(last) => fastpath_publication_key(&chain, &last)?,
        None => prefix.clone(),
    };
    if physical_last.is_none() {
        let prefix_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &prefix)?;
        put_read(&mut reads, prefix.clone(), prefix_row.revision())?;
        if prefix_row.value().is_some() || prefix_row.revision() != StateRevision::INITIAL {
            return Err(FrozenFrontierError::Invalid(
                "invalid publication prefix row",
            ));
        }
    }
    let next_prior = |after: &[u8]| gate.next_prior_state_row(&prefix, after);
    let page: PhysicalPublicationPage = physical_publication_page(
        store,
        context,
        domain,
        &prefix,
        after_key,
        one,
        &mut reads,
        &next_prior,
    )?;
    let mut next: FrozenFrontierAccumulator = accumulator;
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    if let Some(publication_key) = page.current_keys.first() {
        let suffix: &[u8] = &publication_key[prefix.len()..];
        let request_id: [u8; 32] = suffix
            .try_into()
            .map_err(|_| FrozenFrontierError::Invalid("malformed frozen publication key"))?;
        let identity: AvailabilityIdentity = verify_retained_publication(
            store,
            context,
            domain,
            resolver,
            history,
            expected,
            &validator_set,
            signer.validator_id(),
            &request_id,
        )?;
        next.push(resolver, &identity)?;
        let indexed_key: Vec<u8> = entry_key(&chain, epoch, &request_id)?;
        let indexed_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &indexed_key)?;
        put_read(&mut reads, indexed_key.clone(), indexed_row.revision())?;
        if indexed_row.value().is_some() || indexed_row.revision() != StateRevision::INITIAL {
            return Err(FrozenFrontierError::Invalid(
                "frontier entry index slot is not virgin",
            ));
        }
        let entry: FrontierEntry = FrontierEntry {
            closure_request_id: closure.request_id,
            closure_height: closure.closed_at_block_height,
            ordinal: next.identity().entry_count,
            publication: identity,
        };
        mutations.push(StateMutationEntry::new(
            indexed_key,
            StateMutation::Put(encode_entry(&entry)?),
        )?);
    }
    if let Some(physical_last_request_id) = page.last_request_id {
        let count: u64 = next.identity().entry_count;
        let last_request_id: Option<[u8; 32]> = next.last_request_id();
        let cursor: FrontierCursor = FrontierCursor {
            identity: next.into_identity(),
            last_request_id,
            physical_last_request_id,
            indexed: true,
        };
        mutations.push(StateMutationEntry::new(
            cursor_key,
            StateMutation::Put(encode_cursor(&cursor)?),
        )?);
        commit_rows(gate, store, context, domain, reads, mutations)?;
        return Ok(FrozenFrontierStep::Advanced { entry_count: count });
    }

    if !page.terminal {
        return Err(FrozenFrontierError::Invalid(
            "physical frontier page cannot make progress",
        ));
    }
    let identity: FrozenFrontierIdentity = next.into_identity();
    let vote: FrozenFrontierVote = certifier.cast_vote(identity.clone(), signer)?;
    certifier.verify_vote(
        &vote,
        &consensus::Ed25519ConsensusVerifier::new(
            consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
        ),
    )?;
    let final_record: FinalFrontier = FinalFrontier {
        identity,
        vote: vote.clone(),
        indexed: true,
    };
    commit_rows(
        gate,
        store,
        context,
        domain,
        reads,
        vec![StateMutationEntry::new(
            final_key,
            StateMutation::Put(encode_final(&final_record)?),
        )?],
    )?;
    Ok(FrozenFrontierStep::Finalized(Box::new(vote)))
}

/// Reads one bounded, body-free keyset page from a durably finalized local
/// frontier, then re-verifies every selected publication's full certificate,
/// signed intent, ACK and exact retained artifact bytes before returning its
/// identity. The returned vote authenticates the *whole* frontier; a remote
/// caller must verify a consecutive page stream through its terminal page
/// with `FrozenFrontierPageVerifier`, and must obtain the complete bundles
/// separately before any DrainSet vote. This read never signs or mutates.
#[allow(clippy::too_many_arguments)]
pub fn read_frozen_frontier_page<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &execution::publication::PublicationContext,
    local_validator: ValidatorId,
    after_request_id: Option<[u8; 32]>,
    limit: NonZeroUsize,
) -> Result<(FrozenFrontierVote, FrozenFrontierPage), FrozenFrontierError> {
    read_frozen_frontier_page_gated(
        crate::serving_authority::ServingGate::Original,
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        local_validator,
        after_request_id,
        limit,
    )
}

/// Reads the SAME bounded page owner under the exact live invocation.
#[allow(clippy::too_many_arguments)]
pub fn read_frozen_frontier_page_successor<S: DurablePortableRepository>(
    warrant: &crate::serving_authority::LiveWarrant<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &execution::publication::PublicationContext,
    local_validator: ValidatorId,
    after_request_id: Option<[u8; 32]>,
    limit: NonZeroUsize,
) -> Result<(FrozenFrontierVote, FrozenFrontierPage), FrozenFrontierError> {
    read_frozen_frontier_page_gated(
        crate::serving_authority::ServingGate::Successor(warrant),
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        local_validator,
        after_request_id,
        limit,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn read_frozen_frontier_page_gated<S: DurablePortableRepository>(
    gate: crate::serving_authority::ServingGate<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &execution::publication::PublicationContext,
    local_validator: ValidatorId,
    after_request_id: Option<[u8; 32]>,
    limit: NonZeroUsize,
) -> Result<(FrozenFrontierVote, FrozenFrontierPage), FrozenFrontierError> {
    gate.require_material_reader(store, context, domain)?;
    if limit.get() > MAX_FROZEN_FRONTIER_PAGE_ENTRIES {
        return Err(FrozenFrontierError::InvalidCursor(
            "frontier page limit exceeded",
        ));
    }
    if after_request_id == Some([0; 32]) {
        return Err(FrozenFrontierError::InvalidCursor(
            "zero frontier page cursor",
        ));
    }
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let installed =
        logical_generation::fence_commitment_profile(store, context, domain, &chain, &mut reads)?;
    if installed
        .logical()
        .is_none_or(|profile| profile.minimum_freeze_block_height == 0)
    {
        return Err(FrozenFrontierError::NotReady(
            "historical profile has no frozen frontier",
        ));
    }
    let epoch_record =
        mutation_fence::fence_epoch_state(store, context, domain, &chain, &mut reads)?;
    if epoch_record.current_epoch != epoch {
        return Err(NodeCoreError::EpochMismatch {
            expected: epoch_record.current_epoch,
            actual: epoch,
        }
        .into());
    }
    let validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        expected,
        &epoch_record,
        &mut reads,
    )?;
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        chain.clone(),
        expected.protocol_version(),
        epoch,
        validator_set.clone(),
    )?;

    let closure_key: Vec<u8> = admission_closure_key(&chain, epoch)?;
    let closure_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &closure_key)?;
    let closure_bytes: &[u8] = match closure_row.value() {
        Some(bytes) => bytes,
        None if closure_row.revision() == StateRevision::INITIAL => {
            return Err(FrozenFrontierError::NotReady(
                "ordered Freeze is not committed",
            ));
        }
        None => return Err(FrozenFrontierError::Invalid("Freeze is tombstoned")),
    };
    let closure = decode_admission_closure_record(closure_bytes)?;
    if closure.closed_epoch != epoch || closure.closed_at_block_height == 0 {
        return Err(FrozenFrontierError::Invalid("invalid committed Freeze"));
    }
    let final_key: Vec<u8> = key(&chain, epoch, FRONTIER_FINAL_PREFIX)?;
    let final_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &final_key)?;
    let final_bytes: &[u8] = match final_row.value() {
        Some(bytes) => bytes,
        None if final_row.revision() == StateRevision::INITIAL => {
            return Err(FrozenFrontierError::NotReady(
                "frozen frontier is not finalized",
            ));
        }
        None => return Err(FrozenFrontierError::Invalid("frontier is tombstoned")),
    };
    let final_record: FinalFrontier = decode_final(final_bytes)?;
    if !final_record.indexed {
        return Err(FrozenFrontierError::Invalid(
            "pre-index final frontier has no complete current index",
        ));
    }
    if final_record.identity.chain_id != chain
        || final_record.identity.protocol_version != expected.protocol_version()
        || final_record.identity.epoch != epoch
        || final_record.identity.domain != domain
        || final_record.identity.closure_request_id != closure.request_id
        || final_record.identity.closure_height != closure.closed_at_block_height
        || final_record.vote.validator != local_validator
    {
        return Err(FrozenFrontierError::Invalid(
            "final frontier context or local signer mismatch",
        ));
    }
    certifier.verify_vote(
        &final_record.vote,
        &consensus::Ed25519ConsensusVerifier::new(
            consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
        ),
    )?;

    let prefix: Vec<u8> = key(&chain, epoch, FRONTIER_ENTRY_PREFIX)?;
    let mut ordinal: u64 = 0;
    let after_key: Vec<u8> = match after_request_id {
        Some(request_id) => {
            let cursor_key: Vec<u8> = entry_key(&chain, epoch, &request_id)?;
            let cursor_row: VersionedStateValue =
                store.get_versioned_durable(context, domain, &cursor_key)?;
            if cursor_row.value().is_none() {
                return if cursor_row.revision() == StateRevision::INITIAL {
                    Err(FrozenFrontierError::InvalidCursor(
                        "unknown frontier page cursor",
                    ))
                } else {
                    Err(FrozenFrontierError::Invalid(
                        "frontier page cursor is tombstoned",
                    ))
                };
            }
            let entry: FrontierEntry = decode_entry(cursor_row.value().ok_or(
                FrozenFrontierError::InvalidCursor("frontier index cursor is absent"),
            )?)?;
            validate_entry(&entry, expected, domain, &closure)?;
            if entry.publication.request_id != request_id
                || entry.ordinal > final_record.identity.entry_count
            {
                return Err(FrozenFrontierError::InvalidCursor(
                    "frontier index cursor identity differs",
                ));
            }
            let publication: AvailabilityIdentity = verify_retained_publication(
                store,
                context,
                domain,
                resolver,
                history,
                expected,
                &validator_set,
                local_validator,
                &request_id,
            )?;
            if publication != entry.publication {
                return Err(FrozenFrontierError::Invalid(
                    "frontier index cursor differs from actual publication",
                ));
            }
            ordinal = entry.ordinal;
            cursor_key
        }
        None => {
            let prefix_row: VersionedStateValue =
                store.get_versioned_durable(context, domain, &prefix)?;
            if prefix_row.value().is_some() || prefix_row.revision() != StateRevision::INITIAL {
                return Err(FrozenFrontierError::Invalid(
                    "invalid publication prefix row",
                ));
            }
            prefix.clone()
        }
    };
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        Some(DurableRecordKey::State(after_key.clone())),
        limit,
    )?;
    let scanned: runtime::portable::DurableRecordPage =
        store.scan_portable_keys(context, domain, &scan)?;
    let mut exhausted: bool = scanned.keys().len() < limit.get();
    let mut last_key: Vec<u8> = after_key;
    let mut entries: Vec<AvailabilityIdentity> = Vec::with_capacity(scanned.keys().len());
    for record_key in scanned.keys() {
        let indexed_key: &Vec<u8> = match record_key {
            DurableRecordKey::State(indexed_key) => indexed_key,
            _ => return Err(FrozenFrontierError::Invalid("non-state frontier index row")),
        };
        if !indexed_key.starts_with(&prefix) {
            exhausted = true;
            break;
        }
        let request_id: [u8; 32] = indexed_key[prefix.len()..]
            .try_into()
            .map_err(|_| FrozenFrontierError::Invalid("malformed frontier index key"))?;
        let indexed: VersionedStateValue =
            store.get_versioned_durable(context, domain, indexed_key)?;
        let entry: FrontierEntry = decode_entry(indexed.value().ok_or(
            FrozenFrontierError::Invalid("frontier index row is tombstoned"),
        )?)?;
        validate_entry(&entry, expected, domain, &closure)?;
        ordinal = ordinal.checked_add(1).ok_or(FrozenFrontierError::Invalid(
            "frontier index ordinal overflow",
        ))?;
        if entry.ordinal != ordinal
            || ordinal > final_record.identity.entry_count
            || entry.publication.request_id != request_id
            || entry_key(&chain, epoch, &request_id)? != *indexed_key
        {
            return Err(FrozenFrontierError::Invalid(
                "frontier index position or natural key differs",
            ));
        }
        let publication: AvailabilityIdentity = verify_retained_publication(
            store,
            context,
            domain,
            resolver,
            history,
            expected,
            &validator_set,
            local_validator,
            &request_id,
        )?;
        if publication != entry.publication {
            return Err(FrozenFrontierError::Invalid(
                "frontier index differs from actual publication",
            ));
        }
        entries.push(publication);
        last_key = indexed_key.clone();
    }
    let signed_exhausted: bool = ordinal == final_record.identity.entry_count;
    // Public page compatibility: an exactly full page is nonterminal even
    // when it ends at the signed count; the next page is empty and terminal.
    // The index changes lookup cost, never the original canonical stream.
    let terminal: bool = signed_exhausted && entries.len() < limit.get();
    if signed_exhausted && !exhausted {
        // At most one extra key read, never a whole-index re-fold. Exact
        // exhaustion rejects a fabricated row after the signed count even
        // when the preceding page happened to fill its requested limit.
        let tail_scan: DurableRecordScan = DurableRecordScan::new(
            DurableCollection::State,
            Some(DurableRecordKey::State(last_key)),
            NonZeroUsize::MIN,
        )?;
        let tail: runtime::portable::DurableRecordPage =
            store.scan_portable_keys(context, domain, &tail_scan)?;
        match tail.keys().first() {
            Some(DurableRecordKey::State(key)) if key.starts_with(&prefix) => {
                return Err(FrozenFrontierError::Invalid(
                    "frontier index exceeds signed count",
                ));
            }
            Some(DurableRecordKey::State(_)) | None => {}
            Some(_) => {
                return Err(FrozenFrontierError::Invalid(
                    "non-state frontier index tail",
                ));
            }
        }
    } else if !signed_exhausted && (exhausted || entries.is_empty()) {
        return Err(FrozenFrontierError::Invalid(
            "frontier index ends before signed count",
        ));
    }
    let page: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id,
        entries,
        terminal,
    };
    // Validate the same page bounds and strict request ordering as a remote
    // decoder without allocating a second protocol-specific validation path.
    consensus::encode_frozen_frontier_page(&page)?;
    if after_request_id.is_none() && terminal {
        consensus::verify_frozen_frontier(resolver, &final_record.identity, &page.entries)?;
    }
    Ok((final_record.vote, page))
}

#[cfg(test)]
mod tests;
