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
use crate::fast_path::{FastPathEd25519Verifier, FastPathError, load_validator_set};
use canonical_encoding::{decode_canonical_frame, encode_chain_id};
use consensus::{
    ConsensusSigner, FrontierError, FrozenFrontierAccumulator, FrozenFrontierCertifier,
    FrozenFrontierIdentity, FrozenFrontierPage, FrozenFrontierVote,
    MAX_FROZEN_FRONTIER_PAGE_ENTRIES, decode_frozen_frontier_identity, decode_frozen_frontier_vote,
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
const ENCODING_VERSION: u16 = 1;
const FRONTIER_PROGRESS_PREFIX: &[u8] = b"frontier-progress/";
const FRONTIER_FINAL_PREFIX: &[u8] = b"frontier/";

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
    Invalid(&'static str),
}

impl fmt::Display for FrozenFrontierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::Frontier(error) => error.fmt(formatter),
            Self::Publication(error) => error.fmt(formatter),
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for FrozenFrontierError {}

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
struct FrontierCursor {
    identity: FrozenFrontierIdentity,
    last_request_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FinalFrontier {
    identity: FrozenFrontierIdentity,
    vote: FrozenFrontierVote,
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
    if cursor.identity.entry_count == 0 || cursor.last_request_id == [0; 32] {
        return Err(FrozenFrontierError::Invalid("invalid frontier cursor"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(FRONTIER_CURSOR_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_frozen_frontier_identity(&cursor.identity)?)?;
    frame.field_bytes(2, cursor.last_request_id.to_vec())?;
    Ok(frame.finish()?)
}

fn decode_cursor(input: &[u8]) -> Result<FrontierCursor, FrozenFrontierError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_CURSOR_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let last_request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| FrozenFrontierError::Invalid("frontier cursor request id length"))?;
    let cursor = FrontierCursor {
        identity: decode_frozen_frontier_identity(frame.required_field(1)?)?,
        last_request_id,
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
    let mut frame: CanonicalStruct = CanonicalStruct::new(FRONTIER_FINAL_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_frozen_frontier_identity(&record.identity)?)?;
    frame.field_bytes(2, encode_frozen_frontier_vote(&record.vote)?)?;
    Ok(frame.finish()?)
}

fn decode_final(input: &[u8]) -> Result<FinalFrontier, FrozenFrontierError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FRONTIER_FINAL_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let record = FinalFrontier {
        identity: decode_frozen_frontier_identity(frame.required_field(1)?)?,
        vote: decode_frozen_frontier_vote(frame.required_field(2)?)?,
    };
    if encode_final(&record)?.as_slice() != input {
        return Err(FrozenFrontierError::Invalid("noncanonical final frontier"));
    }
    Ok(record)
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

fn commit_row<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    bytes: Vec<u8>,
) -> Result<(), FrozenFrontierError> {
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(
            key,
            StateMutation::Put(bytes),
        )?])?,
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

/// The exact `chain`-then-`epoch` prefix every retained publication row for
/// one closed epoch shares. Bounding the scan below to this prefix, rather
/// than to `chain` alone, is what keeps an older or newer epoch's retained
/// row entirely outside this epoch's frontier: a request id from another
/// epoch can never sort inside this range no matter how its bytes compare to
/// this epoch's request ids.
fn publication_prefix(chain: &ChainId, epoch: Epoch) -> Result<Vec<u8>, FrozenFrontierError> {
    let mut prefix: Vec<u8> = fastpath_publication_key(chain, epoch, &[0; 32])?;
    prefix.truncate(prefix.len() - 32);
    Ok(prefix)
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
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let installed =
        logical_generation::fence_commitment_profile(store, context, domain, &chain, &mut reads)?;
    if installed.logical().is_none() {
        return Err(FrozenFrontierError::Invalid(
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
    let closure_bytes: &[u8] = observed_closure
        .value()
        .ok_or(FrozenFrontierError::Invalid(
            "ordered Freeze is not committed",
        ))?;
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
        return Err(FrozenFrontierError::Invalid(
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
        if final_record.identity.closure_request_id != closure.request_id
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
        certifier.verify_vote(&final_record.vote, &FastPathEd25519Verifier)?;
        return Ok(FrozenFrontierStep::Finalized(Box::new(final_record.vote)));
    }
    if observed_final.revision() != StateRevision::INITIAL {
        return Err(FrozenFrontierError::Invalid("final frontier is tombstoned"));
    }

    let cursor_key: Vec<u8> = key(&chain, epoch, FRONTIER_PROGRESS_PREFIX)?;
    let observed_cursor: VersionedStateValue =
        store.get_versioned_durable(context, domain, &cursor_key)?;
    put_read(&mut reads, cursor_key.clone(), observed_cursor.revision())?;
    let accumulator: FrozenFrontierAccumulator = if let Some(bytes) = observed_cursor.value() {
        let cursor: FrontierCursor = decode_cursor(bytes)?;
        if cursor.identity.closure_request_id != closure.request_id
            || cursor.identity.closure_height != closure.closed_at_block_height
            || cursor.identity.domain != domain
            || cursor.identity.epoch != epoch
        {
            return Err(FrozenFrontierError::Invalid(
                "frontier cursor disagrees with Freeze",
            ));
        }
        FrozenFrontierAccumulator::resume(resolver, cursor.identity, Some(cursor.last_request_id))?
    } else if observed_cursor.revision() == StateRevision::INITIAL {
        FrozenFrontierAccumulator::new(
            resolver,
            chain.clone(),
            expected.protocol_version(),
            epoch,
            domain,
            closure.request_id,
            closure.closed_at_block_height,
        )?
    } else {
        return Err(FrozenFrontierError::Invalid(
            "frontier cursor is tombstoned",
        ));
    };

    let prefix: Vec<u8> = publication_prefix(&chain, epoch)?;
    let after_key: Vec<u8> = match accumulator.last_request_id() {
        Some(last) => fastpath_publication_key(&chain, epoch, &last)?,
        None => prefix.clone(),
    };
    if accumulator.last_request_id().is_none() {
        let prefix_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &prefix)?;
        if prefix_row.value().is_some() || prefix_row.revision() != StateRevision::INITIAL {
            return Err(FrozenFrontierError::Invalid(
                "invalid publication prefix row",
            ));
        }
    }
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        Some(DurableRecordKey::State(after_key)),
        one,
    )?;
    let page = store.scan_portable_keys(context, domain, &scan)?;
    if let Some(DurableRecordKey::State(publication_key)) = page.keys().first()
        && publication_key.starts_with(&prefix)
    {
        let suffix: &[u8] = &publication_key[prefix.len()..];
        let request_id: [u8; 32] = suffix
            .try_into()
            .map_err(|_| FrozenFrontierError::Invalid("malformed frozen publication key"))?;
        let identity = verify_retained_publication(
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
        let mut next: FrozenFrontierAccumulator = accumulator;
        next.push(resolver, &identity)?;
        let count: u64 = next.identity().entry_count;
        let cursor: FrontierCursor = FrontierCursor {
            identity: next.into_identity(),
            last_request_id: request_id,
        };
        commit_row(
            store,
            context,
            domain,
            reads,
            cursor_key,
            encode_cursor(&cursor)?,
        )?;
        return Ok(FrozenFrontierStep::Advanced { entry_count: count });
    }

    let identity: FrozenFrontierIdentity = accumulator.into_identity();
    let vote: FrozenFrontierVote = certifier.cast_vote(identity.clone(), signer)?;
    certifier.verify_vote(&vote, &FastPathEd25519Verifier)?;
    let final_record: FinalFrontier = FinalFrontier {
        identity,
        vote: vote.clone(),
    };
    commit_row(
        store,
        context,
        domain,
        reads,
        final_key,
        encode_final(&final_record)?,
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
    if limit.get() > MAX_FROZEN_FRONTIER_PAGE_ENTRIES {
        return Err(FrozenFrontierError::Invalid("frontier page limit exceeded"));
    }
    if after_request_id == Some([0; 32]) {
        return Err(FrozenFrontierError::Invalid("zero frontier page cursor"));
    }
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let installed =
        logical_generation::fence_commitment_profile(store, context, domain, &chain, &mut reads)?;
    if installed.logical().is_none() {
        return Err(FrozenFrontierError::Invalid(
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
    let closure_bytes: &[u8] = closure_row.value().ok_or(FrozenFrontierError::Invalid(
        "ordered Freeze is not committed",
    ))?;
    let closure = decode_admission_closure_record(closure_bytes)?;
    if closure.closed_epoch != epoch || closure.closed_at_block_height == 0 {
        return Err(FrozenFrontierError::Invalid("invalid committed Freeze"));
    }
    let final_key: Vec<u8> = key(&chain, epoch, FRONTIER_FINAL_PREFIX)?;
    let final_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &final_key)?;
    let final_bytes: &[u8] = final_row.value().ok_or(FrozenFrontierError::Invalid(
        "frozen frontier is not finalized",
    ))?;
    let final_record: FinalFrontier = decode_final(final_bytes)?;
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
    certifier.verify_vote(&final_record.vote, &FastPathEd25519Verifier)?;

    let prefix: Vec<u8> = publication_prefix(&chain, epoch)?;
    let after_key: Vec<u8> = match after_request_id {
        Some(request_id) => {
            verify_retained_publication(
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
            fastpath_publication_key(&chain, epoch, &request_id)?
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
        Some(DurableRecordKey::State(after_key)),
        limit,
    )?;
    let scanned = store.scan_portable_keys(context, domain, &scan)?;
    let mut entries: Vec<consensus::AvailabilityIdentity> =
        Vec::with_capacity(scanned.keys().len());
    let mut terminal: bool = scanned.continuation().is_none();
    for row in scanned.keys() {
        let DurableRecordKey::State(publication_key) = row else {
            return Err(FrozenFrontierError::Invalid("non-state frontier scan row"));
        };
        if !publication_key.starts_with(&prefix) {
            terminal = true;
            break;
        }
        let request_id: [u8; 32] = publication_key[prefix.len()..]
            .try_into()
            .map_err(|_| FrozenFrontierError::Invalid("malformed frozen publication key"))?;
        entries.push(verify_retained_publication(
            store,
            context,
            domain,
            resolver,
            history,
            expected,
            &validator_set,
            local_validator,
            &request_id,
        )?);
    }
    if entries.is_empty() {
        terminal = true;
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
