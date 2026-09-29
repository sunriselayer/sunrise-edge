//! DR-0154 §"Preserve shared-engine safety before sealing": a bounded,
//! read-only, CAS-folding verifier for the exact predicate a future `Seal`
//! barrier needs before it may treat the shared HotStuff engine as safe to
//! close. `docs/architecture/epoch-handoff.md` states it as "the seal's
//! continuing high/locked suffix is business-free", to be "treat[ed] ... as
//! a protocol predicate over complete verified block headers/justifications,
//! not a leader's Boolean claim".
//!
//! [`verify_business_free_suffix_into`] proves two things about the exact
//! installed [`consensus::ConsensusState`]:
//!
//! * the committed prefix's economic effects are fully applied locally
//!   (`applied_height == committed_height`); and
//! * every certified ancestor strictly above `committed_height`, reached by
//!   walking *both* `high_qc`'s and `locked_qc`'s own justify chains, carries
//!   only closed-admission control candidates
//!   ([`OrderedOperationKind::Freeze`] / [`OrderedOperationKind::DrainSet`]) --
//!   never a business candidate, and never a missing, tombstoned, foreign or
//!   noncanonical one.
//!
//! It never mutates, signs, selects a cut, installs a marker, or implements
//! `Seal` or a writer fence. A future `Seal` barrier composes this predicate
//! with its own independent drain-completion
//! ([`super::drain_completion::verify_drain_complete_into`]) and next-set
//! readiness checks.
//!
//! ## CAS-folding contract
//!
//! Every read this performs -- the installed consensus state, the
//! applied-height marker, and every referenced candidate record -- is folded
//! into a caller-owned `reads: &mut BTreeMap<Vec<u8>, StateRevision>` CAS
//! read set instead of a private one, exactly like
//! [`super::drain_union::verify_drain_ready_into`] and
//! [`super::drain_completion::verify_drain_complete_into`] already do. A
//! future `Seal` vote or proposal can then commit this predicate's exact
//! observations atomically with its own signature: if any observed row's
//! revision moves before that commit, the whole commit is rejected instead of
//! silently exposing a signature over a stale suffix. Folding these reads
//! alone does not by itself make a multi-page or multi-call snapshot stable;
//! only the one atomic commit that finally asserts them together does, and
//! this module never performs that commit.
use super::*;
use consensus::{ConsensusProposal, ConsensusState, decode_consensus_state};

/// Hard bound on the certified-ancestor walk one predicate check performs,
/// applied independently to `high_qc` and `locked_qc`.
/// `ChainedHotStuff::prune_state` retains only a couple of committed heights
/// plus `high_qc`/`locked_qc` themselves, so a legitimate walk terminates in
/// a few steps; this mirrors [`super::engine`]'s own certified-ancestor-walk
/// bound for the same reason.
const MAX_SUFFIX_ANCESTOR_WALK: usize = 64;

/// A storage, decoding or re-verification prerequisite failure. None of these
/// conditions permits treating the suffix as business-free.
#[derive(Debug)]
pub enum SuffixPredicateError {
    /// Storage, encoding or canonical-decoding boundary failure.
    Node(NodeCoreError),
    /// The committed prefix is not yet fully applied locally
    /// (`applied_height != committed_height`): declared catch-up, not a
    /// suffix defect.
    NotReady(&'static str),
    /// A business candidate above `committed_height`, a missing, tombstoned,
    /// foreign or noncanonical candidate record, a digest mismatch, an
    /// unknown certified ancestor, or a consensus state that fails
    /// re-verification.
    Invalid(&'static str),
}

impl fmt::Display for SuffixPredicateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::NotReady(reason) | Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for SuffixPredicateError {}

impl From<NodeCoreError> for SuffixPredicateError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<RuntimeError> for SuffixPredicateError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for SuffixPredicateError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalEncodingError> for SuffixPredicateError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalDecodingError> for SuffixPredicateError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Node(value.into())
    }
}

fn put_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), SuffixPredicateError> {
    if reads
        .insert(key, revision)
        .is_some_and(|prior| prior != revision)
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

/// Re-reads and re-verifies exactly one certified ancestor's referenced
/// candidate body: present, canonical (checked by [`decode_ordered_candidate`]
/// itself), bound to the pinned policy context, digest-matching (the digest
/// recomputed from the exact retrieved bytes must equal the transaction
/// digest the ancestor proposal names, not merely the storage key it was
/// fetched at), and restricted to the two closed-admission control kinds.
/// Every other kind -- every business candidate -- fails closed.
fn verify_control_candidate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    digest: Digest32,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), SuffixPredicateError> {
    let key: Vec<u8> =
        engine::ordered_candidate_record_key(env.policy.context().chain_id(), digest)?;
    let row: VersionedStateValue =
        store.get_versioned_durable(context, env.policy.domain(), &key)?;
    put_read(reads, key, row.revision())?;
    let bytes: &[u8] = row.value().ok_or(SuffixPredicateError::Invalid(
        "certified ancestor's candidate body is missing above the committed height",
    ))?;
    let candidate: OrderedCandidate = decode_ordered_candidate(bytes)?;
    if candidate.context != *env.policy.context() {
        return Err(SuffixPredicateError::Invalid(
            "certified ancestor's candidate body context disagrees with the pinned policy",
        ));
    }
    let recomputed: Digest32 =
        engine::candidate_digest(env.resolver, candidate.context.epoch(), bytes).map_err(|_| {
            SuffixPredicateError::Invalid(
                "certified ancestor's candidate body digest could not be recomputed",
            )
        })?;
    if recomputed != digest {
        return Err(SuffixPredicateError::Invalid(
            "certified ancestor's candidate body digest disagrees with its transaction digest",
        ));
    }
    authenticate_candidate(env, &candidate).map_err(|_| {
        SuffixPredicateError::Invalid(
            "certified ancestor's control candidate failed authentication",
        )
    })?;
    match candidate.kind {
        OrderedOperationKind::Freeze | OrderedOperationKind::DrainSet => Ok(()),
        OrderedOperationKind::FeeClaim
        | OrderedOperationKind::BondLifecycle
        | OrderedOperationKind::BondSlash
        | OrderedOperationKind::Evidence => Err(SuffixPredicateError::Invalid(
            "certified ancestor above the committed height carries a business candidate",
        )),
    }
}

/// Walks one QC's own justify chain strictly above `state.committed_height`,
/// verifying every referenced candidate body along the way. Stops as soon as
/// an ancestor at or below `committed_height` is reached (that prefix is
/// covered by the separate fully-applied check, not by this walk) or the
/// genesis anchor (`justify view == 0`) is reached first.
fn verify_ancestor_chain<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    state: &ConsensusState,
    mut cursor: (Digest32, u64, u64),
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), SuffixPredicateError> {
    for _ in 0..MAX_SUFFIX_ANCESTOR_WALK {
        if cursor.1 == 0 {
            return Ok(());
        }
        let ancestor: &ConsensusProposal =
            state
                .known_proposal(&cursor.0)
                .ok_or(SuffixPredicateError::Invalid(
                    "certified ancestor above the committed height is unknown locally",
                ))?;
        if ancestor.view != cursor.1 || ancestor.height != cursor.2 {
            return Err(SuffixPredicateError::Invalid(
                "certified ancestor disagrees with the referencing certificate",
            ));
        }
        if ancestor.height <= state.committed_height {
            return Ok(());
        }
        if ancestor.transactions.len() > 1
            || (!ancestor.transactions.is_empty() && ancestor.height % 3 != 1)
        {
            return Err(SuffixPredicateError::Invalid(
                "certified ancestor violates the closed ordered scheduling profile",
            ));
        }
        for digest in &ancestor.transactions {
            verify_control_candidate(store, context, env, *digest, reads)?;
        }
        cursor = (
            ancestor.justify.proposal_digest,
            ancestor.justify.view,
            ancestor.justify.height,
        );
    }
    Err(SuffixPredicateError::Invalid(
        "certified-ancestor walk exceeded its bound",
    ))
}

/// Verifies the business-free suffix predicate, folding every read into the
/// caller-owned `reads` CAS read set instead of a fresh, standalone one. See
/// the module documentation for the exact predicate and its CAS-folding
/// contract. This is the variant a future `Seal` vote or proposal must use.
pub fn verify_business_free_suffix_into<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), SuffixPredicateError> {
    let domain: AtomicityDomainId = env.policy.domain();
    let chain: ChainId = env.policy.context().chain_id().clone();

    let state_key: Vec<u8> = engine::ordered_state_key(&chain)?;
    let state_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &state_key)?;
    put_read(reads, state_key, state_row.revision())?;
    let state_bytes: &[u8] = state_row.value().ok_or(SuffixPredicateError::NotReady(
        "ordered economics consensus state is not installed",
    ))?;
    let state: ConsensusState = decode_consensus_state(state_bytes).map_err(|_| {
        SuffixPredicateError::Invalid("ordered economics consensus state does not decode")
    })?;
    env.policy
        .engine()
        .validate_state(&state, &super::policy::Ed25519ConsensusVerifier)
        .map_err(|_| {
            SuffixPredicateError::Invalid(
                "ordered economics consensus state failed re-verification",
            )
        })?;

    let applied_key: Vec<u8> = engine::ordered_applied_height_key(&chain)?;
    let applied_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &applied_key)?;
    put_read(reads, applied_key, applied_row.revision())?;
    let applied_height: u64 = match applied_row.value() {
        Some(bytes) => engine::decode_applied_height(bytes)?,
        None if applied_row.revision() == StateRevision::INITIAL => 0,
        None => {
            return Err(SuffixPredicateError::Invalid(
                "ordered applied-height marker was deleted",
            ));
        }
    };
    if applied_height != state.committed_height {
        return Err(SuffixPredicateError::NotReady(
            "ordered applied prefix lags the committed height; declared catch-up required",
        ));
    }

    verify_ancestor_chain(
        store,
        context,
        env,
        &state,
        (
            state.high_qc.proposal_digest,
            state.high_qc.view,
            state.high_qc.height,
        ),
        reads,
    )?;
    verify_ancestor_chain(
        store,
        context,
        env,
        &state,
        (
            state.locked_qc.proposal_digest,
            state.locked_qc.view,
            state.locked_qc.height,
        ),
        reads,
    )?;
    Ok(())
}

/// Same check as [`verify_business_free_suffix_into`], for a caller with no
/// CAS read set of its own; every read is folded into a fresh one and
/// discarded. Not itself usable by a `Seal` vote, which must fold these reads
/// into its own atomic commit instead.
pub fn verify_business_free_suffix<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<(), SuffixPredicateError> {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    verify_business_free_suffix_into(store, context, env, &mut reads)
}
