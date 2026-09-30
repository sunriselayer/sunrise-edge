//! Derives a candidate-free, certified post-DrainSet terminal witness from
//! the locally committed HotStuff state. This is a pre-Seal predicate, not a
//! portable cut, signed cut decision, import authorization or serving gate.
//!
//! The witness carries an already-signed three-chain proof. It creates no
//! new signature and does not trust the replica's height counter alone. A
//! future cut must independently verify the complete genesis-to-tip history,
//! original candidate/outcome/receipt and business-state collections, then
//! fold this function's read assertions into its own atomic decision.

use super::*;
use consensus::{CommittedBlockProof, ConsensusState, DrainUnionIdentity};

#[derive(Debug)]
pub enum TerminalAnchorError {
    Node(NodeCoreError),
    Barrier(Box<BusinessFreeBarrierError>),
    Drain(DrainCompletionError),
    Suffix(SuffixPredicateError),
    NotReady(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for TerminalAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::Barrier(error) => error.fmt(formatter),
            Self::Drain(error) => error.fmt(formatter),
            Self::Suffix(error) => error.fmt(formatter),
            Self::NotReady(reason) | Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for TerminalAnchorError {}

impl From<NodeCoreError> for TerminalAnchorError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}

impl From<RuntimeError> for TerminalAnchorError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}

impl From<DurableReadError> for TerminalAnchorError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}

impl From<BusinessFreeBarrierError> for TerminalAnchorError {
    fn from(value: BusinessFreeBarrierError) -> Self {
        Self::Barrier(Box::new(value))
    }
}

impl From<DrainCompletionError> for TerminalAnchorError {
    fn from(value: DrainCompletionError) -> Self {
        Self::Drain(value)
    }
}

impl From<SuffixPredicateError> for TerminalAnchorError {
    fn from(value: SuffixPredicateError) -> Self {
        Self::Suffix(value)
    }
}

/// A verified local witness for one candidate-free committed block and its
/// two candidate-free certified descendants. Its private fields prevent a
/// caller from constructing an apparently verified witness from an asserted
/// height or a local barrier marker alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateFreeTerminalWitness {
    drain_identity: DrainUnionIdentity,
    height: u64,
    digest: Digest32,
    proof: CommittedBlockProof,
}

impl CandidateFreeTerminalWitness {
    #[must_use]
    pub fn drain_identity(&self) -> &DrainUnionIdentity {
        &self.drain_identity
    }

    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    #[must_use]
    pub fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Exact already-signed witness bytes can later be exported separately;
    /// this value alone does not attest a complete imported prefix.
    #[must_use]
    pub fn proof(&self) -> &CommittedBlockProof {
        &self.proof
    }
}

fn assert_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), TerminalAnchorError> {
    match reads.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(revision);
            Ok(())
        }
        std::collections::btree_map::Entry::Occupied(entry) if *entry.get() == revision => Ok(()),
        std::collections::btree_map::Entry::Occupied(_) => Err(TerminalAnchorError::Invalid(
            "terminal anchor read changed within one invocation",
        )),
    }
}

/// Derives a post-DrainSet certified empty tip and folds every local
/// prerequisite read into the caller's CAS read set. The proof itself is
/// authenticated by the pinned outgoing validator set; the local barrier is
/// only a writer fence and is never exported as authority.
///
/// The current committed height is selected as a *candidate* tip, not
/// trusted as proof. Its immutable proof must re-verify, match the live
/// committed proposal exactly, and be strictly after the receipt-backed
/// DrainSet height. Its committed block, child and grandchild must all be
/// candidate-free. A caller must still independently verify every earlier
/// proof page and the ordered/business artifact closure before using the
/// returned digest in a cut. Returning a witness does not itself commit a
/// cut or make an import eligible to serve.
pub fn derive_candidate_free_terminal_into<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<CandidateFreeTerminalWitness, TerminalAnchorError> {
    let expected: &execution::publication::PublicationContext = env.policy.context();
    let chain: &ChainId = expected.chain_id();
    let epoch: Epoch = expected.epoch();
    let domain: AtomicityDomainId = env.policy.domain();

    let serving: crate::local_instance_state::FastPathEpochRecord =
        crate::mutation_fence::fence_epoch_state(store, context, domain, chain, reads)?;
    if serving.current_epoch != epoch {
        return Err(TerminalAnchorError::NotReady(
            "terminal anchor policy is not the current serving epoch",
        ));
    }

    let drain_identity: DrainUnionIdentity = super::drain_completion::verify_drain_complete_into(
        store,
        context,
        domain,
        env.resolver,
        expected,
        reads,
    )?;
    // `DrainUnionIdentity::closure_height` names the earlier Freeze, not the
    // committed DrainSet. The empty terminal must follow the latter.
    let drain_key: Vec<u8> = super::drain_set::drain_set_record_key(chain, epoch)?;
    let drain_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &drain_key)?;
    assert_read(reads, drain_key, drain_row.revision())?;
    let drain_bytes: &[u8] = drain_row.value().ok_or(TerminalAnchorError::Invalid(
        "committed DrainSet record is missing or tombstoned",
    ))?;
    let drain_record: DrainSetRecord = super::drain_set::decode_drain_set_record(drain_bytes)
        .map_err(|_| TerminalAnchorError::Invalid("committed DrainSet record is malformed"))?;
    if drain_record.drain_union_identity != drain_identity {
        return Err(TerminalAnchorError::Invalid(
            "committed DrainSet disagrees with verified drain completion",
        ));
    }
    let barrier_key: Vec<u8> = engine::business_free_barrier_key(chain, epoch)?;
    let barrier_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &barrier_key)?;
    assert_read(reads, barrier_key, barrier_row.revision())?;
    let barrier_bytes: &[u8] = match barrier_row.value() {
        Some(bytes) => bytes,
        None if barrier_row.revision() == StateRevision::INITIAL => {
            return Err(TerminalAnchorError::NotReady(
                "business-free barrier is not installed",
            ));
        }
        None => {
            return Err(TerminalAnchorError::Invalid(
                "business-free barrier is tombstoned",
            ));
        }
    };
    let barrier_identity: DrainUnionIdentity =
        super::business_free_barrier::decode_barrier(barrier_bytes, chain, epoch)?;
    if barrier_identity != drain_identity {
        return Err(TerminalAnchorError::Invalid(
            "business-free barrier disagrees with completed DrainSet",
        ));
    }

    super::suffix_predicate::verify_business_free_suffix_into(store, context, env, reads)?;
    let state_key: Vec<u8> = engine::ordered_state_key(chain)?;
    let state_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &state_key)?;
    assert_read(reads, state_key, state_row.revision())?;
    let state_bytes: &[u8] = state_row.value().ok_or(TerminalAnchorError::Invalid(
        "ordered consensus state is missing or tombstoned",
    ))?;
    let state: ConsensusState = consensus::decode_consensus_state(state_bytes)
        .map_err(|_| TerminalAnchorError::Invalid("ordered consensus state does not decode"))?;
    if state.committed_height <= drain_record.committed_at_block_height {
        return Err(TerminalAnchorError::NotReady(
            "no committed block after DrainSet is available",
        ));
    }

    let proof_key: Vec<u8> =
        engine::ordered_committed_proof_key(chain, epoch, state.committed_height)?;
    let proof_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &proof_key)?;
    assert_read(reads, proof_key, proof_row.revision())?;
    let proof_bytes: &[u8] = proof_row.value().ok_or(TerminalAnchorError::Invalid(
        "terminal committed proof is missing or tombstoned",
    ))?;
    let proof: CommittedBlockProof = consensus::decode_committed_block_proof(proof_bytes)
        .map_err(|_| TerminalAnchorError::Invalid("terminal committed proof is malformed"))?;
    let block: consensus::CommittedBlock =
        super::committed_history::verified_committed_block(env.policy, &proof).map_err(|_| {
            TerminalAnchorError::Invalid("terminal committed proof failed authentication")
        })?;
    if block.height != state.committed_height
        || !state.contains_committed(&block.digest)
        || state.known_proposal(&block.digest) != Some(&proof.committed)
    {
        return Err(TerminalAnchorError::Invalid(
            "terminal committed proof disagrees with the live committed tip",
        ));
    }
    if !block.transactions.is_empty()
        || !proof.child.transactions.is_empty()
        || !proof.grandchild.transactions.is_empty()
    {
        return Err(TerminalAnchorError::Invalid(
            "terminal three-chain contains a candidate",
        ));
    }

    Ok(CandidateFreeTerminalWitness {
        drain_identity,
        height: block.height,
        digest: block.digest,
        proof,
    })
}
