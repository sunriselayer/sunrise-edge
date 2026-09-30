//! Bounded independent verification of the immutable signed consensus proof
//! archive, extended so every candidate-bearing committed block is bound to
//! its exact retained candidate bytes, request-id header, retained outcome
//! and original durable request receipt (see
//! [`verify_committed_candidate_linkage`]). This verifies order authority
//! only; it does not attest a portable business-state cut or make an
//! imported namespace eligible to serve, and it installs no new frame and
//! opens no new public serving or import-eligibility path.

use super::*;
use consensus::{CommittedBlock, CommittedBlockProof, decode_committed_block_proof};

/// Rebuilds the claimed block identity from authenticated proposal bytes and
/// verifies the entire three-chain against the pinned outgoing authority.
pub(super) fn verified_committed_block(
    policy: &OrderedEconomicsPolicy,
    proof: &CommittedBlockProof,
) -> Result<CommittedBlock, OrderedEconomicsError> {
    let digest: Digest32 = policy
        .engine()
        .proposal_digest(&proof.committed)
        .map_err(|_| {
            OrderedEconomicsError::Prerequisite("ordered committed proof digest failed")
        })?;
    let block = CommittedBlock {
        height: proof.committed.height,
        view: proof.committed.view,
        digest,
        transactions: proof.committed.transactions.clone(),
    };
    policy
        .engine()
        .verify_committed_block_proof(&block, proof, &super::policy::Ed25519ConsensusVerifier)
        .map_err(|_| {
            OrderedEconomicsError::Prerequisite("ordered committed proof failed authentication")
        })?;
    Ok(block)
}

/// Maximum number of committed heights an importer verifies per call.
pub const MAX_COMMITTED_HISTORY_PAGE: usize = 64;

/// A verified prefix tip. Its fields are private so callers cannot fabricate
/// progress from a source replica's unverified height marker. Restartable
/// import will persist a separate, fenced checkpoint after verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCommittedHistoryTip {
    chain: ChainId,
    epoch: Epoch,
    anchor: Digest32,
    next_height: u64,
    digest: Digest32,
    view: u64,
}

impl VerifiedCommittedHistoryTip {
    /// Starts independent verification at the pinned consensus genesis.
    #[must_use]
    pub fn genesis(policy: &OrderedEconomicsPolicy) -> Self {
        Self {
            chain: policy.context().chain_id().clone(),
            epoch: policy.context().epoch(),
            anchor: policy.anchor(),
            next_height: 1,
            digest: policy.anchor(),
            view: 0,
        }
    }

    /// Height of the last verified committed proposal, zero at genesis.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.next_height - 1
    }

    /// Digest of the last verified committed proposal or genesis anchor.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Checks an externally authenticated terminal commitment. This method
    /// does not authenticate that claim by itself.
    #[must_use]
    pub fn matches_declared_tip(&self, height: u64, digest: Digest32) -> bool {
        self.height() == height && self.digest == digest
    }
}

/// One bounded batch of independently authenticated committed blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCommittedHistoryPage {
    /// Cursor to supply to the next page.
    pub tip: VerifiedCommittedHistoryTip,
    /// Blocks proved in this page, in ascending contiguous height order.
    pub blocks: Vec<CommittedBlock>,
}

/// Independently re-verifies that one candidate-bearing committed block is
/// bound to its own exact retained candidate bytes, request-id header,
/// retained outcome and the ORIGINAL durable request receipt that outcome
/// carries -- not merely that some row exists under a name that looks right.
///
/// [`engine::query_ordered_outcome`] already re-derives the immutable
/// request-header binding and the original receipt cross-check (its own
/// `require_consistent_completion`), so this adds exactly the two checks that
/// depend on the committed block itself: that the retained candidate bytes
/// really hash to the digest the signed and quorum-certified proposal named,
/// that they authenticate purely under the pinned policy (outer/leg
/// signatures, declared context), and that the retained outcome's own
/// `block_height`/`block_digest` are consistent with the block under
/// verification.
///
/// A committed candidate may legitimately recommit at a later height without
/// re-executing (the existing replay-answers-from-retained-outcome path), so
/// the outcome's `block_height` need not equal every block that names its
/// digest -- only the one that first produced it. When that origin height
/// falls inside `verified_so_far` (the blocks this same page call has already
/// verified), this re-derives the match directly against that in-memory
/// block.
///
/// When the origin falls outside this page, its exact archived proof is
/// re-read and independently authenticated before accepting the replay.
/// This still does not prove that two independently read pages came from one
/// stable snapshot: the later cut must bind the pages to one authenticated
/// manifest and reject a store that swaps branches between invocations.
fn verify_committed_candidate_linkage<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    block: &CommittedBlock,
    verified_so_far: &[CommittedBlock],
) -> Result<(), OrderedEconomicsError> {
    let digest: Digest32 = block.transactions[0];
    let chain: ChainId = env.policy.context().chain_id().clone();
    let candidate_key: Vec<u8> = engine::ordered_candidate_record_key(&chain, digest)?;
    let observed_candidate: VersionedStateValue =
        store.get_versioned_durable(context, env.policy.domain(), &candidate_key)?;
    let candidate_bytes: &[u8] =
        observed_candidate
            .value()
            .ok_or(OrderedEconomicsError::Prerequisite(
                "ordered committed history candidate bytes are missing or tombstoned",
            ))?;
    let candidate: OrderedCandidate = decode_ordered_candidate(candidate_bytes).map_err(|_| {
        OrderedEconomicsError::Prerequisite(
            "ordered committed history candidate bytes are malformed",
        )
    })?;
    let recomputed: Digest32 =
        engine::candidate_digest(env.resolver, candidate.context.epoch(), candidate_bytes)?;
    if recomputed != digest {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered committed history candidate bytes do not hash to the committed transaction digest",
        ));
    }
    authenticate_candidate(env, &candidate).map_err(|_| {
        OrderedEconomicsError::Prerequisite(
            "ordered committed history candidate failed authentication",
        )
    })?;
    let outcome: OrderedOutcome =
        query_ordered_outcome(store, context, env, &candidate.request_id)?.ok_or(
            OrderedEconomicsError::Prerequisite(
                "ordered committed history candidate has no retained outcome",
            ),
        )?;
    if outcome.candidate_digest != digest {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered committed history outcome disagrees with the committed candidate digest",
        ));
    }
    if outcome.block_height > block.height {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered committed history outcome claims a height after its own committed block",
        ));
    }
    if outcome.block_height == block.height {
        if outcome.block_digest != block.digest {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered committed history outcome disagrees with the committed block it names",
            ));
        }
    } else if let Some(origin) = verified_so_far
        .iter()
        .find(|earlier| earlier.height == outcome.block_height)
    {
        if origin.digest != outcome.block_digest || origin.transactions != vec![digest] {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered committed history outcome disagrees with its own origin block in this page",
            ));
        }
    } else {
        let origin_key: Vec<u8> = engine::ordered_committed_proof_key(
            &chain,
            env.policy.context().epoch(),
            outcome.block_height,
        )?;
        let origin_row: VersionedStateValue =
            store.get_versioned_durable(context, env.policy.domain(), &origin_key)?;
        let origin_bytes: &[u8] = origin_row
            .value()
            .ok_or(OrderedEconomicsError::Prerequisite(
                "ordered committed history replay origin proof is missing or tombstoned",
            ))?;
        let origin_proof: CommittedBlockProof = decode_committed_block_proof(origin_bytes)
            .map_err(|_| {
                OrderedEconomicsError::Prerequisite(
                    "ordered committed history replay origin proof is malformed",
                )
            })?;
        let origin: CommittedBlock = verified_committed_block(env.policy, &origin_proof)?;
        if origin.height != outcome.block_height
            || origin.digest != outcome.block_digest
            || origin.transactions != vec![digest]
        {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered committed history replay origin proof disagrees with retained outcome",
            ));
        }
    }
    Ok(())
}

/// Reads at most [`MAX_COMMITTED_HISTORY_PAGE`] immutable rows from the
/// importing host's own store. Every proposal and certificate is decoded and
/// reverified against the pinned outgoing validator set. Height and digest
/// continuity are checked across the page boundary; a gap or a conflicting
/// branch cannot be accepted by trusting a source-local committed counter.
/// Every candidate-bearing block is additionally bound to its exact retained
/// candidate bytes, request-id header, retained outcome and original durable
/// request receipt; see [`verify_committed_candidate_linkage`] for exactly
/// what that proves and the one gap it cannot close from a bounded page
/// alone.
pub fn verify_stored_committed_history_page<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    tip: &VerifiedCommittedHistoryTip,
    count: usize,
) -> Result<VerifiedCommittedHistoryPage, OrderedEconomicsError> {
    let policy: &OrderedEconomicsPolicy = env.policy;
    if count == 0 || count > MAX_COMMITTED_HISTORY_PAGE {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered committed history page size is invalid",
        ));
    }
    if tip.chain != *policy.context().chain_id()
        || tip.epoch != policy.context().epoch()
        || tip.anchor != policy.anchor()
    {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered committed history cursor belongs to another authority",
        ));
    }
    let mut verified: VerifiedCommittedHistoryTip = tip.clone();
    let mut blocks: Vec<CommittedBlock> = Vec::with_capacity(count);
    for _ in 0..count {
        let height: u64 = verified.next_height;
        let key: Vec<u8> = engine::ordered_committed_proof_key(
            policy.context().chain_id(),
            policy.context().epoch(),
            height,
        )?;
        let observed: VersionedStateValue =
            store.get_versioned_durable(context, policy.domain(), &key)?;
        let bytes: &[u8] = observed.value().ok_or(OrderedEconomicsError::Prerequisite(
            "ordered committed history proof is missing or tombstoned",
        ))?;
        let proof: CommittedBlockProof = decode_committed_block_proof(bytes).map_err(|_| {
            OrderedEconomicsError::Prerequisite("ordered committed history proof is malformed")
        })?;
        let block: CommittedBlock = verified_committed_block(policy, &proof)?;
        if block.height != height
            || proof.committed.justify.height != height - 1
            || proof.committed.justify.proposal_digest != verified.digest
            || proof.committed.justify.view != verified.view
        {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered committed history is not a contiguous branch",
            ));
        }
        engine::require_profile_shape(&proof.committed)?;
        if !block.transactions.is_empty() {
            verify_committed_candidate_linkage(store, context, env, &block, &blocks)?;
        }
        verified.next_height = height
            .checked_add(1)
            .ok_or(OrderedEconomicsError::Prerequisite(
                "ordered committed history height overflow",
            ))?;
        verified.digest = block.digest;
        verified.view = block.view;
        blocks.push(block);
    }
    Ok(VerifiedCommittedHistoryPage {
        tip: verified,
        blocks,
    })
}
