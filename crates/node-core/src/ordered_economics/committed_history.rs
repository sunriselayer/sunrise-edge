//! Bounded independent verification of the immutable signed consensus proof
//! archive. This verifies order authority only; it does not attest a portable
//! business-state cut or make an imported namespace eligible to serve.

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

/// Reads at most [`MAX_COMMITTED_HISTORY_PAGE`] immutable rows from the
/// importing host's own store. Every proposal and certificate is decoded and
/// reverified against the pinned outgoing validator set. Height and digest
/// continuity are checked across the page boundary; a gap or a conflicting
/// branch cannot be accepted by trusting a source-local committed counter.
pub fn verify_stored_committed_history_page<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    policy: &OrderedEconomicsPolicy,
    tip: &VerifiedCommittedHistoryTip,
    count: usize,
) -> Result<VerifiedCommittedHistoryPage, OrderedEconomicsError> {
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
