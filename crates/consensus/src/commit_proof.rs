//! Per-height committed three-chain HotStuff witness (Sunrise Edge Delivery
//! 3, Unit 13).
//!
//! [`ChainedHotStuff`](crate::ChainedHotStuff) commits a block only once it
//! observes a direct three-chain: `committed <- child <- grandchild`, where
//! `child.justify` certifies `committed`, `grandchild.justify` certifies
//! `child`, and some quorum certificate certifies `grandchild` itself. A
//! [`CommittedBlockProof`] is a public, self-contained record of exactly
//! those four objects for one committed block, carrying every proposal and
//! certificate it references inline rather than by reference into
//! [`crate::ConsensusState`]. It can therefore be independently re-verified
//! by [`ChainedHotStuff::verify_committed_block_proof`] long after the
//! proposals it names have been pruned from any validator's live state.
//!
//! [`crate::ConsensusOutput::committed_proofs`] carries one such proof for
//! every entry of `committed_blocks`, in the same order, assembled from
//! state as it stood immediately before pruning. A multi-height commit (or a
//! commit reached after a fork was abandoned) never reuses one proof's
//! `grandchild_certificate` for another committed height: each proof is
//! built from the exact three-chain that justified committing its own
//! block, not merely from the newest certificate the triggering event
//! carried.

use crate::{
    ChainedHotStuff, CommittedBlock, ConsensusError, ConsensusProposal, ConsensusVerifier,
    QuorumCertificate, decode_proposal, decode_quorum_certificate, encode_proposal,
    encode_quorum_certificate,
};
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};

const COMMITTED_BLOCK_PROOF_TYPE_ID: u16 = 0xD017;
const ENCODING_VERSION: u16 = 1;

/// Outer byte bound checked before any parsing, mirroring
/// [`crate::durable`]'s per-type caps: one proof carries at most three
/// [`ConsensusProposal`]s (each bounded by
/// `crate::durable::MAX_ENCODED_PROPOSAL_BYTES`) and one
/// [`QuorumCertificate`] (bounded by
/// `crate::durable::MAX_ENCODED_CERTIFICATE_BYTES`).
pub const MAX_ENCODED_COMMITTED_BLOCK_PROOF_BYTES: usize =
    3 * crate::durable::MAX_ENCODED_PROPOSAL_BYTES + crate::durable::MAX_ENCODED_CERTIFICATE_BYTES;

/// Self-contained three-chain commit witness for one [`CommittedBlock`]
/// (Delivery 3 Unit 13).
///
/// * `committed` -- the proposal the witness proves committed.
/// * `child` -- `committed`'s direct successor; `child.justify` certifies
///   `committed`.
/// * `grandchild` -- `child`'s direct successor; `grandchild.justify`
///   certifies `child`.
/// * `grandchild_certificate` -- an independently re-verified quorum
///   certificate over `grandchild` itself, completing the three-chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedBlockProof {
    /// The committed proposal this witness proves.
    pub committed: ConsensusProposal,
    /// `committed`'s direct successor, whose `justify` certifies it.
    pub child: ConsensusProposal,
    /// `child`'s direct successor, whose `justify` certifies `child`.
    pub grandchild: ConsensusProposal,
    /// Quorum certificate over `grandchild`, completing the three-chain.
    pub grandchild_certificate: QuorumCertificate,
}

fn ensure_encoded_bound(actual: usize) -> Result<(), ConsensusError> {
    if actual > MAX_ENCODED_COMMITTED_BLOCK_PROOF_BYTES {
        return Err(ConsensusError::EncodedFrameTooLarge {
            kind: "committed_block_proof",
            actual,
            max: MAX_ENCODED_COMMITTED_BLOCK_PROOF_BYTES,
        });
    }
    Ok(())
}

/// Encodes a [`CommittedBlockProof`] as one canonical frame (`0xD017/v1`)
/// nesting each proposal's/certificate's own existing canonical encoding.
pub fn encode_committed_block_proof(
    proof: &CommittedBlockProof,
) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical = CanonicalStruct::new(COMMITTED_BLOCK_PROOF_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_proposal(&proof.committed)?)?;
    canonical.field_bytes(2, encode_proposal(&proof.child)?)?;
    canonical.field_bytes(3, encode_proposal(&proof.grandchild)?)?;
    canonical.field_bytes(4, encode_quorum_certificate(&proof.grandchild_certificate)?)?;
    let bytes = canonical.finish()?;
    ensure_encoded_bound(bytes.len())?;
    Ok(bytes)
}

/// Decodes and strictly re-validates one canonical [`CommittedBlockProof`].
///
/// Requires the input to fit [`MAX_ENCODED_COMMITTED_BLOCK_PROOF_BYTES`]
/// before any parsing, the proof type id/encoding version, exactly fields
/// 1-4, every nested value to decode under its own bounded strict decoder
/// ([`decode_proposal`] x3, [`decode_quorum_certificate`] x1), and
/// byte-exact re-encoding of the decoded value. It does not verify any
/// signature, quorum, or chain linkage; callers must still call
/// [`ChainedHotStuff::verify_committed_block_proof`].
pub fn decode_committed_block_proof(input: &[u8]) -> Result<CommittedBlockProof, ConsensusError> {
    ensure_encoded_bound(input.len())?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(COMMITTED_BLOCK_PROOF_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let committed = decode_proposal(frame.required_field(1)?)?;
    let child = decode_proposal(frame.required_field(2)?)?;
    let grandchild = decode_proposal(frame.required_field(3)?)?;
    let grandchild_certificate = decode_quorum_certificate(frame.required_field(4)?)?;
    let proof = CommittedBlockProof {
        committed,
        child,
        grandchild,
        grandchild_certificate,
    };
    if encode_committed_block_proof(&proof)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCommittedBlockProof);
    }
    Ok(proof)
}

impl ChainedHotStuff {
    /// Independently re-verifies a [`CommittedBlockProof`] against
    /// `expected`: every embedded proposal's own signature and justify
    /// certificate, `grandchild_certificate`'s own context and quorum, the
    /// exact digest/view/height linkage `committed -> child -> grandchild`,
    /// and that `proof.committed` is exactly the block `expected` names.
    ///
    /// [`Self::validate_proposal`] independently re-verifies each
    /// proposal's leader signature *and* its own `justify` certificate
    /// (context, canonical vote order, quorum, every vote signature), so
    /// calling it on `child` and `grandchild` already fully re-verifies the
    /// `committed`- and `child`-certifying quorum certificates embedded in
    /// their `justify` fields; only `grandchild_certificate` -- which is not
    /// any proposal's own `justify` -- needs a separate
    /// [`Self::verify_certificate`] call.
    pub fn verify_committed_block_proof<V: ConsensusVerifier>(
        &self,
        expected: &CommittedBlock,
        proof: &CommittedBlockProof,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.validate_proposal(&proof.committed, verifier)?;
        self.validate_proposal(&proof.child, verifier)?;
        self.validate_proposal(&proof.grandchild, verifier)?;
        self.verify_certificate(&proof.grandchild_certificate, verifier)?;

        let committed_digest = self.proposal_digest(&proof.committed)?;
        let child_digest = self.proposal_digest(&proof.child)?;
        let grandchild_digest = self.proposal_digest(&proof.grandchild)?;

        if proof.child.justify.proposal_digest != committed_digest
            || proof.child.justify.view != proof.committed.view
            || proof.child.justify.height != proof.committed.height
        {
            return Err(ConsensusError::CommittedBlockProofChainMismatch(
                "child does not directly justify committed",
            ));
        }
        if proof.grandchild.justify.proposal_digest != child_digest
            || proof.grandchild.justify.view != proof.child.view
            || proof.grandchild.justify.height != proof.child.height
        {
            return Err(ConsensusError::CommittedBlockProofChainMismatch(
                "grandchild does not directly justify child",
            ));
        }
        if proof.grandchild_certificate.proposal_digest != grandchild_digest
            || proof.grandchild_certificate.view != proof.grandchild.view
            || proof.grandchild_certificate.height != proof.grandchild.height
        {
            return Err(ConsensusError::CommittedBlockProofChainMismatch(
                "grandchild_certificate does not certify grandchild",
            ));
        }

        if expected.height != proof.committed.height
            || expected.view != proof.committed.view
            || expected.digest != committed_digest
            || expected.transactions != proof.committed.transactions
        {
            return Err(ConsensusError::CommittedBlockProofIdentityMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
