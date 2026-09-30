//! Merkle tree over RISE leaves.
//!
//! A leaf hash is sha256(0x00 || claimant || claimable_at || amount).
//! An internal node is sha256(0x01 || left || right) after sorting the two
//! children, so a proof is only the sibling hashes.

use sha2::{Digest, Sha256};

use crate::Leaf;

/// A tree built from an ordered leaf list.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    root: [u8; 32],
    leaves: Vec<Leaf>,
}

impl MerkleTree {
    /// Builds a tree. The leaf list must be non-empty.
    pub fn new(leaves: &[Leaf]) -> Option<Self> {
        if leaves.is_empty() {
            return None;
        }
        let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
        while level.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                if i + 1 == level.len() {
                    next.push(level[i]);
                } else {
                    next.push(node_hash(level[i], level[i + 1]));
                }
                i += 2;
            }
            level = next;
        }
        Some(Self {
            root: level[0],
            leaves: leaves.to_vec(),
        })
    }

    /// Root pinned in the Edge commitment.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Proof for the leaf at `index`.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut level: Vec<[u8; 32]> = self.leaves.iter().map(leaf_hash).collect();
        let mut cursor = index;
        while level.len() > 1 {
            let sibling = if cursor % 2 == 0 {
                if cursor + 1 < level.len() {
                    Some(level[cursor + 1])
                } else {
                    None
                }
            } else {
                Some(level[cursor - 1])
            };
            if let Some(hash) = sibling {
                siblings.push(hash);
            }
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                if i + 1 == level.len() {
                    next.push(level[i]);
                } else {
                    next.push(node_hash(level[i], level[i + 1]));
                }
                i += 2;
            }
            cursor /= 2;
            level = next;
        }
        Some(MerkleProof { siblings })
    }
}

/// Sibling hashes from a leaf to the root.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Sibling at each level.
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Returns whether `leaf` is committed by `root`.
    pub fn verifies(&self, root: [u8; 32], leaf: &Leaf) -> bool {
        let mut current = leaf_hash(leaf);
        for sibling in &self.siblings {
            current = node_hash(current, *sibling);
        }
        current == root
    }
}

/// Proof errors. Verification itself returns a boolean.
#[derive(Debug, PartialEq, Eq)]
pub struct ProofError;

fn leaf_hash(leaf: &Leaf) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf.claimant);
    hasher.update(leaf.asset.as_bytes());
    hasher.update([0xff]);
    hasher.update(leaf.claimable_at.to_be_bytes());
    hasher.update(leaf.amount.to_be_bytes());
    hasher.finalize().into()
}

fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (first, second) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}
