//! Sunrise RISE claims against a frozen shutdown ledger.
//!
//! The Sunrise chain stops on 5 October 2026. This crate aggregates `rise`
//! rows from that ledger into a Merkle tree, checks a Keplr ADR-036 signature,
//! and decides whether a custody balance may move to a 32-byte Edge address.
//! USDC and IBC assets are not claimed here.
//!
//! A leaf is one claimant and one `claimable_at`. Rows that share both are
//! summed. The tree is not stored on chain; genesis keeps the root, the ledger
//! sha256, and the snapshot time. There is no certified wall clock yet, so a
//! leaf later than the snapshot time stays in the tree and cannot be paid.

mod adr036;
mod merkle;

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

pub use adr036::{
    Authorization, SignatureError, canonical_bytes, encode_sunrise, sign_doc_bytes,
    verify_authorization,
};
pub use merkle::{MerkleProof, MerkleTree, ProofError};

/// One RISE total for a Cosmos claimant at one unlock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf {
    /// Raw 20-byte Cosmos account.
    pub claimant: [u8; 20],
    /// Unix seconds. Later than the snapshot means the leaf is not payable yet.
    pub claimable_at: u64,
    /// Total base units.
    pub amount: u64,
}

/// Frozen ledger header and rows.
#[derive(Debug, Deserialize)]
struct ClaimsFile {
    snapshot_unix: u64,
    claims: Vec<ClaimRow>,
}

#[derive(Debug, Deserialize)]
struct ClaimRow {
    owner: String,
    asset: String,
    amount: String,
    claimable_at: u64,
    payout: String,
}

/// Builds payable and not-yet-payable RISE leaves from a claims file.
pub fn rise_leaves(raw: &[u8]) -> Result<(u64, Vec<Leaf>), ClaimError> {
    let file: ClaimsFile =
        serde_json::from_slice(raw).map_err(|err| ClaimError::Ledger(err.to_string()))?;
    let mut totals: BTreeMap<([u8; 20], u64), u64> = BTreeMap::new();
    for row in file.claims {
        if row.asset != "rise" {
            continue;
        }
        if row.payout != "edge" {
            return Err(ClaimError::Ledger(format!(
                "rise row for {} has payout {}",
                row.owner, row.payout
            )));
        }
        let claimant = adr036::sunrise_address(&row.owner)?;
        let amount: u64 = row
            .amount
            .parse()
            .map_err(|_| ClaimError::Amount(row.amount.clone()))?;
        if amount == 0 {
            continue;
        }
        let entry = totals.entry((claimant, row.claimable_at)).or_insert(0);
        *entry = entry.checked_add(amount).ok_or(ClaimError::Overflow)?;
    }
    let leaves = totals
        .into_iter()
        .map(|((claimant, claimable_at), amount)| Leaf {
            claimant,
            claimable_at,
            amount,
        })
        .collect();
    Ok((file.snapshot_unix, leaves))
}

/// In-memory claim state. The durable chain stores the same fields.
#[derive(Clone, Debug)]
pub struct ClaimState {
    /// Merkle root of the frozen leaves.
    pub root: [u8; 32],
    /// sha256 of the claims file bytes.
    pub ledger_sha256: [u8; 32],
    /// Snapshot unix time. Later leaves are not payable.
    pub snapshot_unix: u64,
    /// Remaining units in the custody coin.
    pub custody: u64,
    /// Amount already paid from each leaf.
    pub consumed: BTreeMap<([u8; 20], u64), u64>,
    /// Nonces already used by each claimant.
    pub nonces: BTreeSet<([u8; 20], u64)>,
}

/// A request to move part of one leaf to an Edge address.
#[derive(Clone, Debug)]
pub struct ClaimRequest {
    /// Signed authorization.
    pub authorization: Authorization,
    /// Compressed secp256k1 pubkey.
    pub pubkey: Vec<u8>,
    /// 64-byte R||S signature over the ADR-036 sign doc.
    pub signature: Vec<u8>,
    /// The leaf the proof commits to.
    pub leaf: Leaf,
    /// Sibling hashes from the leaf up to the root.
    pub proof: Vec<[u8; 32]>,
}

/// Result of a successful claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimReceipt {
    /// Edge recipient.
    pub recipient: [u8; 32],
    /// Amount moved out of custody.
    pub amount: u64,
    /// Custody balance after the move.
    pub custody_remaining: u64,
}

/// Errors from building or applying a claim.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// The claims file is not usable.
    Ledger(String),
    /// An amount is not a u64.
    Amount(String),
    /// A sum exceeded u64.
    Overflow,
    /// The signature, proof, or remaining balance rejected the claim.
    Rejected(String),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ledger(msg) => write!(f, "ledger: {msg}"),
            Self::Amount(value) => write!(f, "amount {value} is not a u64"),
            Self::Overflow => write!(f, "rise total overflowed u64"),
            Self::Rejected(msg) => write!(f, "rejected: {msg}"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Checks one claim and updates custody, consumed units, and the nonce.
pub fn apply_claim(
    state: &mut ClaimState,
    request: &ClaimRequest,
) -> Result<ClaimReceipt, ClaimError> {
    let auth = &request.authorization;
    if auth.asset != "rise" {
        return Err(ClaimError::Rejected(format!(
            "asset {} is not rise",
            auth.asset
        )));
    }
    let ledger =
        hex::decode(&auth.ledger_sha256).map_err(|err| ClaimError::Rejected(err.to_string()))?;
    if ledger.as_slice() != state.ledger_sha256 {
        return Err(ClaimError::Rejected(
            "ledger hash does not match the commitment".into(),
        ));
    }
    let claimant = adr036::sunrise_address(&auth.claimant)?;
    if claimant != request.leaf.claimant {
        return Err(ClaimError::Rejected(
            "signed claimant does not match the leaf".into(),
        ));
    }
    verify_authorization(auth, &request.pubkey, &request.signature)
        .map_err(|err| ClaimError::Rejected(err.to_string()))?;
    if request.leaf.claimable_at > state.snapshot_unix {
        return Err(ClaimError::Rejected(format!(
            "leaf unlocks at {}, snapshot is {}",
            request.leaf.claimable_at, state.snapshot_unix
        )));
    }
    if !(MerkleProof {
        siblings: request.proof.clone(),
    })
    .verifies(state.root, &request.leaf)
    {
        return Err(ClaimError::Rejected(
            "merkle proof does not match the root".into(),
        ));
    }
    if !state.nonces.insert((claimant, auth.nonce)) {
        return Err(ClaimError::Rejected(format!(
            "nonce {} was already used",
            auth.nonce
        )));
    }
    let already = state
        .consumed
        .get(&(claimant, request.leaf.claimable_at))
        .copied()
        .unwrap_or(0);
    let available = request
        .leaf
        .amount
        .checked_sub(already)
        .ok_or(ClaimError::Overflow)?;
    if auth.amount == 0 || auth.amount > available {
        state.nonces.remove(&(claimant, auth.nonce));
        return Err(ClaimError::Rejected(format!(
            "amount {} exceeds available {}",
            auth.amount, available
        )));
    }
    if auth.amount > state.custody {
        state.nonces.remove(&(claimant, auth.nonce));
        return Err(ClaimError::Rejected(format!(
            "amount {} exceeds custody {}",
            auth.amount, state.custody
        )));
    }
    let recipient = parse_edge_address(&auth.destination)?;
    state.custody -= auth.amount;
    state
        .consumed
        .insert((claimant, request.leaf.claimable_at), already + auth.amount);
    Ok(ClaimReceipt {
        recipient,
        amount: auth.amount,
        custody_remaining: state.custody,
    })
}

fn parse_edge_address(value: &str) -> Result<[u8; 32], ClaimError> {
    let text = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(text)
        .map_err(|err| ClaimError::Rejected(format!("destination {value}: {err}")))?;
    let address: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ClaimError::Rejected(format!("destination {value} is not 32 bytes")))?;
    Ok(address)
}

/// sha256 of the raw claims file. This is the value signed in `ledger_sha256`.
pub fn ledger_sha256(raw: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw).into()
}
