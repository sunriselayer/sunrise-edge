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

/// One frozen total for a Cosmos claimant, asset, and unlock time.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf {
    /// Raw 20-byte Cosmos account.
    pub claimant: [u8; 20],
    /// `rise`, `usdrise`, `usdn`, or an IBC denom.
    pub asset: String,
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
}

/// The USDRise wrapper. Its USDN is the backing for USDrise, so that balance
/// is not a second claim.
const USDRISE_WRAPPER: &str = "sunrise14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s2v9j75";
const USDN_IBC: &str = "ibc/A7AD825A4B48DDA0138D118655E60100D22A4D690C45B95221520B58C9A64B63";

/// Builds one leaf per claimant, asset, and unlock time.
///
/// `rise` and `usdrise` stay on Edge. Unwrapped USDN is added to `usdrise`.
/// The wrapper contract's own USDN is skipped. Other IBC denoms are settled
/// on the chain named in [`payout_route`].
pub fn ledger_leaves(raw: &[u8]) -> Result<(u64, Vec<Leaf>), ClaimError> {
    let file: ClaimsFile =
        serde_json::from_slice(raw).map_err(|err| ClaimError::Ledger(err.to_string()))?;
    let mut totals: BTreeMap<([u8; 20], String, u64), u64> = BTreeMap::new();
    for row in file.claims {
        if is_wrapper_usdn(&row.owner, &row.asset) {
            continue;
        }
        let asset = if is_usdn(&row.asset) {
            "usdrise".to_string()
        } else {
            row.asset.clone()
        };
        if payout_route(&asset).is_none() && !is_edge_asset(&asset) {
            return Err(ClaimError::Ledger(format!("unknown asset {}", row.asset)));
        }
        let claimant = adr036::sunrise_address(&row.owner)?;
        let amount: u64 = row
            .amount
            .parse()
            .map_err(|_| ClaimError::Amount(row.amount.clone()))?;
        if amount == 0 {
            continue;
        }
        let entry = totals
            .entry((claimant, asset, row.claimable_at))
            .or_insert(0);
        *entry = entry.checked_add(amount).ok_or(ClaimError::Overflow)?;
    }
    let leaves = totals
        .into_iter()
        .map(|((claimant, asset, claimable_at), amount)| Leaf {
            claimant,
            asset,
            claimable_at,
            amount,
        })
        .collect();
    Ok((file.snapshot_unix, leaves))
}

fn is_usdn(asset: &str) -> bool {
    asset == "usdn" || asset == USDN_IBC
}

fn is_wrapper_usdn(owner: &str, asset: &str) -> bool {
    owner == USDRISE_WRAPPER && is_usdn(asset)
}

fn is_edge_asset(asset: &str) -> bool {
    asset == "rise" || asset == "usdrise"
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
    /// Remaining units of each Edge asset in protocol custody.
    pub custody: BTreeMap<String, u64>,
    /// Edge balance already claimed and not yet withdrawn, by claimant and asset.
    pub edge_balance: BTreeMap<([u8; 20], String), u64>,
    /// Amount already taken from each leaf.
    pub consumed: BTreeMap<([u8; 20], String, u64), u64>,
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

/// Where a successful claim settles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// Units moved from protocol custody to an Edge address.
    Edge {
        /// `rise` or `usdrise`.
        asset: String,
        /// 32-byte Edge address.
        recipient: [u8; 32],
        /// Amount credited.
        amount: u64,
    },
    /// Instruction for the hot-wallet process. Edge does not send this.
    External(PayoutOrder),
}

/// One hot-wallet payment already authorized by a claim.
///
/// Field order of [`payout_order_bytes`] is the bytes `sunrise-payout` verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutOrder {
    /// Claim asset, such as `usdn` or `usdrise`.
    pub asset: String,
    /// Destination chain. `1` is Ethereum mainnet.
    pub chain_id: String,
    /// Token denom or ERC-20 contract.
    pub denom: String,
    /// EVM or bech32 destination.
    pub destination: String,
    /// Base units to send.
    pub amount: u64,
    /// Bech32 claimant.
    pub claimant: String,
    /// Nonce from the authorization.
    pub nonce: u64,
    /// Hex sha256 of the claims file.
    pub ledger_sha256: String,
}

/// Canonical JSON for a payout order. Keys are alphabetical.
pub fn payout_order_bytes(order: &PayoutOrder) -> Vec<u8> {
    format!(
        r#"{{"amount":"{}","asset":"{}","chain_id":"{}","claimant":"{}","denom":"{}","destination":"{}","ledger_sha256":"{}","nonce":{}}}"#,
        order.amount,
        order.asset,
        order.chain_id,
        order.claimant,
        order.denom,
        order.destination,
        order.ledger_sha256,
        order.nonce
    )
    .into_bytes()
}

/// sha256 of [`payout_order_bytes`], hex. The hot wallet records this id.
pub fn payout_order_id(order: &PayoutOrder) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(payout_order_bytes(order)))
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
) -> Result<Settlement, ClaimError> {
    let auth = &request.authorization;
    if auth.asset != request.leaf.asset {
        return Err(ClaimError::Rejected(
            "signed asset does not match the leaf".into(),
        ));
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
    let key = (
        claimant,
        request.leaf.asset.clone(),
        request.leaf.claimable_at,
    );
    let already = state.consumed.get(&key).copied().unwrap_or(0);
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
    state.consumed.insert(key, already + auth.amount);
    if is_edge_asset(&auth.asset) {
        let recipient = parse_edge_address(&auth.destination)?;
        let custody = state.custody.entry(auth.asset.clone()).or_insert(0);
        if auth.amount > *custody {
            state.nonces.remove(&(claimant, auth.nonce));
            state.consumed.insert(
                (claimant, auth.asset.clone(), request.leaf.claimable_at),
                already,
            );
            return Err(ClaimError::Rejected(format!(
                "amount {} exceeds {} custody {}",
                auth.amount, auth.asset, *custody
            )));
        }
        *custody -= auth.amount;
        let balance = state
            .edge_balance
            .entry((claimant, auth.asset.clone()))
            .or_insert(0);
        *balance = balance
            .checked_add(auth.amount)
            .ok_or(ClaimError::Overflow)?;
        return Ok(Settlement::Edge {
            asset: auth.asset.clone(),
            recipient,
            amount: auth.amount,
        });
    }
    let route = payout_route(&auth.asset)
        .ok_or_else(|| ClaimError::Rejected(format!("asset {} has no payout route", auth.asset)))?;
    validate_external_destination(route, &auth.destination)?;
    Ok(Settlement::External(PayoutOrder {
        asset: auth.asset.clone(),
        chain_id: route.chain_id.into(),
        denom: route.denom.into(),
        destination: auth.destination.clone(),
        amount: auth.amount,
        claimant: auth.claimant.clone(),
        nonce: auth.nonce,
        ledger_sha256: auth.ledger_sha256.clone(),
    }))
}

/// Burns credited USDrise and authorizes an Ethereum USDC send of the same base units.
pub fn withdraw_usdrise(
    state: &mut ClaimState,
    request: &ClaimRequest,
) -> Result<PayoutOrder, ClaimError> {
    let auth = &request.authorization;
    if auth.asset != "usdrise" {
        return Err(ClaimError::Rejected(
            "USDrise withdrawal must use asset usdrise".into(),
        ));
    }
    verify_authorization(auth, &request.pubkey, &request.signature)
        .map_err(|err| ClaimError::Rejected(err.to_string()))?;
    let claimant = adr036::sunrise_address(&auth.claimant)?;
    if !auth.destination.starts_with("0x") {
        return Err(ClaimError::Rejected(
            "USDrise withdrawal destination must be an EVM address".into(),
        ));
    }
    if !state.nonces.insert((claimant, auth.nonce)) {
        return Err(ClaimError::Rejected(format!(
            "nonce {} was already used",
            auth.nonce
        )));
    }
    let balance = state
        .edge_balance
        .entry((claimant, "usdrise".into()))
        .or_insert(0);
    if auth.amount == 0 || auth.amount > *balance {
        state.nonces.remove(&(claimant, auth.nonce));
        return Err(ClaimError::Rejected(format!(
            "amount {} exceeds credited USDrise {}",
            auth.amount, *balance
        )));
    }
    *balance -= auth.amount;
    Ok(PayoutOrder {
        asset: "usdrise".into(),
        chain_id: "1".into(),
        denom: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
        destination: auth.destination.clone(),
        amount: auth.amount,
        claimant: auth.claimant.clone(),
        nonce: auth.nonce,
        ledger_sha256: auth.ledger_sha256.clone(),
    })
}

#[derive(Clone, Copy)]
struct PayRoute {
    chain_id: &'static str,
    denom: &'static str,
    bech32_prefix: Option<&'static str>,
}

fn payout_route(asset: &str) -> Option<PayRoute> {
    Some(match asset {
        "ibc/C4CFF46FD6DE35CA4CF4CE031E643C8FDC9BA4B99AE598E9B0ED98FE3A2319F9" => PayRoute {
            chain_id: "cosmoshub-4",
            denom: "uatom",
            bech32_prefix: Some("cosmos"),
        },
        "ibc/47BD209179859CDE4A2806763D7189B6E6FE13A17880FE2B42DE1E6C1E329E23" => PayRoute {
            chain_id: "osmosis-1",
            denom: "uosmo",
            bech32_prefix: Some("osmo"),
        },
        "ibc/8E27BA2D5493AF5636760E354E46004562C46AB7EC0CC4C1CA14E9E20E2545B5" => PayRoute {
            chain_id: "noble-1",
            denom: "uusdc",
            bech32_prefix: Some("noble"),
        },
        "ibc/AAF322A78A0E34B76CDA05BA9AE96DC1521F9E103EC576AB9931116B2AB8C26B" => PayRoute {
            chain_id: "noble-1",
            denom: "ausdy",
            bech32_prefix: Some("noble"),
        },
        "ibc/694A6B26A43A2FBECCFFEAC022DEACB39578E54207FDD32005CD976B57B98004" => PayRoute {
            chain_id: "1",
            denom: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            bech32_prefix: None,
        },
        "ibc/0E293A7622DC9A6439DB60E6D234B5AF446962E27CA3AB44D0590603DFF6968E" => PayRoute {
            chain_id: "1",
            denom: "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
            bech32_prefix: None,
        },
        "ibc/D4FF12988C31AD8E3D2555621F95C7EB2B6FBAAD2F9487FB11A2A8BBB004B4B3" => PayRoute {
            chain_id: "1",
            denom: "0xdac17f958d2ee523a2206206994597c13d831ec7",
            bech32_prefix: None,
        },
        "ibc/361B5A15BD029B92BC57500263F926EA0D59901A48A35A40F84696EF153C7B1D" => PayRoute {
            chain_id: "1",
            denom: "0xa00C59fF5a080D2b954d0c75e46E22a0c371235a",
            bech32_prefix: None,
        },
        _ => return None,
    })
}

fn validate_external_destination(route: PayRoute, destination: &str) -> Result<(), ClaimError> {
    if route.bech32_prefix.is_none() {
        if destination.starts_with("0x") && destination.len() == 42 {
            return Ok(());
        }
        return Err(ClaimError::Rejected(format!(
            "destination {destination} is not an EVM address"
        )));
    }
    Ok(())
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
