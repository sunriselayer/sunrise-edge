//! Keplr ADR-036 authorization for one RISE claim.
//!
//! The canonical JSON field order matches the Go `claim` package:
//! amount, asset, claimant, destination, ledger_sha256, nonce.
//! The sign document is the amino JSON Keplr produces for `signArbitrary`,
//! with an empty chain id and zero account number and sequence.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use digest010::Digest as RipemdDigest;
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use ripemd::Ripemd160;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ClaimError;

/// The message a claimant signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Ledger file sha256, hex.
    pub ledger_sha256: String,
    /// Bech32 sunrise address.
    pub claimant: String,
    /// Must be `rise` for this crate.
    pub asset: String,
    /// Base units, decimal.
    pub amount: u64,
    /// 32-byte Edge address, hex.
    pub destination: String,
    /// One-time claim number.
    pub nonce: u64,
}

#[derive(Serialize)]
struct Canonical<'a> {
    amount: String,
    asset: &'a str,
    claimant: &'a str,
    destination: &'a str,
    ledger_sha256: &'a str,
    nonce: u64,
}

/// Why a signature was rejected.
#[derive(Debug, PartialEq, Eq)]
pub struct SignatureError(pub String);

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SignatureError {}

/// Bytes that are base64-encoded into the ADR-036 sign document.
pub fn canonical_bytes(auth: &Authorization) -> Result<Vec<u8>, SignatureError> {
    let value = Canonical {
        amount: auth.amount.to_string(),
        asset: &auth.asset,
        claimant: &auth.claimant,
        destination: &auth.destination,
        ledger_sha256: &auth.ledger_sha256,
        nonce: auth.nonce,
    };
    serde_json::to_vec(&value).map_err(|err| SignatureError(err.to_string()))
}

/// Amino sign document bytes. The verifier hashes these with sha256.
pub fn sign_doc_bytes(canonical: &[u8], claimant: &str) -> String {
    let data = base64_std(canonical);
    format!(
        r#"{{"account_number":"0","chain_id":"","fee":{{"amount":[],"gas":"0"}},"memo":"","msgs":[{{"type":"sign/MsgSignData","value":{{"data":"{data}","signer":"{claimant}"}}}}],"sequence":"0"}}"#
    )
}

/// Checks the pubkey, the sunrise address, and the signature.
pub fn verify_authorization(
    auth: &Authorization,
    pubkey: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let address = cosmos_address(pubkey)?;
    let claimant =
        sunrise_address(&auth.claimant).map_err(|err| SignatureError(err.to_string()))?;
    if address != claimant {
        return Err(SignatureError(format!(
            "pubkey address does not match claimant {}",
            auth.claimant
        )));
    }
    let canonical = canonical_bytes(auth)?;
    let sign_doc = sign_doc_bytes(&canonical, &auth.claimant);
    let key = VerifyingKey::from_sec1_bytes(pubkey)
        .map_err(|err| SignatureError(format!("pubkey: {err}")))?;
    let sig = Signature::from_slice(signature)
        .map_err(|err| SignatureError(format!("signature: {err}")))?;
    key.verify(sign_doc.as_bytes(), &sig)
        .map_err(|_| SignatureError("signature does not match the pubkey".into()))
}

pub(crate) fn sunrise_address(value: &str) -> Result<[u8; 20], ClaimError> {
    let checked = CheckedHrpstring::new::<Bech32>(value)
        .map_err(|err| ClaimError::Rejected(format!("address {value}: {err}")))?;
    if checked.hrp().to_string() != "sunrise" {
        return Err(ClaimError::Rejected(format!(
            "address {value} is not a sunrise bech32 address"
        )));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| ClaimError::Rejected(format!("address {value} is not 20 bytes")))?;
    Ok(address)
}

fn cosmos_address(pubkey: &[u8]) -> Result<[u8; 20], SignatureError> {
    if pubkey.len() != 33 {
        return Err(SignatureError(format!("pubkey length {}", pubkey.len())));
    }
    let sha = Sha256::digest(pubkey);
    let ripe = <Ripemd160 as RipemdDigest>::digest(sha);
    let mut address = [0u8; 20];
    address.copy_from_slice(&ripe);
    Ok(address)
}

fn base64_std(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    if i < input.len() {
        let remain = input.len() - i;
        let mut n = (input[i] as u32) << 16;
        if remain == 2 {
            n |= (input[i + 1] as u32) << 8;
        }
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if remain == 2 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

/// Encodes a 20-byte address as `sunrise1...` for tests.
pub fn encode_sunrise(address: &[u8; 20]) -> String {
    let hrp = Hrp::parse("sunrise").expect("sunrise is a valid hrp");
    bech32::encode::<Bech32>(hrp, address).expect("address encodes")
}
