//! `runtime::BlobStore` over `host::DoBlobStore`, with local digest
//! recomputation.
//!
//! Per DR-0152, a storage adapter selects no hash algorithm of its own;
//! this module trusts only the algorithm already carried on the caller
//! `Digest32`. It refuses to store or believe a `(digest, bytes)` pair
//! whose bytes do not actually hash to that digest under that algorithm,
//! and refuses an algorithm this build has not implemented, rather than
//! storing or returning unverified content.

use protocol_types::{Digest32, HashAlgorithmId};
use runtime::{BlobStore, RuntimeError};
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsCast;

use crate::host::DoBlobStore;

fn recompute_digest(algorithm: HashAlgorithmId, bytes: &[u8]) -> Result<[u8; 32], RuntimeError> {
    match algorithm {
        HashAlgorithmId::Sha2_256 => Ok(Sha256::digest(bytes).into()),
        // Every other algorithm identifier is either unimplemented in this
        // build or, per `config::decode_trusted_adapter_config`, never
        // admitted by this adapter own genesis hash-suite pin in the
        // first place; either way this fails closed instead of trusting
        // an unverified digest.
        _ => Err(RuntimeError::DurableStoreUnavailable),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn js_value_to_bytes(value: &wasm_bindgen::JsValue) -> Option<Vec<u8>> {
    if let Some(array) = value.dyn_ref::<js_sys::Uint8Array>() {
        return Some(array.to_vec());
    }
    if let Some(buffer) = value.dyn_ref::<js_sys::ArrayBuffer>() {
        return Some(js_sys::Uint8Array::new(buffer).to_vec());
    }
    None
}

/// `BlobStore` over one Durable Object own `DoBlobStore` bridge.
pub struct DoBlobStoreAdapter {
    blobs: DoBlobStore,
}

impl DoBlobStoreAdapter {
    #[must_use]
    pub const fn new(blobs: DoBlobStore) -> Self {
        Self { blobs }
    }
}

impl BlobStore for DoBlobStoreAdapter {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let recomputed = recompute_digest(digest.algorithm(), &bytes)?;
        if recomputed != digest.bytes() {
            return Err(RuntimeError::BlobDigestConflict { digest });
        }
        let digest_hex = hex_encode(&digest.bytes());
        match self.blobs.put_if_absent(&digest_hex, &bytes) {
            Ok(_newly_stored) => Ok(()),
            // The host bridge throws on an exact digest/content conflict
            // (see `host::DoBlobStore::put_if_absent`); any other host
            // failure reaches the same branch, since neither case is a
            // successful store.
            Err(_) => Err(RuntimeError::BlobDigestConflict { digest }),
        }
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        let digest_hex = hex_encode(&digest.bytes());
        let value = self
            .blobs
            .get_blob(&digest_hex)
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }
        let bytes = js_value_to_bytes(&value).ok_or(RuntimeError::DurableStoreUnavailable)?;
        let recomputed = recompute_digest(digest.algorithm(), &bytes)?;
        if recomputed != digest.bytes() {
            return Err(RuntimeError::InvalidPersistedState);
        }
        Ok(Some(bytes))
    }
}
