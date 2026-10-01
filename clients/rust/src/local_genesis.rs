//! Shared local genesis-file and committee verification, not transport policy.
//!
//! Pins come from local composition. A verified genesis is not a peer-selected
//! live serving context, and no TLS or endpoint identity is inferred here.

use std::{fs::File, io::Read, path::Path};

use crypto::SignatureVerifier;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::MAX_GENESIS_MANIFEST_BYTES;
use node_core::fast_path::records::FastPathValidatorSetRecord;
use node_core::genesis::{
    GenesisError, GenesisManifest, decode_genesis_manifest, genesis_manifest_commitment,
    genesis_manifest_signing_frame,
};
use protocol_types::{Digest32, SignatureSchemeId};
use validator_set::{ValidatorInfo, ValidatorSet};

/// Internal failures mapped by each public client to its existing trust error.
#[derive(Debug)]
pub(crate) enum LocalGenesisError {
    Io(std::io::Error),
    Decode(GenesisError),
    CommitmentMismatch,
    ContextMismatch,
    InvalidSignature,
}

/// The same file's authenticated manifest and locally checked commitment.
pub(crate) struct PinnedGenesis {
    pub(crate) manifest: GenesisManifest,
    pub(crate) digest: Digest32,
}

/// Preserve the original bounded read, including following file symlinks.
/// Reading bytes does not itself establish a trusted genesis pin.
pub(crate) fn read_bounded(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let mut file: File = File::open(path)?;
    let cap: u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    let mut buffer: Vec<u8> = Vec::new();
    file.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)?;
    if buffer.len() > maximum {
        return Err(std::io::Error::other(
            "genesis manifest exceeds the maximum accepted size",
        ));
    }
    Ok(buffer)
}

/// Read once, then check canonical bytes, digest, context and signature in the
/// same order used by both public loaders. Profile-specific admission and
/// policy construction remain the owning client's next steps.
#[allow(clippy::result_large_err)]
pub(crate) fn load_pinned_genesis(
    manifest_path: &Path,
    resolver: &HashSuiteResolver,
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
) -> Result<PinnedGenesis, LocalGenesisError> {
    let bytes: Vec<u8> =
        read_bounded(manifest_path, MAX_GENESIS_MANIFEST_BYTES).map_err(LocalGenesisError::Io)?;
    let manifest: GenesisManifest =
        decode_genesis_manifest(&bytes).map_err(LocalGenesisError::Decode)?;
    let digest: Digest32 =
        genesis_manifest_commitment(resolver, &manifest).map_err(LocalGenesisError::Decode)?;
    if digest.bytes() != expected_digest {
        return Err(LocalGenesisError::CommitmentMismatch);
    }
    if manifest.context() != expected_context {
        return Err(LocalGenesisError::ContextMismatch);
    }
    let verifier: crypto::Ed25519Verifier =
        crypto::Ed25519Verifier::from_verifying_key_bytes(&manifest.genesis_authority)
            .map_err(|_| LocalGenesisError::InvalidSignature)?;
    let frame: Vec<u8> =
        genesis_manifest_signing_frame(&manifest).map_err(LocalGenesisError::Decode)?;
    let valid: bool = verifier
        .verify_framed(&frame, &manifest.signature)
        .map_err(|_| LocalGenesisError::InvalidSignature)?;
    if !valid {
        return Err(LocalGenesisError::InvalidSignature);
    }
    Ok(PinnedGenesis { manifest, digest })
}

/// Convert the already-authenticated record without changing each caller's
/// existing unsupported-scheme diagnostic or validation order.
pub(crate) fn validator_set_from_record(
    record: &FastPathValidatorSetRecord,
    expected_context: &PublicationContext,
    unsupported_scheme: &'static str,
) -> Result<ValidatorSet, String> {
    if &record.context != expected_context {
        return Err("validator set record context mismatch".to_string());
    }
    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(record.validators.len());
    for validator in &record.validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(unsupported_scheme.to_string());
        }
        info.push(ValidatorInfo {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: validator.signature_scheme,
            public_key: validator.public_key.clone(),
        });
    }
    ValidatorSet::new(expected_context.epoch(), info).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
