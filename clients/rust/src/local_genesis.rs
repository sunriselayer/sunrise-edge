//! Shared local genesis-file bounded I/O, not transport policy or trust.
//!
//! Pins come from local composition. A verified genesis is not a peer-selected
//! live serving context, and no TLS or endpoint identity is inferred here.
//! Authentication itself is `node_core::genesis::VerifiedGenesisRoot`'s own
//! production trust model; this module reads bytes once and hands them to it.

use std::{error::Error, fmt, fs::File, io::Read, path::Path};

use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::MAX_GENESIS_MANIFEST_BYTES;
use node_core::genesis::{GenesisRootError, VerifiedGenesisRoot};

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

/// Failures constructing a locally trusted [`VerifiedGenesisRoot`] from a
/// genesis manifest file: either the bounded read itself failed, or the read
/// bytes were classified and rejected by the core verified-root constructor.
#[derive(Debug)]
pub enum GenesisTrustError {
    /// The manifest file could not be read or exceeded
    /// [`node_core::MAX_GENESIS_MANIFEST_BYTES`].
    Io(std::io::Error),
    /// [`VerifiedGenesisRoot::verify_bytes`] classified and rejected the read
    /// bytes.
    Verification(GenesisRootError),
}

impl fmt::Display for GenesisTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read genesis manifest: {error}"),
            Self::Verification(error) => write!(f, "genesis manifest rejected: {error}"),
        }
    }
}

impl Error for GenesisTrustError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Verification(error) => Some(error),
        }
    }
}

/// Reads a genesis manifest file once, bounded by
/// [`node_core::MAX_GENESIS_MANIFEST_BYTES`], and hands the exact bytes to
/// [`VerifiedGenesisRoot::verify_bytes`] -- the sole production authentication
/// path. This function performs no separate authentication of its own.
#[allow(clippy::result_large_err)]
pub fn load_verified_genesis_root(
    manifest_path: &Path,
    resolver: &HashSuiteResolver,
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
) -> Result<VerifiedGenesisRoot, GenesisTrustError> {
    let bytes: Vec<u8> =
        read_bounded(manifest_path, MAX_GENESIS_MANIFEST_BYTES).map_err(GenesisTrustError::Io)?;
    VerifiedGenesisRoot::verify_bytes(resolver, &bytes, expected_digest, expected_context)
        .map_err(GenesisTrustError::Verification)
}

#[cfg(test)]
mod tests;
