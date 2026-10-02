//! The one immutable verified genesis root (DR-0182).
//!
//! See `docs/architecture/genesis-trust.md` for the complete rationale.
//! `VerifiedGenesisRoot` centralizes locally pinned genesis authentication:
//! one public constructor authenticates bounded canonical bytes against a
//! trusted local pin/context and stores the exact resolver, authenticated
//! admission profile and original committee together, so every consumer in
//! this crate shares one verified value instead of independently
//! reconstructing and cross-checking the same relationship.
//!
//! This is original-genesis historical evidence only. It never satisfies a
//! live epoch pin, Freeze, successor selection or serving activation; it
//! authenticates the manifest and original committee, not that publication,
//! initialization, custody or installed objects are valid or present.

use core::fmt;

use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use protocol_types::Digest32;
use validator_set::ValidatorSet;

use crate::admission_profile::VerifiedAdmissionProfile;

use super::{
    GenesisCommitteeError, GenesisError, GenesisManifest, convert_genesis_committee,
    decode_genesis_manifest, genesis_manifest_commitment, verify_manifest_authority,
};

/// Errors from [`VerifiedGenesisRoot::verify_bytes`].
///
/// Classified so callers (and SDK diagnostics) can distinguish manifest
/// decoding, commitment, context, authority/signature and committee defects
/// without matching message strings. Multidefect tests pin the precedence
/// among these: decode, then commitment, then context, then authority, then
/// committee -- exactly the order [`VerifiedGenesisRoot::verify_bytes`]
/// checks them.
#[derive(Debug)]
pub enum GenesisRootError {
    /// Bounded canonical manifest decoding (including round-trip equality)
    /// failed.
    Decode(GenesisError),
    /// The manifest's own commitment digest does not equal the local pin.
    CommitmentMismatch,
    /// The manifest's publication context, or the supplied resolver's own
    /// chain/protocol, does not equal the expected local context.
    ContextMismatch,
    /// The manifest's authority is zero, noncanonical, or its signature over
    /// its own profile-specific signed frame does not verify.
    InvalidSignature,
    /// The manifest's signed validator-set record is not a valid original
    /// genesis committee.
    InvalidCommittee(GenesisCommitteeError),
}

impl fmt::Display for GenesisRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "genesis root manifest decoding failed: {error}"),
            Self::CommitmentMismatch => {
                write!(
                    f,
                    "genesis root manifest commitment does not match the local pin"
                )
            }
            Self::ContextMismatch => write!(f, "genesis root context does not match"),
            Self::InvalidSignature => {
                write!(f, "genesis root authority or signature is invalid")
            }
            Self::InvalidCommittee(error) => {
                write!(f, "genesis root committee is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for GenesisRootError {}

/// One immutable verified genesis root: a locally authenticated signed
/// genesis manifest, the exact resolver it was checked under, its
/// authenticated admission profile and its original immutable committee.
///
/// Private immutable fields, closed `verify_bytes` construction only. No
/// `Default`, decoding/serde implementation or unchecked constructor exists,
/// and there is no public mutable field: cloning this value as historical
/// evidence confers no writer, reservation, consensus-vote or activation
/// authority, and its resolver is part of the value, not a separately
/// caller-selected dependency.
///
/// A caller outside this module can neither build a literal nor mutate an
/// existing value's fields:
///
/// ```compile_fail
/// fn build(manifest: node_core::genesis::GenesisManifest) {
///     let _root = node_core::genesis::VerifiedGenesisRoot {
///         manifest,
///     };
/// }
/// ```
///
/// ```compile_fail
/// fn replace_resolver(
///     root: &mut node_core::genesis::VerifiedGenesisRoot,
///     resolver: hashing::HashSuiteResolver,
/// ) {
///     root.resolver = resolver;
/// }
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedGenesisRoot {
    manifest: GenesisManifest,
    digest: Digest32,
    resolver: HashSuiteResolver,
    admission_profile: VerifiedAdmissionProfile,
    genesis_committee: ValidatorSet,
}

impl VerifiedGenesisRoot {
    /// Authenticates bounded canonical genesis manifest bytes against a
    /// trusted local digest pin and context.
    ///
    /// `resolver`, `expected_digest` and `expected_context` must be trusted
    /// local composition: a peer-supplied pin or context does not become
    /// trust merely by passing this function. Checks, in order:
    ///
    /// 1. Bounded canonical manifest decoding.
    /// 2. Manifest commitment against the raw local digest pin.
    /// 3. Manifest context against the expected context.
    /// 4. Resolver chain/protocol against that context.
    /// 5. Canonical round-trip equality (enforced by strict decoding itself).
    /// 6. Nonzero canonical prime-order Ed25519 authority and the
    ///    profile-specific signed frame.
    /// 7. Original committee context, Ed25519 schemes, capacity and set
    ///    validity.
    pub fn verify_bytes(
        resolver: &HashSuiteResolver,
        bytes: &[u8],
        expected_digest: [u8; 32],
        expected_context: &PublicationContext,
    ) -> Result<Self, GenesisRootError> {
        // 1. Bounded canonical manifest decoding (this also enforces exact
        // canonical round-trip equality against `bytes`, satisfying step 5).
        let manifest: GenesisManifest =
            decode_genesis_manifest(bytes).map_err(GenesisRootError::Decode)?;

        // 2. Manifest commitment against the raw local digest pin.
        let digest: Digest32 =
            genesis_manifest_commitment(resolver, &manifest).map_err(GenesisRootError::Decode)?;
        if digest.bytes() != expected_digest {
            return Err(GenesisRootError::CommitmentMismatch);
        }

        // 3. Manifest context against the expected context.
        if manifest.context() != expected_context {
            return Err(GenesisRootError::ContextMismatch);
        }

        // 4. Resolver chain/protocol against that context.
        if resolver.chain_id() != expected_context.chain_id()
            || resolver.protocol_version() != expected_context.protocol_version()
        {
            return Err(GenesisRootError::ContextMismatch);
        }

        // 6. Nonzero canonical prime-order Ed25519 authority and the
        // profile-specific signed frame.
        verify_manifest_authority(&manifest).map_err(|_| GenesisRootError::InvalidSignature)?;

        // 7. Original committee context, Ed25519 schemes, capacity and set
        // validity.
        let genesis_committee: ValidatorSet =
            convert_genesis_committee(&manifest).map_err(GenesisRootError::InvalidCommittee)?;

        let admission_profile: VerifiedAdmissionProfile =
            VerifiedAdmissionProfile::from_verified_manifest(&manifest, digest);

        Ok(Self {
            manifest,
            digest,
            resolver: resolver.clone(),
            admission_profile,
            genesis_committee,
        })
    }

    /// Returns the exact authenticated signed genesis manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GenesisManifest {
        &self.manifest
    }

    /// Returns the self-describing manifest commitment digest.
    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Returns the original locally pinned genesis context.
    #[must_use]
    pub fn genesis_context(&self) -> &PublicationContext {
        self.manifest.context()
    }

    /// Returns the exact resolver this root was authenticated under. Part of
    /// the value, not a separately caller-selected dependency.
    #[must_use]
    pub const fn genesis_resolver(&self) -> &HashSuiteResolver {
        &self.resolver
    }

    /// Returns the authenticated descriptive admission profile.
    #[must_use]
    pub const fn admission_profile(&self) -> &VerifiedAdmissionProfile {
        &self.admission_profile
    }

    /// Returns the validated original genesis committee.
    #[must_use]
    pub const fn genesis_committee(&self) -> &ValidatorSet {
        &self.genesis_committee
    }
}

#[cfg(test)]
mod tests;
