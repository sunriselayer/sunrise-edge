//! Bounded, non-authorizing publication review and presentation.
//!
//! [DR-0214](../../../docs/architecture/decisions/0214-protected-custody-and-review-boundary.md)
//! defers an additional presentation layer until a concrete, bounded,
//! non-authorizing review consumer exists. This module is that consumer:
//! given the same immutable [`PreparedPublication`] that is signed, it
//! independently recomputes the exact canonical artifact bytes, commitment,
//! semantics and submission signing frame using only the existing
//! publication codecs, and exposes a bounded, display-safe snapshot of every
//! field [DR-0214](../../../docs/architecture/decisions/0214-protected-custody-and-review-boundary.md)
//! lists as required publication review input. See
//! [DR-0237](../../../docs/architecture/decisions/0237-bounded-publication-review-presentation.md)
//! and the [publication review contract](../../../docs/architecture/publication-review.md).
//!
//! # Explicit non-claims
//!
//! This is NOT a signer, a general review/approval endpoint, or a node/network
//! consumer. Building a [`PublicationReview`] loads no signing seed, contacts
//! no signer or node, and submits nothing. A successful [`PublicationReview`]
//! proves bounded structural, commitment and semantics consistency between
//! the retained artifact and the exact bytes that will be signed; it is not
//! code-safety or business approval, and it does not replace
//! [`PreparedPublication::finalize`] authentication.

use abi::package_types::PackageOrigin;
use execution::local_execution::{
    general_execution_semantics, generic_object_result_semantics, local_execution_semantics,
};
use execution::publication::{
    CodeArtifact, PublicationError, UnverifiedDependencyRef, artifact_commitment,
    decode_code_artifact, encode_code_artifact, publication_submission_signing_frame,
};
use execution::{
    CONTRACT_WASM_ADMISSION_PROFILE_VERSION, GENERAL_CONTRACT_WASM_PROFILE_VERSION,
    GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION, MAX_CONTRACT_ENTRYPOINT_NAME_BYTES,
    MAX_CONTRACT_ENTRYPOINTS, TYPED_CONTRACT_WASM_PROFILE_VERSION,
};
use node_core::publication::{PublicationAdmissionError, local_publication_profile_semantics};

use crate::Address;
use crate::publication_client::PreparedPublication;

/// Maximum printable bytes accepted for one displayed chain identifier.
pub const MAX_REVIEW_CHAIN_ID_DISPLAY_BYTES: usize = 128;
/// Maximum exports presented, matching the existing artifact export bound.
pub const MAX_REVIEW_EXPORTS: usize = MAX_CONTRACT_ENTRYPOINTS;
/// Maximum bytes accepted for one displayed export name.
pub const MAX_REVIEW_EXPORT_DISPLAY_BYTES: usize = MAX_CONTRACT_ENTRYPOINT_NAME_BYTES;
/// Maximum dependencies presented, matching the existing artifact dependency bound.
pub const MAX_REVIEW_DEPENDENCIES: usize = execution::publication::MAX_DEPENDENCIES;
/// Maximum total material fields a review snapshot may present, bounding
/// aggregate display work independent of any single field's own bound.
pub const MAX_REVIEW_TOTAL_FIELDS: usize = 10 + MAX_REVIEW_EXPORTS + MAX_REVIEW_DEPENDENCIES;
/// Maximum total bytes across every rendered display string in one review
/// snapshot, bounding aggregate presentation work independent of any single
/// field's own bound.
pub const MAX_REVIEW_DISPLAY_BYTES: usize = 131_072;
/// Maximum bytes the independent artifact re-encode/re-decode round trip may
/// use while recomputing the preimage-to-frame correspondence, matching the
/// existing closed artifact ceiling.
pub const MAX_REVIEW_WORK_BYTES: usize = execution::publication::MAX_PUBLICATION_BYTES;

/// Fail-closed errors for bounded, non-authorizing publication review.
///
/// Every variant rejects the input outright; none silently truncates, drops,
/// or substitutes a field and none performs any signing, custody, or network
/// action.
#[derive(Debug)]
pub enum PublicationReviewError {
    /// Independent canonical artifact/commitment recomputation failed.
    Artifact(PublicationError),
    /// Independent semantics recomputation failed or used an unknown profile.
    Semantics(PublicationAdmissionError),
    /// The retained semantics digest differs from the independently
    /// recomputed profile semantics; the profile claims meaning the retained
    /// artifact's own bytes do not support.
    SemanticsMismatch,
    /// Re-decoding the independently re-encoded artifact produced different
    /// structural content; the retained artifact does not round-trip exactly
    /// through the canonical codec it claims to use.
    ArtifactRoundTripMismatch,
    /// The independently recomputed artifact commitment differs from the
    /// one [`PreparedPublication`] retained.
    DigestMismatch,
    /// The independently recomputed submission signing frame differs from
    /// the one [`PreparedPublication`] retained; review and signing would
    /// not consume the same bytes.
    FrameMismatch,
    /// A field required for review contains bytes that cannot be safely
    /// displayed (non-printable, control, or otherwise unbounded-risk bytes).
    UndisplayableField(&'static str),
    /// A field, collection, or the aggregate snapshot exceeded its explicit
    /// bound before or during presentation.
    Limit {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// An artifact profile is structurally valid but has no recognized
    /// review semantics mapping; review refuses rather than guessing.
    UnknownWasmProfile(u32),
}

impl std::fmt::Display for PublicationReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Artifact(error) => write!(f, "publication review artifact error: {error}"),
            Self::Semantics(error) => write!(f, "publication review semantics error: {error}"),
            Self::SemanticsMismatch => {
                f.write_str("publication review: retained semantics do not match the profile")
            }
            Self::ArtifactRoundTripMismatch => {
                f.write_str("publication review: artifact does not round-trip through its codec")
            }
            Self::DigestMismatch => {
                f.write_str("publication review: recomputed artifact commitment mismatch")
            }
            Self::FrameMismatch => {
                f.write_str("publication review: recomputed signing frame mismatch")
            }
            Self::UndisplayableField(field) => {
                write!(f, "publication review: field '{field}' is not displayable")
            }
            Self::Limit {
                field,
                actual,
                maximum,
            } => write!(
                f,
                "publication review: field '{field}' length/count {actual} exceeds {maximum}"
            ),
            Self::UnknownWasmProfile(profile) => {
                write!(f, "publication review: unknown wasm profile {profile}")
            }
        }
    }
}

impl std::error::Error for PublicationReviewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Artifact(error) => Some(error),
            Self::Semantics(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PublicationError> for PublicationReviewError {
    fn from(error: PublicationError) -> Self {
        Self::Artifact(error)
    }
}

impl From<PublicationAdmissionError> for PublicationReviewError {
    fn from(error: PublicationAdmissionError) -> Self {
        Self::Semantics(error)
    }
}

fn bound(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), PublicationReviewError> {
    if actual > maximum {
        return Err(PublicationReviewError::Limit {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

/// Accepts only printable, non-control ASCII bytes and bounds the byte length
/// before copying. Rejecting rather than stripping or truncating keeps this
/// function from silently hiding bytes a terminal would otherwise interpret
/// as control sequences (including ANSI/VT escape injection).
fn display_safe(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<String, PublicationReviewError> {
    bound(field, value.len(), maximum)?;
    if value.bytes().any(|byte| !(0x20..=0x7E).contains(&byte)) {
        return Err(PublicationReviewError::UndisplayableField(field));
    }
    Ok(value.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bounded, display-safe presentation of one unverified dependency reference.
///
/// Mirrors exactly the fields [`UnverifiedDependencyRef`] retains; it adds no
/// provenance, existence, or authentication claim of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyReview {
    chain_id: String,
    publisher_hex: String,
    seed_hex: String,
    revision: u64,
    protocol_version: u32,
    epoch: u64,
    artifact_digest_hex: String,
}

impl DependencyReview {
    fn build(dependency: &UnverifiedDependencyRef) -> Result<Self, PublicationReviewError> {
        let origin: &PackageOrigin = dependency.origin();
        Ok(Self {
            chain_id: display_safe(
                "dependency.chain_id",
                origin.chain_id().as_str(),
                MAX_REVIEW_CHAIN_ID_DISPLAY_BYTES,
            )?,
            publisher_hex: hex(origin.publisher()),
            seed_hex: hex(origin.seed()),
            revision: dependency.revision(),
            protocol_version: dependency.context().protocol_version().get(),
            epoch: dependency.context().epoch().get(),
            artifact_digest_hex: dependency.artifact_digest().to_string(),
        })
    }

    /// Dependency's declared chain identifier (printable, display-safe).
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Dependency's declared publisher reference, as lowercase hex.
    #[must_use]
    pub fn publisher_hex(&self) -> &str {
        &self.publisher_hex
    }

    /// Dependency's declared creation seed, as lowercase hex.
    #[must_use]
    pub fn seed_hex(&self) -> &str {
        &self.seed_hex
    }

    /// Dependency's declared revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Dependency's declared protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Dependency's declared epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Dependency's declared artifact commitment digest (algorithm-prefixed hex).
    #[must_use]
    pub fn artifact_digest_hex(&self) -> &str {
        &self.artifact_digest_hex
    }
}

/// Immutable, display-safe, non-authorizing publication review snapshot.
///
/// Built only from a [`PreparedPublication`]'s own retained inputs. Building
/// one performs no signing, custody, or network action and accepts no
/// replacement content after construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationReview {
    publisher_hex: String,
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    revision: u64,
    wasm_profile: u32,
    wasm_profile_name: &'static str,
    wasm_bytes_len: usize,
    unverified_abi_bytes_len: usize,
    semantics_hex: String,
    artifact_digest_hex: String,
    exports: Vec<String>,
    dependencies: Vec<DependencyReview>,
    nonce: u64,
    request_id_hex: String,
}

fn wasm_profile_name(profile: u32) -> Result<&'static str, PublicationReviewError> {
    match profile {
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION => Ok("publication-only"),
        TYPED_CONTRACT_WASM_PROFILE_VERSION => Ok("typed-host-execution"),
        GENERAL_CONTRACT_WASM_PROFILE_VERSION => Ok("general-execution"),
        GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION => Ok("generic-object-result"),
        other => Err(PublicationReviewError::UnknownWasmProfile(other)),
    }
}

/// Independently recomputes the exact profile semantics commitment that
/// [`CodeArtifact::wasm_profile`] claims, under the retained trusted
/// resolver/context. An unrecognized profile fails closed rather than
/// guessing a semantics mapping.
fn recompute_profile_semantics(
    prepared: &PreparedPublication,
) -> Result<protocol_types::Digest32, PublicationReviewError> {
    let profile: u32 = prepared.artifact().wasm_profile();
    let context = prepared.context();
    match profile {
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION => Ok(local_publication_profile_semantics(
            prepared.resolver(),
            context,
        )?),
        TYPED_CONTRACT_WASM_PROFILE_VERSION => {
            Ok(local_execution_semantics(prepared.resolver(), context)?)
        }
        GENERAL_CONTRACT_WASM_PROFILE_VERSION => {
            Ok(general_execution_semantics(prepared.resolver(), context)?)
        }
        GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION => Ok(generic_object_result_semantics(
            prepared.resolver(),
            context,
        )?),
        other => Err(PublicationReviewError::UnknownWasmProfile(other)),
    }
}

impl PublicationReview {
    /// Builds a bounded, display-safe, non-authorizing review snapshot from a
    /// [`PreparedPublication`]'s own retained inputs.
    ///
    /// Independently re-derives, from the retained [`CodeArtifact`] alone and
    /// using only the existing canonical codecs:
    ///
    /// 1. A fresh encode/decode round trip of the artifact, rejecting any
    ///    content that does not reproduce exactly (unknown/trailing fields,
    ///    non-canonical order, or any other decode failure refuses review).
    /// 2. The artifact commitment digest, compared against the one
    ///    [`PreparedPublication`] retained.
    /// 3. The profile semantics commitment, compared against the retained
    ///    semantics digest.
    /// 4. The exact submission signing frame, compared byte-for-byte against
    ///    [`PreparedPublication::signable_frame`].
    ///
    /// Any mismatch, any undisplayable field, or exceeding an explicit bound
    /// refuses with a typed error and builds no partial/placeholder review.
    pub fn build(prepared: &PreparedPublication) -> Result<Self, PublicationReviewError> {
        let artifact: &CodeArtifact = prepared.artifact();

        let reencoded: Vec<u8> = encode_code_artifact(artifact)?;
        bound("artifact.reencoded", reencoded.len(), MAX_REVIEW_WORK_BYTES)?;
        let redecoded: CodeArtifact = decode_code_artifact(&reencoded)?;
        if &redecoded != artifact {
            return Err(PublicationReviewError::ArtifactRoundTripMismatch);
        }

        let recomputed_digest =
            artifact_commitment(prepared.resolver(), prepared.context(), artifact)?;
        if &recomputed_digest != prepared.artifact_digest() {
            return Err(PublicationReviewError::DigestMismatch);
        }

        let recomputed_semantics = recompute_profile_semantics(prepared)?;
        if &recomputed_semantics != prepared.semantics() {
            return Err(PublicationReviewError::SemanticsMismatch);
        }

        let recomputed_frame: Vec<u8> = publication_submission_signing_frame(
            prepared.resolver(),
            prepared.context(),
            artifact,
            prepared.nonce(),
            *prepared.request_id().as_bytes(),
        )?;
        if recomputed_frame.as_slice() != prepared.signable_frame() {
            return Err(PublicationReviewError::FrameMismatch);
        }

        let exports_source: &[String] = artifact.exports();
        bound("exports", exports_source.len(), MAX_REVIEW_EXPORTS)?;
        let mut exports: Vec<String> = Vec::with_capacity(exports_source.len());
        for export in exports_source {
            exports.push(display_safe(
                "export",
                export,
                MAX_REVIEW_EXPORT_DISPLAY_BYTES,
            )?);
        }

        let dependencies_source: &[UnverifiedDependencyRef] = artifact.unverified_dependencies();
        bound(
            "dependencies",
            dependencies_source.len(),
            MAX_REVIEW_DEPENDENCIES,
        )?;
        let mut dependencies: Vec<DependencyReview> = Vec::with_capacity(dependencies_source.len());
        for dependency in dependencies_source {
            dependencies.push(DependencyReview::build(dependency)?);
        }

        let chain_id: String = display_safe(
            "context.chain_id",
            artifact.context().chain_id().as_str(),
            MAX_REVIEW_CHAIN_ID_DISPLAY_BYTES,
        )?;

        let total_fields: usize = 10usize
            .checked_add(exports.len())
            .and_then(|value| value.checked_add(dependencies.len()))
            .ok_or(PublicationReviewError::Limit {
                field: "total_fields",
                actual: usize::MAX,
                maximum: MAX_REVIEW_TOTAL_FIELDS,
            })?;
        bound("total_fields", total_fields, MAX_REVIEW_TOTAL_FIELDS)?;

        let mut total_display_bytes: usize = chain_id.len();
        for export in &exports {
            total_display_bytes = total_display_bytes
                .checked_add(export.len())
                .ok_or(PublicationReviewError::Limit {
                    field: "total_display_bytes",
                    actual: usize::MAX,
                    maximum: MAX_REVIEW_DISPLAY_BYTES,
                })?;
        }
        for dependency in &dependencies {
            total_display_bytes = total_display_bytes
                .checked_add(dependency.chain_id.len())
                .ok_or(PublicationReviewError::Limit {
                    field: "total_display_bytes",
                    actual: usize::MAX,
                    maximum: MAX_REVIEW_DISPLAY_BYTES,
                })?;
        }
        bound(
            "total_display_bytes",
            total_display_bytes,
            MAX_REVIEW_DISPLAY_BYTES,
        )?;

        let publisher: Address = prepared.publisher();
        Ok(Self {
            publisher_hex: publisher.to_string(),
            chain_id,
            protocol_version: artifact.context().protocol_version().get(),
            epoch: artifact.context().epoch().get(),
            revision: artifact.revision(),
            wasm_profile: artifact.wasm_profile(),
            wasm_profile_name: wasm_profile_name(artifact.wasm_profile())?,
            wasm_bytes_len: artifact.wasm().len(),
            unverified_abi_bytes_len: artifact.unverified_abi().len(),
            semantics_hex: prepared.semantics().to_string(),
            artifact_digest_hex: prepared.artifact_digest().to_string(),
            exports,
            dependencies,
            nonce: prepared.nonce(),
            request_id_hex: prepared.request_id().to_string(),
        })
    }

    /// Configured publisher identity, as lowercase hex.
    #[must_use]
    pub fn publisher_hex(&self) -> &str {
        &self.publisher_hex
    }

    /// Publication context chain identifier (printable, display-safe).
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Publication context protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Publication context epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Artifact revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Numeric structural WASM admission profile.
    #[must_use]
    pub const fn wasm_profile(&self) -> u32 {
        self.wasm_profile
    }

    /// Human-readable name of the recognized structural WASM admission profile.
    #[must_use]
    pub const fn wasm_profile_name(&self) -> &'static str {
        self.wasm_profile_name
    }

    /// Exact WASM byte length. Raw WASM bytes are deliberately not rendered
    /// as display text; only their length is bounded review metadata here.
    #[must_use]
    pub const fn wasm_bytes_len(&self) -> usize {
        self.wasm_bytes_len
    }

    /// Exact unverified ABI declaration byte length. Raw ABI bytes are
    /// deliberately not rendered as display text; only their length is
    /// bounded review metadata here.
    #[must_use]
    pub const fn unverified_abi_bytes_len(&self) -> usize {
        self.unverified_abi_bytes_len
    }

    /// Independently recomputed and matched profile semantics commitment
    /// (algorithm-prefixed hex).
    #[must_use]
    pub fn semantics_hex(&self) -> &str {
        &self.semantics_hex
    }

    /// Independently recomputed and matched artifact commitment digest
    /// (algorithm-prefixed hex).
    #[must_use]
    pub fn artifact_digest_hex(&self) -> &str {
        &self.artifact_digest_hex
    }

    /// Declared exports (printable, display-safe, canonically ordered).
    #[must_use]
    pub fn exports(&self) -> &[String] {
        &self.exports
    }

    /// Declared unverified dependency references.
    #[must_use]
    pub fn dependencies(&self) -> &[DependencyReview] {
        &self.dependencies
    }

    /// Signed publisher nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Signed submission request identity, as lowercase hex.
    #[must_use]
    pub fn request_id_hex(&self) -> &str {
        &self.request_id_hex
    }
}
