//! Bounded, non-authorizing publication review and presentation.
//!
//! [DR-0214](../../../docs/architecture/decisions/0214-protected-custody-and-review-boundary.md)
//! defers an additional presentation layer until a concrete, bounded,
//! non-authorizing review consumer exists. This module is that consumer:
//! given the same immutable [`PreparedPublication`] that is signed, it
//! performs a defensive self-consistency recheck of that already-typed
//! owner's retained canonical bytes, commitment, semantics and submission
//! signing frame using only the existing publication codecs, and exposes a
//! bounded, display-safe snapshot of every field
//! [DR-0214](../../../docs/architecture/decisions/0214-protected-custody-and-review-boundary.md)
//! lists as required publication review input. See
//! [DR-0237](../../../docs/architecture/decisions/0237-bounded-publication-review-presentation.md)
//! and the [publication review contract](../../../docs/architecture/publication-review.md).
//!
//! # Explicit non-claims
//!
//! This is NOT a signer, a general review/approval endpoint, or a node/network
//! consumer. Building a [`PublicationReview`] loads no signing seed, contacts
//! no signer or node, and submits nothing. The round-trip/digest/semantics/
//! frame checks in [`PublicationReview::build`] are a defensive recheck of an
//! already-validated, already-typed `CodeArtifact` value (never raw/untrusted
//! bytes); they cannot detect unknown or trailing wire fields and, given
//! `CodeArtifact`'s own construction and decoding invariants, cannot actually
//! fail for any value reachable through safe Rust. They exist as regression
//! insurance, not as an adversarial decoder or an independent code-provenance
//! proof. A successful [`PublicationReview`] is not code-safety or business
//! approval, and it does not replace [`PreparedPublication::finalize`]
//! authentication.

use abi::package_types::{MAX_PACKAGE_CHAIN_ID_BYTES, PackageOrigin};
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
use hashing::HashingError;
use node_core::publication::{PublicationAdmissionError, local_publication_profile_semantics};
use protocol_types::{Digest32, HashPurpose};

use crate::publication_client::PreparedPublication;
use crate::review_presentation::{DisplayTextError, display_safe as checked_display_text};

/// Number of dependency sub-fields rendered per dependency (chain id,
/// publisher, seed, revision, protocol version, epoch, artifact digest).
const DEPENDENCY_FIELD_COUNT: usize = 7;
/// Number of fixed (non-export, non-dependency) fields [`PublicationReview::build`]
/// renders: publisher, origin chain id, origin seed, context chain id,
/// protocol version, epoch, hash suite id, revision, numeric wasm profile,
/// named wasm profile, wasm byte length, wasm digest, ABI byte length, ABI
/// digest, semantics, artifact digest, export count, dependency count,
/// nonce, request id and the signable frame as hex.
const FIXED_REVIEW_FIELDS: usize = 21;
/// Maximum total rendered fields (fixed, plus one per export, plus
/// [`DEPENDENCY_FIELD_COUNT`] per dependency) one review may present. This
/// mirrors `CodeArtifact`'s own export/dependency ceilings exactly and so
/// cannot be exceeded by any `CodeArtifact` that exists in safe Rust; it is
/// restated here only so the renderer has an explicit bound to check against,
/// not a separate copied limit.
pub const MAX_REVIEW_TOTAL_FIELDS: usize = FIXED_REVIEW_FIELDS
    + MAX_CONTRACT_ENTRYPOINTS
    + execution::publication::MAX_DEPENDENCIES * DEPENDENCY_FIELD_COUNT;
/// Maximum total bytes across every rendered label, value and line
/// separator in one review. Deliberately smaller than the structural worst
/// case (a maximal export/dependency closure), so this is an independently
/// enforceable presentation bound, not decoration: a publication whose
/// review would exceed it still has an unaffected `publish` path, which
/// carries no such presentation-only ceiling.
pub const MAX_REVIEW_DISPLAY_BYTES: usize = 16_384;

/// Fail-closed errors for bounded, non-authorizing publication review.
///
/// Every variant rejects the input outright; none silently truncates, drops,
/// or substitutes a field and none performs any signing, custody, or network
/// action.
#[derive(Debug)]
pub enum PublicationReviewError {
    /// Defensive self-consistency recheck failed (artifact/commitment codec).
    Artifact(PublicationError),
    /// Defensive self-consistency recheck failed (semantics recomputation).
    Semantics(PublicationAdmissionError),
    /// A resolver/digest lookup used for presentation-only component digests
    /// (WASM/ABI bytes, hash-suite lookup) failed.
    Hashing(HashingError),
    /// The retained semantics digest differs from the presentation-only
    /// per-profile recomputation in [`presentation_semantics_for_profile`].
    /// Unreachable for any `CodeArtifact` produced by
    /// [`execution::publication::authenticate_publication`] or a correctly
    /// chosen caller profile; retained as defensive regression insurance.
    SemanticsMismatch,
    /// Re-decoding the freshly re-encoded artifact produced different
    /// structural content. The input is already a validated, typed
    /// `CodeArtifact`, not raw bytes, so this cannot fail for any value
    /// reachable through safe Rust; retained as defensive regression
    /// insurance against this module's own encode/decode bugs, not an
    /// adversarial unknown/trailing-byte decoder check.
    ArtifactRoundTripMismatch,
    /// The freshly recomputed artifact commitment differs from the one
    /// [`PreparedPublication`] retained. Unreachable through
    /// `PreparedPublication::prepare`, which computes both from the same
    /// inputs; retained as defensive regression insurance.
    DigestMismatch,
    /// The freshly recomputed submission signing frame differs from the one
    /// [`PreparedPublication`] retained. Unreachable through
    /// `PreparedPublication::prepare` for the same reason as
    /// [`Self::DigestMismatch`]; retained as defensive regression insurance.
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
    /// presentation-only semantics mapping. `CodeArtifact::new` and
    /// `decode_code_artifact` both already restrict `wasm_profile` to the
    /// four currently known profile constants, so this is unreachable for
    /// any `CodeArtifact` that exists in safe Rust; it exists only so this
    /// module fails closed instead of panicking if a future profile constant
    /// is ever added to `execution` without updating this presentation
    /// dispatch (see [`presentation_semantics_for_profile`]).
    UnknownWasmProfile(u32),
}

impl std::fmt::Display for PublicationReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Artifact(error) => write!(f, "publication review artifact error: {error}"),
            Self::Semantics(error) => write!(f, "publication review semantics error: {error}"),
            Self::Hashing(error) => write!(f, "publication review hashing error: {error}"),
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
            Self::Hashing(error) => Some(error),
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

impl From<HashingError> for PublicationReviewError {
    fn from(error: HashingError) -> Self {
        Self::Hashing(error)
    }
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
    checked_display_text(value, maximum).map_err(|error: DisplayTextError| match error {
        DisplayTextError::Limit { actual, maximum } => PublicationReviewError::Limit {
            field,
            actual,
            maximum,
        },
        DisplayTextError::Undisplayable => PublicationReviewError::UndisplayableField(field),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Minimal internal accumulator enforcing the aggregate field-count and
/// byte-count presentation budget as each rendered line is produced. Not a
/// framework: it only counts and joins `label=value` lines.
struct BoundedRenderer {
    lines: Vec<(String, String)>,
    total_bytes: usize,
}

impl BoundedRenderer {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Counts the label, value, `=` separator and trailing newline toward the
    /// aggregate budget before appending; refuses rather than truncating.
    fn push(
        &mut self,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), PublicationReviewError> {
        let label: String = label.into();
        let value: String = value.into();
        let fields: usize =
            self.lines
                .len()
                .checked_add(1)
                .ok_or(PublicationReviewError::Limit {
                    field: "total_fields",
                    actual: usize::MAX,
                    maximum: MAX_REVIEW_TOTAL_FIELDS,
                })?;
        if fields > MAX_REVIEW_TOTAL_FIELDS {
            return Err(PublicationReviewError::Limit {
                field: "total_fields",
                actual: fields,
                maximum: MAX_REVIEW_TOTAL_FIELDS,
            });
        }
        let label_len: usize = label.len();
        let value_len: usize = value.len();
        let line_bytes: usize = label_len
            .checked_add(1)
            .and_then(|running| running.checked_add(value_len))
            .and_then(|running| running.checked_add(1))
            .ok_or(PublicationReviewError::Limit {
                field: "total_display_bytes",
                actual: usize::MAX,
                maximum: MAX_REVIEW_DISPLAY_BYTES,
            })?;
        let total: usize =
            self.total_bytes
                .checked_add(line_bytes)
                .ok_or(PublicationReviewError::Limit {
                    field: "total_display_bytes",
                    actual: usize::MAX,
                    maximum: MAX_REVIEW_DISPLAY_BYTES,
                })?;
        if total > MAX_REVIEW_DISPLAY_BYTES {
            return Err(PublicationReviewError::Limit {
                field: "total_display_bytes",
                actual: total,
                maximum: MAX_REVIEW_DISPLAY_BYTES,
            });
        }
        self.total_bytes = total;
        self.lines.push((label, value));
        Ok(())
    }

    fn finish(self) -> Vec<(String, String)> {
        self.lines
    }
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
                MAX_PACKAGE_CHAIN_ID_BYTES,
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
    origin_chain_id: String,
    origin_seed_hex: String,
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    hash_suite_id: u16,
    revision: u64,
    wasm_profile: u32,
    wasm_profile_name: &'static str,
    wasm_bytes_len: usize,
    diagnostic_wasm_contract_code_hash_hex: String,
    unverified_abi_bytes_len: usize,
    diagnostic_abi_bytes_hash_hex: String,
    semantics_hex: String,
    artifact_digest_hex: String,
    exports: Vec<String>,
    dependencies: Vec<DependencyReview>,
    nonce: u64,
    request_id_hex: String,
    frame_hex: String,
    artifact_bytes: Vec<u8>,
    frame_bytes: Vec<u8>,
    lines: Vec<(String, String)>,
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

/// Presentation-only profile-to-semantics dispatch.
///
/// For each of the four profile constants `CodeArtifact` currently supports,
/// this calls the one existing canonical semantics function for that exact
/// profile number: the same functions `node_core::local_execution`'s
/// dependency-closure admission and `execution::execution_scopes`'s
/// execution-authority checks call for an *exact* (non-relaxed) profile
/// match. It does not implement, replace, or claim the cross-profile policy
/// compatibility those owners separately enforce (for example, profile-three
/// code admitted under a profile-four execution policy); it only checks
/// whether this artifact's own declared profile and declared semantics field
/// are mutually self-consistent. A match proves commitment self-consistency,
/// not understood code meaning or business-safety approval.
fn presentation_semantics_for_profile(
    prepared: &PreparedPublication,
) -> Result<Digest32, PublicationReviewError> {
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
    /// Performs a defensive self-consistency recheck of the retained,
    /// already-typed [`CodeArtifact`] (see the module and error docs for why
    /// these checks cannot actually fail through safe Rust), then renders
    /// every material field DR-0214 lists through one bounded internal
    /// renderer that counts every actual label, value and separator against
    /// an explicit aggregate field/byte budget before accepting it. Any
    /// mismatch, undisplayable field, or exceeded bound refuses with a typed
    /// error and builds no partial/placeholder review.
    pub fn build(prepared: &PreparedPublication) -> Result<Self, PublicationReviewError> {
        let artifact: &CodeArtifact = prepared.artifact();

        let artifact_bytes: Vec<u8> = encode_code_artifact(artifact)?;
        let redecoded: CodeArtifact = decode_code_artifact(&artifact_bytes)?;
        if &redecoded != artifact {
            return Err(PublicationReviewError::ArtifactRoundTripMismatch);
        }
        let recomputed_digest =
            artifact_commitment(prepared.resolver(), prepared.context(), artifact)?;
        if &recomputed_digest != prepared.artifact_digest() {
            return Err(PublicationReviewError::DigestMismatch);
        }
        let recomputed_semantics = presentation_semantics_for_profile(prepared)?;
        if &recomputed_semantics != prepared.semantics() {
            return Err(PublicationReviewError::SemanticsMismatch);
        }
        let frame_bytes: Vec<u8> = publication_submission_signing_frame(
            prepared.resolver(),
            prepared.context(),
            artifact,
            prepared.nonce(),
            *prepared.request_id().as_bytes(),
        )?;
        if frame_bytes.as_slice() != prepared.signable_frame() {
            return Err(PublicationReviewError::FrameMismatch);
        }

        let epoch = prepared.context().epoch();
        let hash_suite_id: u16 = prepared.resolver().suite_for_epoch(epoch)?.id.get();
        let wasm_digest: Digest32 = prepared.resolver().hash_for_purpose(
            epoch,
            HashPurpose::ContractCode,
            artifact.wasm(),
        )?;
        let abi_digest: Digest32 = prepared.resolver().hash_for_purpose(
            epoch,
            HashPurpose::ContractCode,
            artifact.unverified_abi(),
        )?;

        let mut renderer = BoundedRenderer::new();
        let publisher_hex: String = prepared.publisher().to_string();
        renderer.push("publisher", publisher_hex.clone())?;
        let origin_chain_id: String = display_safe(
            "origin.chain_id",
            artifact.origin().chain_id().as_str(),
            MAX_PACKAGE_CHAIN_ID_BYTES,
        )?;
        renderer.push("origin_chain_id", origin_chain_id.clone())?;
        let origin_seed_hex: String = hex(artifact.origin().seed());
        renderer.push("origin_seed_hex", origin_seed_hex.clone())?;
        let chain_id: String = display_safe(
            "context.chain_id",
            artifact.context().chain_id().as_str(),
            MAX_PACKAGE_CHAIN_ID_BYTES,
        )?;
        renderer.push("chain_id", chain_id.clone())?;
        renderer.push(
            "protocol_version",
            artifact.context().protocol_version().get().to_string(),
        )?;
        renderer.push("epoch", artifact.context().epoch().get().to_string())?;
        renderer.push("hash_suite_id", hash_suite_id.to_string())?;
        renderer.push("revision", artifact.revision().to_string())?;
        renderer.push("wasm_profile", artifact.wasm_profile().to_string())?;
        let wasm_profile_name_value: &'static str = wasm_profile_name(artifact.wasm_profile())?;
        renderer.push("wasm_profile_name", wasm_profile_name_value)?;
        renderer.push("wasm_bytes", artifact.wasm().len().to_string())?;
        let diagnostic_wasm_contract_code_hash_hex: String = wasm_digest.to_string();
        renderer.push(
            "diagnostic_wasm_contract_code_hash",
            diagnostic_wasm_contract_code_hash_hex.clone(),
        )?;
        renderer.push("abi_bytes", artifact.unverified_abi().len().to_string())?;
        let diagnostic_abi_bytes_hash_hex: String = abi_digest.to_string();
        renderer.push(
            "diagnostic_abi_bytes_hash",
            diagnostic_abi_bytes_hash_hex.clone(),
        )?;
        let semantics_hex: String = prepared.semantics().to_string();
        renderer.push("semantics", semantics_hex.clone())?;
        let artifact_digest_hex: String = prepared.artifact_digest().to_string();
        renderer.push("artifact_digest", artifact_digest_hex.clone())?;

        let exports_source: &[String] = artifact.exports();
        let mut exports: Vec<String> = Vec::with_capacity(exports_source.len());
        renderer.push("export_count", exports_source.len().to_string())?;
        for (index, export) in exports_source.iter().enumerate() {
            let safe: String = display_safe("export", export, MAX_CONTRACT_ENTRYPOINT_NAME_BYTES)?;
            renderer.push(format!("export[{index}]"), safe.clone())?;
            exports.push(safe);
        }

        let dependencies_source: &[UnverifiedDependencyRef] = artifact.unverified_dependencies();
        let mut dependencies: Vec<DependencyReview> = Vec::with_capacity(dependencies_source.len());
        renderer.push("dependency_count", dependencies_source.len().to_string())?;
        for (index, dependency) in dependencies_source.iter().enumerate() {
            let review: DependencyReview = DependencyReview::build(dependency)?;
            renderer.push(
                format!("dependency[{index}].chain_id"),
                review.chain_id.clone(),
            )?;
            renderer.push(
                format!("dependency[{index}].publisher"),
                review.publisher_hex.clone(),
            )?;
            renderer.push(format!("dependency[{index}].seed"), review.seed_hex.clone())?;
            renderer.push(
                format!("dependency[{index}].revision"),
                review.revision.to_string(),
            )?;
            renderer.push(
                format!("dependency[{index}].protocol_version"),
                review.protocol_version.to_string(),
            )?;
            renderer.push(
                format!("dependency[{index}].epoch"),
                review.epoch.to_string(),
            )?;
            renderer.push(
                format!("dependency[{index}].artifact_digest"),
                review.artifact_digest_hex.clone(),
            )?;
            dependencies.push(review);
        }

        renderer.push("nonce", prepared.nonce().to_string())?;
        let request_id_hex: String = prepared.request_id().to_string();
        renderer.push("request_id", request_id_hex.clone())?;
        let frame_hex: String = hex(&frame_bytes);
        renderer.push("frame_hex", frame_hex.clone())?;

        Ok(Self {
            publisher_hex,
            origin_chain_id,
            origin_seed_hex,
            chain_id,
            protocol_version: artifact.context().protocol_version().get(),
            epoch: artifact.context().epoch().get(),
            hash_suite_id,
            revision: artifact.revision(),
            wasm_profile: artifact.wasm_profile(),
            wasm_profile_name: wasm_profile_name_value,
            wasm_bytes_len: artifact.wasm().len(),
            diagnostic_wasm_contract_code_hash_hex,
            unverified_abi_bytes_len: artifact.unverified_abi().len(),
            diagnostic_abi_bytes_hash_hex,
            semantics_hex,
            artifact_digest_hex,
            exports,
            dependencies,
            nonce: prepared.nonce(),
            request_id_hex,
            frame_hex,
            artifact_bytes,
            frame_bytes,
            lines: renderer.finish(),
        })
    }

    /// Configured publisher identity, as lowercase hex.
    #[must_use]
    pub fn publisher_hex(&self) -> &str {
        &self.publisher_hex
    }

    /// Origin's declared chain identifier (printable, display-safe). Equal
    /// to [`Self::chain_id`] by `CodeArtifact::new`'s own invariant, but
    /// rendered and retained separately so the origin identity is always
    /// presented explicitly, not merely implied by the context field.
    #[must_use]
    pub fn origin_chain_id(&self) -> &str {
        &self.origin_chain_id
    }

    /// Origin's declared creation seed, as lowercase hex. Two publications
    /// differing only by `--origin-seed` differ here (and in
    /// `artifact_digest`), not only in an opaque digest.
    #[must_use]
    pub fn origin_seed_hex(&self) -> &str {
        &self.origin_seed_hex
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

    /// Expected hash-suite identifier the retained resolver resolves for
    /// this context's epoch; the same identifier `trusted_context` already
    /// checks against the caller's expected protocol context.
    #[must_use]
    pub const fn hash_suite_id(&self) -> u16 {
        self.hash_suite_id
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

    /// Exact WASM byte length. This is metadata-only preview, not a semantic
    /// or code-safety review of the WASM content: raw WASM bytes are not
    /// rendered as display text. The exact bytes are unmodified inside
    /// [`Self::artifact_bytes`] for independent inspection or hashing with
    /// any tool. [`Self::diagnostic_wasm_contract_code_hash_hex`] is only a
    /// diagnostic comparison value, not authenticated code provenance.
    #[must_use]
    pub const fn wasm_bytes_len(&self) -> usize {
        self.wasm_bytes_len
    }

    /// Diagnostic hash of the retained WASM bytes under `ContractCode`.
    /// It grants no registry identity, verified `canonical_code_hash`,
    /// `module_ref`, provenance or approval. The publication commitment
    /// hashes the complete encoded artifact instead of this raw component.
    #[must_use]
    pub fn diagnostic_wasm_contract_code_hash_hex(&self) -> &str {
        &self.diagnostic_wasm_contract_code_hash_hex
    }

    /// Exact unverified ABI declaration byte length. This is metadata-only
    /// preview, not a semantic or code-safety review of the ABI content: raw
    /// ABI bytes are not rendered as display text. The exact bytes are
    /// unmodified inside [`Self::artifact_bytes`], and
    /// [`Self::diagnostic_abi_bytes_hash_hex`] is only a diagnostic comparison.
    #[must_use]
    pub const fn unverified_abi_bytes_len(&self) -> usize {
        self.unverified_abi_bytes_len
    }

    /// Diagnostic hash of unverified ABI bytes under the existing
    /// `ContractCode` purpose. It is neither code identity nor the
    /// publication commitment, and grants no provenance or approval.
    #[must_use]
    pub fn diagnostic_abi_bytes_hash_hex(&self) -> &str {
        &self.diagnostic_abi_bytes_hash_hex
    }

    /// Presentation-recomputed and matched profile semantics commitment
    /// (algorithm-prefixed hex). See [`presentation_semantics_for_profile`]
    /// for exactly what this does and does not prove.
    #[must_use]
    pub fn semantics_hex(&self) -> &str {
        &self.semantics_hex
    }

    /// Recomputed and matched artifact commitment digest (algorithm-prefixed
    /// hex).
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

    /// Exact submission signing frame, as lowercase hex. Byte-for-byte
    /// identical to [`PreparedPublication::signable_frame`] (the frame check
    /// in [`Self::build`] already proved this); this is the exact bounded
    /// canonical preimage-to-frame correspondence, exposed for display.
    #[must_use]
    pub fn frame_hex(&self) -> &str {
        &self.frame_hex
    }

    /// Exact bounded canonical artifact bytes (the same bytes
    /// `artifact_commitment` hashes), reusing the buffer
    /// [`Self::build`] already produced and verified round-trips exactly.
    /// Includes the complete, unmodified WASM and ABI bytes; a caller that
    /// needs the full raw code/ABI content (rather than only a length and
    /// digest) reads it from here, not from a truncated display field.
    #[must_use]
    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    /// Exact bounded submission signing frame bytes, reusing the buffer
    /// [`Self::build`] already recomputed and verified against
    /// [`PreparedPublication::signable_frame`].
    #[must_use]
    pub fn frame_bytes(&self) -> &[u8] {
        &self.frame_bytes
    }

    /// Every rendered `(label, value)` line, in presentation order, exactly
    /// as counted against this review's aggregate field/byte budget. Prefer
    /// [`Self::render`] for a single ready-to-print string.
    #[must_use]
    pub fn lines(&self) -> &[(String, String)] {
        &self.lines
    }

    /// The ONE complete bounded text rendering of every field this review
    /// counted toward its aggregate budget, as `label=value\n` lines in
    /// presentation order. A caller (SDK or CLI) builds this complete string
    /// once and prints or stores it as-is; nothing is recomputed, filtered,
    /// or re-measured after [`Self::build`] already bounded it.
    #[must_use]
    pub fn render(&self) -> String {
        let capacity: usize = self
            .lines
            .iter()
            .map(|(label, value)| label.len() + value.len() + 2)
            .sum();
        let mut out: String = String::with_capacity(capacity);
        for (label, value) in &self.lines {
            out.push_str(label);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{DependencyReview, PublicationReviewError, display_safe};
    use abi::package_types::PackageOrigin;
    use execution::publication::{PublicationContext, UnverifiedDependencyRef};
    use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion};

    #[test]
    fn display_safe_preserves_error_mapping_and_order() {
        assert!(matches!(
            display_safe("context.chain_id", "\n", 0),
            Err(PublicationReviewError::Limit {
                field: "context.chain_id",
                actual: 1,
                maximum: 0,
            })
        ));
        assert!(matches!(
            display_safe("context.chain_id", "\n", 1),
            Err(PublicationReviewError::UndisplayableField(
                "context.chain_id"
            ))
        ));
    }

    #[test]
    fn dependency_presentation_refuses_control_bytes_before_copying() {
        let chain: ChainId = ChainId::new("dependency\u{1}chain").unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(1), Epoch::new(0)).unwrap();
        let origin: PackageOrigin = PackageOrigin::unverified(chain, [22; 32], [5; 32]).unwrap();
        let dependency: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
            origin,
            1,
            context,
            Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]),
        )
        .unwrap();
        assert!(matches!(
            DependencyReview::build(&dependency),
            Err(PublicationReviewError::UndisplayableField(
                "dependency.chain_id"
            ))
        ));
    }
}
