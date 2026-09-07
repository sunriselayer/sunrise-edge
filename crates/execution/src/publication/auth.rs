//! Publication authentication and candidate verification.
//!
//! Authenticates exact immutable code artifact bytes and strict owning publisher key
//! in an expected trusted context, while granting NO execution, storage, dependency,
//! or type authority.
//!
//! # Explicit Non-Claims
//! - ABI declaration bytes and dependency references remain UNVERIFIED.
//! - The resulting candidate is not admitted, published, executable,
//!   dependency-authenticated, typed-ABI verified, or persisted.
//! - Preserves original hash context; never reconstructs a trusted resolver from request fields.

use super::{
    CodeArtifact, PublicationContext, PublicationError as E, PublicationRequest,
    encode_code_artifact, encode_publication_context,
};
use abi::package_types::encode_package_origin;
use canonical_encoding::{CanonicalStruct, encode_digest32};
use crypto::{
    Ed25519OwnerAddressPolicy, Ed25519Verifier, SignatureDomain, SignatureMessageType,
    SignatureVerifier, frame_signature_message, validate_ed25519_owner_address,
};
use hashing::HashSuiteResolver;
use protocol_types::{Digest32, HashPurpose, SignatureSchemeId};

/// An authenticated publication candidate witnessing publisher signature and WASM profile.
///
/// This candidate witnesses exact publisher signature and structural WASM profile only.
/// It is not admitted, published, executable, dependency-authenticated, typed-ABI verified,
/// or persisted. It introduces no side effects and grants no execution, storage, dependency,
/// or type authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPublicationCandidate {
    request: std::sync::Arc<PublicationRequest>,
}

impl AuthenticatedPublicationCandidate {
    /// Returns a reference to the authenticated publication request.
    #[must_use]
    pub fn request(&self) -> &PublicationRequest {
        &self.request
    }
}

/// Validates that the trusted expected context matches the resolver and artifact context.
///
/// Ensures original hash context is preserved and structural profile and revision limits
/// are verified before expensive cryptographic or validation operations occur.
fn validate_publication_context(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    artifact: &CodeArtifact,
) -> Result<(), E> {
    if resolver.chain_id() != expected.chain_id() {
        return Err(E::ChainMismatch);
    }
    if resolver.protocol_version() != expected.protocol_version() {
        return Err(E::ContextMismatch);
    }
    if artifact.context() != expected {
        return Err(E::ContextMismatch);
    }
    if artifact.origin().chain_id() != expected.chain_id() {
        return Err(E::ChainMismatch);
    }
    if artifact.revision() != 1 {
        return Err(E::InvalidRevision(artifact.revision()));
    }
    if !matches!(artifact.wasm_profile(), 1..=4) {
        return Err(E::UnsupportedWasmProfile(artifact.wasm_profile()));
    }
    Ok(())
}

/// Computes the cryptographic commitment digest for a code artifact under the expected epoch context.
///
/// Enforces trusted context consistency and uses the active `ContractCode` purpose algorithm.
pub fn artifact_commitment(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    artifact: &CodeArtifact,
) -> Result<Digest32, E> {
    validate_publication_context(resolver, expected, artifact)?;
    let encoded_bytes: Vec<u8> = encode_code_artifact(artifact)?;
    let commitment: Digest32 =
        resolver.hash_for_purpose(expected.epoch(), HashPurpose::ContractCode, &encoded_bytes)?;
    Ok(commitment)
}

/// Internal helper that constructs the signed payload frame from an already-computed artifact digest.
///
/// Binds the entire artifact (context, origin, revision, nonce, digest, scheme) into a canonical
/// frame to prevent replay and avoid redundant commitment hashing during authentication.
fn compute_publication_signing_frame(
    expected: &PublicationContext,
    artifact: &CodeArtifact,
    nonce: u64,
    artifact_digest: &Digest32,
) -> Result<Vec<u8>, E> {
    let mut cs: CanonicalStruct = CanonicalStruct::new(0x6307, 1);
    cs.field_bytes(1, encode_publication_context(expected)?)?;
    cs.field_bytes(2, encode_package_origin(artifact.origin())?)?;
    cs.field_u64(3, artifact.revision())?;
    cs.field_u64(4, nonce)?;
    cs.field_bytes(5, encode_digest32(artifact_digest)?)?;
    cs.field_u16(6, SignatureSchemeId::Ed25519.as_u16())?;
    let payload: Vec<u8> = cs.finish()?;

    let domain: SignatureDomain = SignatureDomain {
        chain_id: expected.chain_id().clone(),
        protocol_version: expected.protocol_version(),
        epoch: expected.epoch(),
        message_type: SignatureMessageType::new("CreatePackage")?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };

    let framed_message: Vec<u8> = frame_signature_message(&domain, &payload)?;
    Ok(framed_message)
}

/// Constructs the publication signing frame for a code artifact and nonce.
///
/// Computes the artifact commitment under the trusted resolver and frames the resulting payload.
pub fn publication_signing_frame(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    artifact: &CodeArtifact,
    nonce: u64,
) -> Result<Vec<u8>, E> {
    let digest: Digest32 = artifact_commitment(resolver, expected, artifact)?;
    compute_publication_signing_frame(expected, artifact, nonce, &digest)
}

/// Authenticates a publication request against expected context and expected semantics.
///
/// Verification proceeds in strict sequence:
/// 1. Exact trusted context validation
/// 2. Expected semantics equality check
/// 3. Strict publisher key validation with canonical prime-order policy
/// 4. Recomputation of artifact commitment and full comparison against request digest
/// 5. Construction of signature payload frame with computed digest
/// 6. Ed25519 signature verification over framed payload
/// 7. Non-executing structural WASM validation
///
/// Returns an [`AuthenticatedPublicationCandidate`] witnessing publisher signature and WASM profile.
/// ABI declaration bytes and dependency references remain unverified.
pub fn authenticate_publication(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    expected_semantics: &Digest32,
    request: PublicationRequest,
) -> Result<AuthenticatedPublicationCandidate, E> {
    authenticate_with_request_id(resolver, expected, expected_semantics, request, None)
}

pub(super) fn authenticate_with_request_id(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    expected_semantics: &Digest32,
    request: PublicationRequest,
    request_id: Option<[u8; 32]>,
) -> Result<AuthenticatedPublicationCandidate, E> {
    let artifact: &CodeArtifact = request.artifact();

    // 1. Verify exact trusted context matches
    validate_publication_context(resolver, expected, artifact)?;

    // 2. Verify expected semantics digest equality
    if artifact.semantics() != expected_semantics {
        return Err(E::SemanticsMismatch);
    }

    // 3. Validate strict publisher address with canonical prime order policy
    validate_ed25519_owner_address(
        artifact.origin().publisher(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;

    // 4. Recompute artifact commitment and verify equality with request artifact digest
    let computed_digest: Digest32 = artifact_commitment(resolver, expected, artifact)?;
    if &computed_digest != request.artifact_digest() {
        return Err(E::CommitmentMismatch);
    }

    // 5. Construct publication signing frame using the computed digest
    let frame: Vec<u8> = match request_id {
        Some(request_id) => super::submission::frame_submission_digest(
            expected,
            artifact,
            request.nonce(),
            &computed_digest,
            request_id,
        )?,
        None => compute_publication_signing_frame(
            expected,
            artifact,
            request.nonce(),
            &computed_digest,
        )?,
    };

    // 6. Verify publisher signature over framed message prior to costly WASM operations
    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(artifact.origin().publisher())?;
    let is_valid_sig: bool = verifier.verify_framed(&frame, request.signature())?;
    if !is_valid_sig {
        return Err(E::InvalidSignature);
    }

    // 7. Non-executing structural WASM profile and export validation
    let export_refs: Vec<&str> = artifact
        .exports()
        .iter()
        .map(|name: &String| name.as_str())
        .collect();
    let wasm_handle: crate::ValidatedContractWasm = crate::validate_contract_wasm_profile(
        artifact.wasm(),
        &export_refs,
        artifact.wasm_profile(),
    )?;
    drop(wasm_handle);

    // 8. Return candidate witness owning the request
    Ok(AuthenticatedPublicationCandidate {
        request: std::sync::Arc::new(request),
    })
}
