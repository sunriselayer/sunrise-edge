//! Request-identity-bound publication ingress. The older candidate frame is
//! intentionally a different signature domain and cannot authorize this request.

use super::{
    AuthenticatedPublicationCandidate, CodeArtifact, PublicationContext, PublicationError as E,
    PublicationRequest, artifact_commitment, decode_publication_request,
    encode_publication_context, encode_publication_request,
};
use canonical_encoding::{
    CanonicalFrame, CanonicalStruct, decode_canonical_frame, encode_digest32,
};
use crypto::{SignatureDomain, SignatureMessageType, frame_signature_message};
use hashing::HashSuiteResolver;
use protocol_types::{Digest32, SignatureSchemeId};

/// Complete bounded ingress envelope limit, including request identity.
pub const MAX_PUBLICATION_SUBMISSION_BYTES: usize = super::MAX_PUBLICATION_BYTES + 128;

/// Unverified publication request whose single signature binds its request ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationSubmission {
    request_id: [u8; 32],
    request: PublicationRequest,
}

impl PublicationSubmission {
    /// Constructs bounded unverified input; no admission authority is granted.
    pub fn new(request_id: [u8; 32], request: PublicationRequest) -> Result<Self, E> {
        if request_id == [0; 32] {
            return Err(E::Empty("request_id"));
        }
        Ok(Self {
            request_id,
            request,
        })
    }
    /// Returns the signed idempotency identity.
    #[must_use]
    pub const fn request_id(&self) -> &[u8; 32] {
        &self.request_id
    }
    /// Returns the signed artifact and nonce; its signature uses the submission domain.
    #[must_use]
    pub fn request(&self) -> &PublicationRequest {
        &self.request
    }
}

pub(super) fn frame_submission_digest(
    expected: &PublicationContext,
    artifact: &CodeArtifact,
    nonce: u64,
    digest: &Digest32,
    request_id: [u8; 32],
) -> Result<Vec<u8>, E> {
    if request_id == [0; 32] {
        return Err(E::Empty("request_id"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6309, 1);
    frame.field_bytes(1, request_id.to_vec())?;
    frame.field_bytes(2, encode_publication_context(expected)?)?;
    frame.field_bytes(
        3,
        abi::package_types::encode_package_origin(artifact.origin())?,
    )?;
    frame.field_u64(4, artifact.revision())?;
    frame.field_u64(5, nonce)?;
    frame.field_bytes(6, encode_digest32(digest)?)?;
    frame.field_u16(7, SignatureSchemeId::Ed25519.as_u16())?;
    let domain: SignatureDomain = SignatureDomain {
        chain_id: expected.chain_id().clone(),
        protocol_version: expected.protocol_version(),
        epoch: expected.epoch(),
        message_type: SignatureMessageType::new("CreatePackageSubmission")?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(frame_signature_message(&domain, &frame.finish()?)?)
}

/// Creates the single signature frame binding request identity and exact artifact.
pub fn publication_submission_signing_frame(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    artifact: &CodeArtifact,
    nonce: u64,
    request_id: [u8; 32],
) -> Result<Vec<u8>, E> {
    let digest: Digest32 = artifact_commitment(resolver, expected, artifact)?;
    frame_submission_digest(expected, artifact, nonce, &digest, request_id)
}

/// Authenticates this ingress signature; still grants no durable publication authority.
pub fn authenticate_publication_submission(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    semantics: &Digest32,
    submission: PublicationSubmission,
) -> Result<AuthenticatedPublicationCandidate, E> {
    super::auth::authenticate_with_request_id(
        resolver,
        expected,
        semantics,
        submission.request,
        Some(submission.request_id),
    )
}

/// Encodes the closed version-one submission frame.
pub fn encode_publication_submission(submission: &PublicationSubmission) -> Result<Vec<u8>, E> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6308, 1);
    frame.field_bytes(1, submission.request_id.to_vec())?;
    frame.field_bytes(2, encode_publication_request(&submission.request)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    check_size(bytes.len())?;
    Ok(bytes)
}

fn check_size(actual: usize) -> Result<(), E> {
    if actual > MAX_PUBLICATION_SUBMISSION_BYTES {
        return Err(E::Limit {
            field: "submission",
            actual,
            maximum: MAX_PUBLICATION_SUBMISSION_BYTES,
        });
    }
    Ok(())
}

/// Strictly decodes bounded unverified ingress bytes.
pub fn decode_publication_submission(bytes: &[u8]) -> Result<PublicationSubmission, E> {
    check_size(bytes.len())?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x6308)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| E::Empty("request_id_length"))?;
    PublicationSubmission::new(
        request_id,
        decode_publication_request(frame.required_field(2)?)?,
    )
}
