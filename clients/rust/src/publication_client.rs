//! Explicit, authenticated local-devnet publication client operations.
//!
//! Publication authentication proves exact publisher bytes, not durable admission,
//! ABI authority, or generic contract execution. Callers must independently run
//! `query_verified_context` before signing, just as for transactions.

use abi::package_types::PackageOrigin;
use crypto::SignatureSigner;
use execution::publication::{
    CodeArtifact, PublicationContext, PublicationRequest, PublicationSubmission,
    artifact_commitment, authenticate_publication_submission, decode_publication_submission,
    encode_publication_submission, publication_submission_signing_frame,
};
use hashing::HashSuiteResolver;
use node_core::RequestId;
use node_wire::{
    HttpNodeResult, NODE_EVENT_MEDIA_TYPE, NODE_RESULT_MEDIA_TYPE, QUERY_RESULT_MEDIA_TYPE,
};
use protocol_types::{Digest32, SignatureSchemeId};

use crate::{
    Client, ClientError, ExpectedProtocolContext, LocalSigner, Method, Transport, WireRequest,
    WireResponse,
};

/// The explicitly enabled local-devnet publication endpoint.
pub const PUBLICATION_PATH: &str = "/v1/contracts/publications";

/// Constructs the fixed genesis hash schedule supported by the local-devnet profile.
/// Rejects unsupported expectations; never reads configuration from a response.
pub fn local_publication_resolver(
    expected: &ExpectedProtocolContext,
) -> Result<HashSuiteResolver, ClientError> {
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        vec![crate::HashSuiteSchedule {
            activation_epoch: crate::Epoch::new(0),
            suite: crate::HashSuite::genesis(),
        }],
    )?;
    trusted_context(&resolver, expected)?;
    Ok(resolver)
}

pub(crate) fn trusted_context(
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
) -> Result<PublicationContext, ClientError> {
    if resolver.chain_id() != expected.chain_id()
        || resolver.protocol_version() != expected.protocol_version()
        || resolver.suite_for_epoch(expected.epoch())?.id != expected.hash_suite_id()
        || expected.signature_scheme_id() != SignatureSchemeId::Ed25519.as_u16()
        || expected.address_binding_id()
            != crate::ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID
        || expected.transaction_auth_profile_id()
            != crate::ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID
    {
        return Err(ClientError::PublicationTrustMismatch);
    }
    Ok(PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )?)
}

/// Signs a caller-constructed artifact once, binding its exact nonce and request ID.
///
/// The caller must first verify the remote context against `expected`. The
/// resolver and artifact semantics must come from local trusted configuration.
pub fn build_signed_publication(
    signer: &LocalSigner,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    artifact: CodeArtifact,
    nonce: u64,
    request_id: RequestId,
) -> Result<PublicationSubmission, ClientError> {
    let context: PublicationContext = trusted_context(resolver, expected)?;
    if artifact.origin().publisher() != signer.address().as_bytes() {
        return Err(ClientError::ExternalSignerAddressMismatch {
            expected: crate::Address::new(*artifact.origin().publisher()),
            actual: signer.address(),
        });
    }
    let digest: Digest32 = artifact_commitment(resolver, &context, &artifact)?;
    let semantics: Digest32 = *artifact.semantics();
    let frame: Vec<u8> = publication_submission_signing_frame(
        resolver,
        &context,
        &artifact,
        nonce,
        *request_id.as_bytes(),
    )?;
    let signature_bytes: Vec<u8> = signer.sign_framed(&frame)?;
    let signature: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| crypto::CryptoError::InvalidSignatureLength(signature_bytes.len()))?;
    let request: PublicationRequest = PublicationRequest::new(artifact, nonce, digest, signature);
    let submission: PublicationSubmission =
        PublicationSubmission::new(*request_id.as_bytes(), request)?;
    authenticate_publication_submission(resolver, &context, &semantics, submission.clone())?;
    Ok(submission)
}

impl<T: Transport> Client<T> {
    /// Submits canonical publication bytes and requires one Accepted acknowledgement
    /// of the exact signed reference. This checks the server's claim, not an inclusion proof.
    pub fn submit_publication(
        &self,
        submission: &PublicationSubmission,
    ) -> Result<HttpNodeResult, ClientError> {
        let request: WireRequest = WireRequest {
            method: Method::Post,
            path: PUBLICATION_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: encode_publication_submission(submission)?,
            deadline: None,
        };
        let response: WireResponse = self.transport().send(&request)?;
        let bytes: Vec<u8> = crate::client::expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let result: HttpNodeResult = HttpNodeResult::decode(&bytes)?;
        let request_id: RequestId = RequestId::new(*submission.request_id())?;
        if result.request_id() != request_id {
            return Err(ClientError::SubmitResponseRequestIdMismatch {
                expected: request_id,
                actual: result.request_id(),
            });
        }
        let artifact: &CodeArtifact = submission.request().artifact();
        let reference: execution::publication::UnverifiedDependencyRef =
            execution::publication::UnverifiedDependencyRef::new(
                artifact.origin().clone(),
                artifact.revision(),
                artifact.context().clone(),
                *submission.request().artifact_digest(),
            )?;
        let expected_payload: Vec<u8> = execution::publication::encode_dependency_ref(&reference)?;
        let [acknowledgement] = result.responses() else {
            return Err(ClientError::PublicationSubmitAcknowledgementMismatch);
        };
        if acknowledgement.request_id() != request_id
            || acknowledgement.status() != crate::NodeResponseStatus::Accepted
            || acknowledgement.payload() != Some(expected_payload.as_slice())
        {
            return Err(ClientError::PublicationSubmitAcknowledgementMismatch);
        }
        Ok(result)
    }

    /// Fetches a publication and authenticates its exact selector, signature,
    /// commitment and WASM against the current locally trusted context/semantics.
    /// For a publication from an earlier epoch, use `query_publication_in_context`.
    /// A 404 is only a server-reported absence, not a cryptographic absence proof.
    pub fn query_publication(
        &self,
        origin: &PackageOrigin,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        expected_semantics: &Digest32,
    ) -> Result<Option<PublicationSubmission>, ClientError> {
        let context: PublicationContext = trusted_context(resolver, expected)?;
        self.query_publication_in_context(origin, resolver, expected, &context, expected_semantics)
    }

    /// Queries under the active remote expectation but verifies publisher bytes
    /// under a separately supplied original publication context and trusted resolver.
    /// This preserves historical signature/digest verification across epochs and
    /// protocol versions without trusting context or hash schedules from responses.
    pub fn query_publication_in_context(
        &self,
        origin: &PackageOrigin,
        original_resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        original_context: &PublicationContext,
        expected_semantics: &Digest32,
    ) -> Result<Option<PublicationSubmission>, ClientError> {
        self.query_publication_with_semantics(
            origin,
            original_resolver,
            expected,
            original_context,
            |_| Ok(*expected_semantics),
        )
    }

    pub(crate) fn query_publication_with_semantics(
        &self,
        origin: &PackageOrigin,
        original_resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        original_context: &PublicationContext,
        semantics: impl FnOnce(&CodeArtifact) -> Result<Digest32, ClientError>,
    ) -> Result<Option<PublicationSubmission>, ClientError> {
        if origin.chain_id() != expected.chain_id() {
            return Err(ClientError::PublicationTrustMismatch);
        }
        if original_context.chain_id() != expected.chain_id()
            || original_resolver.chain_id() != original_context.chain_id()
            || original_resolver.protocol_version() != original_context.protocol_version()
            || original_context.epoch() > expected.epoch()
        {
            return Err(ClientError::PublicationTrustMismatch);
        }
        self.query_verified_context(expected)?;
        let publisher: String = origin
            .publisher()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let seed: String = origin
            .seed()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request: WireRequest = WireRequest {
            method: Method::Get,
            path: format!("{PUBLICATION_PATH}/{publisher}/{seed}"),
            content_type: None,
            body: Vec::new(),
            deadline: None,
        };
        let response: WireResponse = self.transport().send(&request)?;
        if response.status == 404 {
            return Ok(None);
        }
        let bytes: Vec<u8> = crate::client::expect_success(response, QUERY_RESULT_MEDIA_TYPE)?;
        let submission: PublicationSubmission = decode_publication_submission(&bytes)?;
        if submission.request().artifact().origin() != origin {
            return Err(ClientError::PublicationQuerySelectorMismatch);
        }
        authenticate_publication_submission(
            original_resolver,
            original_context,
            &semantics(submission.request().artifact())?,
            submission.clone(),
        )?;
        Ok(Some(submission))
    }
}
