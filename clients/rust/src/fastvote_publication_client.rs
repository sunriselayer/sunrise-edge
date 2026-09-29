//! Publication-before-apply client workflow for the signed handoff profile.
//!
//! This is deliberately separate from the historical FastVote apply path.
//! The caller selects it only from a locally authenticated genesis profile;
//! no endpoint response or route selection can authorize a downgrade.

use core::fmt;
use std::error::Error;
use std::time::{Duration, Instant};

use consensus::bundle::{
    PublicationBundle, decode_publication_bundle, encode_publication_bundle,
    verify_publication_bundle,
};
use consensus::{
    AvailabilityCertificate, AvailabilityCertifier, AvailabilityIdentity, AvailabilityVote,
    FastCertificate, FastPathCertifier, decode_availability_vote, encode_availability_certificate,
    encode_fast_certificate,
};
use execution::paid_execution::{
    PaidExecutionResult, SignedPaidIntent, authenticate_paid_intent, decode_signed_paid_intent,
    encode_signed_paid_intent, paid_invocation_digest,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_wire::{
    FASTVOTE_PUBLICATION_RETAIN_PATH, FASTVOTE_PUBLICATION_SOURCE_PATH,
    FASTVOTE_PUBLISHED_APPLY_PATH, FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH, FastVoteApplyRequest,
    FastVotePublishedApplyRequest, NODE_EVENT_MEDIA_TYPE, RetainedPublicationSourceRequest,
};
use protocol_types::{AtomicityDomainId, Digest32, ValidatorId};

use crate::client::expect_success;
use crate::error::ClientError;
use crate::fastvote_client::{
    FastVoteApplyAttempt, FastVoteEndpoint, FastVoteEndpointConfigError, FastVoteNetworkError,
    bounded_deadline, validate_fastvote_apply_response, validate_fastvote_endpoints,
};
use crate::transport::{Method, Transport, WireRequest};
use crate::{Client, FastPathEd25519Verifier, NODE_RESULT_MEDIA_TYPE};

/// One endpoint's independently checked retention ACK, or its exact error.
#[derive(Debug)]
pub struct FastVoteAvailabilityAttempt {
    /// Locally configured validator identity for this endpoint.
    pub validator_id: ValidatorId,
    /// Only a vote with the exact publication identity and valid registered
    /// signature is `Ok`.
    pub result: Result<AvailabilityVote, ClientError>,
}

/// One successful publication round. This proves a quorum signed retention;
/// it does not assert that any validator has applied the user transaction.
#[derive(Debug)]
pub struct FastVotePublishedRound {
    /// Source validator whose prepared material supplied the verified bundle.
    pub source_validator: ValidatorId,
    /// Exact bundle forwarded to each retainer.
    pub bundle: PublicationBundle,
    /// Quorum proof to persist before any apply POST.
    pub availability_certificate: AvailabilityCertificate,
    /// Individual retention results, including failed or Byzantine peers.
    pub attempts: Vec<FastVoteAvailabilityAttempt>,
}

/// Failure before any publication quorum was formed. Each endpoint failure is
/// preserved for diagnosis; neither variant authorizes an apply.
#[derive(Debug)]
pub enum FastVotePublicationError {
    /// Local pin, signature, deadline or configuration preflight failed.
    Network(FastVoteNetworkError),
    /// No configured prepared replica supplied a valid complete bundle.
    NoSource(Vec<(ValidatorId, ClientError)>),
    /// A source was verified, but independently valid matching ACKs lacked
    /// strict greater-than-two-thirds voting power.
    InsufficientQuorum(Vec<FastVoteAvailabilityAttempt>),
}

impl fmt::Display for FastVotePublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => write!(f, "FastVote publication preflight: {error}"),
            Self::NoSource(failures) => write!(
                f,
                "no prepared validator supplied a verified publication bundle ({} attempts)",
                failures.len()
            ),
            Self::InsufficientQuorum(attempts) => write!(
                f,
                "publication retention did not reach availability quorum ({} attempts)",
                attempts.len()
            ),
        }
    }
}

impl Error for FastVotePublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Network(error) => Some(error),
            Self::NoSource(_) | Self::InsufficientQuorum(_) => None,
        }
    }
}

impl From<FastVoteNetworkError> for FastVotePublicationError {
    fn from(value: FastVoteNetworkError) -> Self {
        Self::Network(value)
    }
}

impl From<FastVoteEndpointConfigError> for FastVotePublicationError {
    fn from(value: FastVoteEndpointConfigError) -> Self {
        Self::Network(value.into())
    }
}

impl From<ClientError> for FastVotePublicationError {
    fn from(value: ClientError) -> Self {
        Self::Network(value.into())
    }
}

impl From<execution::paid_execution::PaidExecutionError> for FastVotePublicationError {
    fn from(value: execution::paid_execution::PaidExecutionError) -> Self {
        Self::Network(FastVoteNetworkError::Preflight(ClientError::PaidExecution(
            value,
        )))
    }
}

fn availability_certifier(
    certifier: &FastPathCertifier,
) -> Result<AvailabilityCertifier, ClientError> {
    AvailabilityCertifier::new(
        certifier.chain_id().clone(),
        certifier.protocol_version(),
        certifier.epoch(),
        certifier.validator_set().clone(),
    )
    .map_err(ClientError::FastVoteConsensus)
}

/// Checks local signed-intent authentication, full-certificate quorum and
/// exact publication identity before contacting a peer. The manifest digest
/// is covered by the verified availability signatures; no caller-provided
/// hash may substitute for those signatures.
fn verify_published_authority(
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    domain: AtomicityDomainId,
    signed: &SignedPaidIntent,
    certificate: &FastCertificate,
    availability: &AvailabilityCertificate,
) -> Result<(), ClientError> {
    let expected_context: PublicationContext = PublicationContext::new(
        certifier.chain_id().clone(),
        certifier.protocol_version(),
        certifier.epoch(),
    )
    .map_err(ClientError::Publication)?;
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(signed)?;
    authenticate_paid_intent(resolver, &expected_context, &signed_bytes)?;
    let tx_hash: Digest32 = paid_invocation_digest(resolver, signed)?;
    if certificate.tx_hash != tx_hash {
        return Err(ClientError::FastVoteUnexpectedTransaction {
            expected: tx_hash,
            actual: certificate.tx_hash,
        });
    }
    certifier.verify_certificate(certificate, &FastPathEd25519Verifier)?;
    let identity: &AvailabilityIdentity = &availability.identity;
    if identity.domain != domain
        || identity.request_id != signed.intent.request_id
        || identity.signed_intent_digest != tx_hash
        || identity.execution_commitment != certificate.execution_effects_hash
    {
        return Err(ClientError::FastVotePublicationMismatch(
            "availability certificate identity",
        ));
    }
    availability_certifier(certifier)?
        .verify_certificate(availability, &FastPathEd25519Verifier)?;
    Ok(())
}

impl<T: Transport> Client<T> {
    /// Requests a canonical full-certificate publication bundle from one
    /// prepared source and independently verifies its local signed request,
    /// domain, validator-set certificate, witness digest and artifact hashes.
    /// Retainers also perform their stricter witness-closure check before ACK.
    #[allow(clippy::too_many_arguments)]
    pub fn source_fastvote_publication(
        &self,
        signed: &SignedPaidIntent,
        certificate: &FastCertificate,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        domain: AtomicityDomainId,
        deadline: Option<Instant>,
    ) -> Result<(PublicationBundle, AvailabilityIdentity), ClientError> {
        let signed_bytes: Vec<u8> = encode_signed_paid_intent(signed)?;
        let expected_context: PublicationContext = PublicationContext::new(
            certifier.chain_id().clone(),
            certifier.protocol_version(),
            certifier.epoch(),
        )
        .map_err(ClientError::Publication)?;
        authenticate_paid_intent(resolver, &expected_context, &signed_bytes)?;
        let tx_hash: Digest32 = paid_invocation_digest(resolver, signed)?;
        if certificate.tx_hash != tx_hash {
            return Err(ClientError::FastVoteUnexpectedTransaction {
                expected: tx_hash,
                actual: certificate.tx_hash,
            });
        }
        certifier.verify_certificate(certificate, &FastPathEd25519Verifier)?;
        let certificate_bytes: Vec<u8> = encode_fast_certificate(certificate)?;
        let body: Vec<u8> = FastVoteApplyRequest {
            signed_paid_intent: signed_bytes.clone(),
            certificate: certificate_bytes,
        }
        .encode()?;
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_PUBLICATION_SOURCE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        let response_body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let bundle: PublicationBundle = decode_publication_bundle(&response_body)?;
        if bundle.domain != domain
            || bundle.request_id != signed.intent.request_id
            || bundle.signed_intent != signed_bytes
            || bundle.certificate != *certificate
        {
            return Err(ClientError::FastVotePublicationMismatch(
                "source bundle domain, request, signed bytes or full certificate",
            ));
        }
        let verified = verify_publication_bundle(
            &bundle,
            certifier,
            &FastPathEd25519Verifier,
            resolver,
            history,
        )?;
        if verified.identity.signed_intent_digest != tx_hash {
            return Err(ClientError::FastVotePublicationMismatch(
                "source bundle signed-intent digest",
            ));
        }
        Ok((bundle, verified.identity))
    }

    /// Requests the exact retained full publication bundle for one operation
    /// this caller already knows about only through an independently
    /// verified signed frontier entry (`expected_identity`), never through a
    /// locally held signed intent or certificate: the source may have only
    /// ever retained this operation, never prepared it. Verifies the
    /// returned bundle's quorum certificate, witness commitment and every
    /// artifact exactly as [`Self::source_fastvote_publication`] does, then
    /// additionally re-derives the carried signed intent's own digest and
    /// requires it to equal both the certificate's `tx_hash` and the
    /// expected identity -- the binding `consensus` alone cannot check --
    /// and requires the fully re-verified identity to equal
    /// `expected_identity` byte-for-byte under this caller's own locally
    /// pinned `certifier` (chain, protocol version, epoch and validator
    /// set). This endpoint is never itself an authority: every check here
    /// runs regardless of which replica answered.
    pub fn source_retained_fastvote_publication(
        &self,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        expected_identity: &AvailabilityIdentity,
        deadline: Option<Instant>,
    ) -> Result<PublicationBundle, ClientError> {
        let request: RetainedPublicationSourceRequest = RetainedPublicationSourceRequest {
            epoch: certifier.epoch(),
            request_id: expected_identity.request_id,
        };
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: request.encode()?,
            deadline,
        })?;
        let response_body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let bundle: PublicationBundle = decode_publication_bundle(&response_body)?;
        if bundle.domain != expected_identity.domain
            || bundle.request_id != expected_identity.request_id
        {
            return Err(ClientError::FastVotePublicationMismatch(
                "retained source bundle domain or request id",
            ));
        }
        let verified = verify_publication_bundle(
            &bundle,
            certifier,
            &FastPathEd25519Verifier,
            resolver,
            history,
        )?;
        if verified.identity != *expected_identity {
            return Err(ClientError::FastVotePublicationMismatch(
                "retained source bundle identity",
            ));
        }
        let expected_context: PublicationContext = PublicationContext::new(
            certifier.chain_id().clone(),
            certifier.protocol_version(),
            certifier.epoch(),
        )
        .map_err(ClientError::Publication)?;
        authenticate_paid_intent(resolver, &expected_context, &bundle.signed_intent)?;
        let signed: SignedPaidIntent = decode_signed_paid_intent(&bundle.signed_intent)?;
        let tx_hash: Digest32 = paid_invocation_digest(resolver, &signed)?;
        if tx_hash != bundle.certificate.tx_hash
            || tx_hash != expected_identity.signed_intent_digest
        {
            return Err(ClientError::FastVoteUnexpectedTransaction {
                expected: expected_identity.signed_intent_digest,
                actual: tx_hash,
            });
        }
        if signed.intent.request_id != expected_identity.request_id {
            return Err(ClientError::FastVotePublicationMismatch(
                "retained source bundle signed-intent request id",
            ));
        }
        Ok(bundle)
    }

    /// Asks this endpoint to retain the *complete* verified bundle. The core
    /// durably retains and rechecks it before returning a signed ACK.
    pub fn retain_fastvote_publication(
        &self,
        bundle_bytes: &[u8],
        deadline: Option<Instant>,
    ) -> Result<AvailabilityVote, ClientError> {
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_PUBLICATION_RETAIN_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: bundle_bytes.to_vec(),
            deadline,
        })?;
        let response_body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        decode_availability_vote(&response_body).map_err(ClientError::FastVoteConsensus)
    }

    /// Low-level publication-gated apply. The server independently enforces
    /// the installed profile and quorum authority; callers needing local
    /// preflight use [`apply_published_fastvote_to_all`].
    pub fn apply_published_fastvote(
        &self,
        signed: &SignedPaidIntent,
        resolver: &HashSuiteResolver,
        certificate: &FastCertificate,
        availability: &AvailabilityCertificate,
        deadline: Option<Instant>,
    ) -> Result<PaidExecutionResult, ClientError> {
        let body: Vec<u8> = FastVotePublishedApplyRequest {
            signed_paid_intent: encode_signed_paid_intent(signed)?,
            certificate: encode_fast_certificate(certificate)?,
            availability_certificate: encode_availability_certificate(availability)?,
        }
        .encode()?;
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_PUBLISHED_APPLY_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        let response_body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        validate_fastvote_apply_response(signed, resolver, &response_body)
    }
}

/// Gets a genuine full bundle from a prepared replica, broadcasts it to the
/// configured cohort, counts only exact-identity registered signatures and
/// returns a verified quorum certificate. No apply POST occurs in this call.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub fn collect_fastvote_availability_certificate<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    domain: AtomicityDomainId,
    signed: &SignedPaidIntent,
    certificate: &FastCertificate,
    overall_deadline: Instant,
    per_request_cap: Duration,
) -> Result<FastVotePublishedRound, FastVotePublicationError> {
    validate_fastvote_endpoints(endpoints, certifier)?;
    bounded_deadline(overall_deadline, per_request_cap)?;
    let expected_context: PublicationContext = PublicationContext::new(
        certifier.chain_id().clone(),
        certifier.protocol_version(),
        certifier.epoch(),
    )
    .map_err(ClientError::Publication)?;
    authenticate_paid_intent(
        resolver,
        &expected_context,
        &encode_signed_paid_intent(signed)?,
    )?;
    let tx_hash: Digest32 = paid_invocation_digest(resolver, signed)?;
    if certificate.tx_hash != tx_hash {
        return Err(ClientError::FastVoteUnexpectedTransaction {
            expected: tx_hash,
            actual: certificate.tx_hash,
        }
        .into());
    }
    certifier
        .verify_certificate(certificate, &FastPathEd25519Verifier)
        .map_err(ClientError::FastVoteConsensus)?;

    let mut source_failures: Vec<(ValidatorId, ClientError)> = Vec::new();
    let mut selected: Option<(ValidatorId, PublicationBundle, AvailabilityIdentity)> = None;
    for endpoint in endpoints {
        let deadline: Instant = bounded_deadline(overall_deadline, per_request_cap)?;
        match endpoint.client.source_fastvote_publication(
            signed,
            certificate,
            certifier,
            resolver,
            history,
            domain,
            Some(deadline),
        ) {
            Ok((bundle, identity)) => {
                selected = Some((endpoint.validator_id, bundle, identity));
                break;
            }
            Err(error) => source_failures.push((endpoint.validator_id, error)),
        }
    }
    let Some((source_validator, bundle, identity)) = selected else {
        return Err(FastVotePublicationError::NoSource(source_failures));
    };
    let bundle_bytes: Vec<u8> =
        encode_publication_bundle(&bundle).map_err(ClientError::FastVotePublicationBundle)?;
    let availability_certifier: AvailabilityCertifier = availability_certifier(certifier)?;
    let mut attempts: Vec<FastVoteAvailabilityAttempt> = Vec::with_capacity(endpoints.len());
    let mut votes: Vec<AvailabilityVote> = Vec::new();
    for endpoint in endpoints {
        let result: Result<AvailabilityVote, ClientError> =
            match bounded_deadline(overall_deadline, per_request_cap) {
                Err(_) => Err(ClientError::FastVoteOverallDeadlineExceeded),
                Ok(deadline) => endpoint
                    .client
                    .retain_fastvote_publication(&bundle_bytes, Some(deadline))
                    .and_then(|vote| {
                        if vote.validator != endpoint.validator_id {
                            return Err(ClientError::FastVoteEndpointIdentityMismatch {
                                expected: endpoint.validator_id,
                                actual: vote.validator,
                            });
                        }
                        if vote.identity != identity {
                            return Err(ClientError::FastVotePublicationMismatch(
                                "retention ACK identity",
                            ));
                        }
                        availability_certifier
                            .verify_vote(&vote, &FastPathEd25519Verifier)
                            .map_err(ClientError::FastVoteConsensus)?;
                        Ok(vote)
                    }),
            };
        if let Ok(vote) = &result {
            votes.push(vote.clone());
        }
        attempts.push(FastVoteAvailabilityAttempt {
            validator_id: endpoint.validator_id,
            result,
        });
    }
    let Some(availability_certificate) = availability_certifier
        .try_form_certificate(&identity, &votes, &FastPathEd25519Verifier)
        .map_err(ClientError::FastVoteConsensus)?
    else {
        return Err(FastVotePublicationError::InsufficientQuorum(attempts));
    };
    Ok(FastVotePublishedRound {
        source_validator,
        bundle,
        availability_certificate,
        attempts,
    })
}

/// Verifies the exact signed operation, full certificate and availability
/// quorum under the local pin before contacting any endpoint, then reports
/// each published-apply acknowledgement independently.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub fn apply_published_fastvote_to_all<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    domain: AtomicityDomainId,
    signed: &SignedPaidIntent,
    certificate: &FastCertificate,
    availability: &AvailabilityCertificate,
    overall_deadline: Instant,
    per_request_cap: Duration,
) -> Result<Vec<FastVoteApplyAttempt>, FastVoteNetworkError> {
    validate_fastvote_endpoints(endpoints, certifier)?;
    bounded_deadline(overall_deadline, per_request_cap)?;
    verify_published_authority(
        certifier,
        resolver,
        domain,
        signed,
        certificate,
        availability,
    )?;
    let mut attempts: Vec<FastVoteApplyAttempt> = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let result: Result<PaidExecutionResult, ClientError> =
            match bounded_deadline(overall_deadline, per_request_cap) {
                Err(_) => Err(ClientError::FastVoteOverallDeadlineExceeded),
                Ok(deadline) => endpoint.client.apply_published_fastvote(
                    signed,
                    resolver,
                    certificate,
                    availability,
                    Some(deadline),
                ),
            };
        attempts.push(FastVoteApplyAttempt {
            validator_id: endpoint.validator_id,
            result,
        });
    }
    Ok(attempts)
}
