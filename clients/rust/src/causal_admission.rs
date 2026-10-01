//! Profile-aware FastVote operations under one locally verified genesis pin.
//!
//! The older naked-certifier helpers remain useful for historical profiles;
//! they cannot infer the causal admission rule from a committee alone. These
//! entry points validate the original request lane before any endpoint I/O.

use std::time::{Duration, Instant};

use consensus::{AvailabilityCertificate, FastCertificate};
use execution::paid_execution::SignedPaidIntent;
use hashing::HashSuiteResolver;
use protocol_types::AtomicityDomainId;

use crate::fastvote_client::{
    FastVoteApplyAttempt, FastVoteAttempt, FastVoteEndpoint, FastVoteNetworkError,
    FastVoteQuorumError, TrustedFastVoteGenesis, collect_fastvote_certificate,
};
use crate::fastvote_publication_client::{
    FastVotePublicationError, FastVotePublishedRound, apply_published_fastvote_to_all,
    collect_fastvote_availability_certificate,
};
use crate::{ClientError, Transport};

impl TrustedFastVoteGenesis {
    fn require_owned_preflight(
        &self,
        signed: &SignedPaidIntent,
    ) -> Result<(), Box<ClientError>> {
        self.require_owned_request_id(&signed.intent.request_id)
            .map_err(Box::new)?;
        let context = self.admission_profile().context();
        if signed.intent.context != *context
            || self.commitment_profile != self.admission_profile().commitment_profile()
            || !self.committee_matches_pin()
            || self.certifier.chain_id() != context.chain_id()
            || self.certifier.protocol_version() != context.protocol_version()
            || self.certifier.epoch() != context.epoch()
        {
            return Err(Box::new(ClientError::PublicationTrustMismatch));
        }
        Ok(())
    }

    /// Authenticate the lane and collect independently verified matching votes.
    #[allow(clippy::result_large_err)]
    pub fn collect_owned_certificate<T: Transport>(
        &self,
        endpoints: &[FastVoteEndpoint<T>],
        resolver: &HashSuiteResolver,
        signed: &SignedPaidIntent,
        overall_deadline: Instant,
        per_request_cap: Duration,
    ) -> Result<(FastCertificate, Vec<FastVoteAttempt>), FastVoteQuorumError> {
        self.require_owned_preflight(signed)
            .map_err(|cause: Box<ClientError>| FastVoteNetworkError::from(*cause))?;
        collect_fastvote_certificate(
            endpoints,
            &self.certifier,
            resolver,
            signed,
            overall_deadline,
            per_request_cap,
        )
    }

    /// Retain the complete certified closure before forming availability.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn collect_owned_availability<T: Transport>(
        &self,
        endpoints: &[FastVoteEndpoint<T>],
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        domain: AtomicityDomainId,
        signed: &SignedPaidIntent,
        certificate: &FastCertificate,
        overall_deadline: Instant,
        per_request_cap: Duration,
    ) -> Result<FastVotePublishedRound, FastVotePublicationError> {
        self.require_owned_preflight(signed)
            .map_err(|cause: Box<ClientError>| FastVoteNetworkError::from(*cause))?;
        collect_fastvote_availability_certificate(
            endpoints,
            &self.certifier,
            resolver,
            history,
            domain,
            signed,
            certificate,
            overall_deadline,
            per_request_cap,
        )
    }

    /// Apply only after both execution and availability quorums verify.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn apply_owned_publication<T: Transport>(
        &self,
        endpoints: &[FastVoteEndpoint<T>],
        resolver: &HashSuiteResolver,
        domain: AtomicityDomainId,
        signed: &SignedPaidIntent,
        certificate: &FastCertificate,
        availability: &AvailabilityCertificate,
        overall_deadline: Instant,
        per_request_cap: Duration,
    ) -> Result<Vec<FastVoteApplyAttempt>, FastVoteNetworkError> {
        self.require_owned_preflight(signed)
            .map_err(|cause: Box<ClientError>| FastVoteNetworkError::from(*cause))?;
        apply_published_fastvote_to_all(
            endpoints,
            &self.certifier,
            resolver,
            domain,
            signed,
            certificate,
            availability,
            overall_deadline,
            per_request_cap,
        )
    }
}
