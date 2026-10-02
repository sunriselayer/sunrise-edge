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
    /// Checks the request lane and this exact signed intent's own context
    /// against the one immutable root's authenticated context. `certifier`,
    /// `commitment_profile()` and `admission_profile()` are all derived from
    /// that same root at construction time, so a disagreement among them is
    /// not a case this preflight can observe -- there is no longer a second,
    /// independently supplied value either could drift from, so no repair
    /// check is preserved for it.
    fn require_owned_preflight(&self, signed: &SignedPaidIntent) -> Result<(), Box<ClientError>> {
        self.require_owned_request_id(&signed.intent.request_id)
            .map_err(Box::new)?;
        if signed.intent.context != *self.admission_profile().context() {
            return Err(Box::new(ClientError::PublicationTrustMismatch));
        }
        Ok(())
    }

    /// Authenticate the lane and collect independently verified matching
    /// votes, using this root's own resolver -- never a second,
    /// independently selected schedule.
    #[allow(clippy::result_large_err)]
    pub fn collect_owned_certificate<T: Transport>(
        &self,
        endpoints: &[FastVoteEndpoint<T>],
        signed: &SignedPaidIntent,
        overall_deadline: Instant,
        per_request_cap: Duration,
    ) -> Result<(FastCertificate, Vec<FastVoteAttempt>), FastVoteQuorumError> {
        self.require_owned_preflight(signed)
            .map_err(|cause: Box<ClientError>| FastVoteNetworkError::from(*cause))?;
        collect_fastvote_certificate(
            endpoints,
            self.certifier(),
            self.genesis_root().genesis_resolver(),
            signed,
            overall_deadline,
            per_request_cap,
        )
    }

    /// Retain the complete certified closure before forming availability,
    /// using this root's own resolver. `history` remains a separate explicit
    /// local input.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn collect_owned_availability<T: Transport>(
        &self,
        endpoints: &[FastVoteEndpoint<T>],
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
            self.certifier(),
            self.genesis_root().genesis_resolver(),
            history,
            domain,
            signed,
            certificate,
            overall_deadline,
            per_request_cap,
        )
    }

    /// Apply only after both execution and availability quorums verify,
    /// using this root's own resolver.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn apply_owned_publication<T: Transport>(
        &self,
        endpoints: &[FastVoteEndpoint<T>],
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
            self.certifier(),
            self.genesis_root().genesis_resolver(),
            domain,
            signed,
            certificate,
            availability,
            overall_deadline,
            per_request_cap,
        )
    }
}
