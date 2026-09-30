//! Bounded, restartable transport driver for a selected outgoing quorum's
//! post-Freeze publication drain. This reaches only a target's *local* union
//! readiness; it never forms an ordered DrainSet vote or activates an epoch.

use core::fmt;
use std::error::Error;
use std::time::{Duration, Instant};

use consensus::{
    DrainUnionIdentity, FastPathCertifier, FrozenFrontierCertifier, FrozenFrontierPage,
    FrozenFrontierVote, verify_frozen_frontier_quorum,
};
use hashing::HashSuiteResolver;
use node_wire::{FrozenFrontierPageRequest, MAX_FRONTIER_PAGE_LIMIT};

use crate::Client;
use crate::FastPathEd25519Verifier;
use crate::error::ClientError;
use crate::fastvote_client::{
    FastVoteEndpoint, FastVoteEndpointConfigError, FastVoteNetworkError, bounded_deadline,
    validate_fastvote_endpoints,
};
use crate::fastvote_drain_client::ExpectedDrainFreeze;
use crate::transport::Transport;

/// A whole-run deadline, a cap on each network request, a bound on each
/// source page and a cap on mutation attempts. An incomplete run is safe to
/// invoke again with the same locally pinned selection and source mapping.
#[derive(Clone, Copy, Debug)]
pub struct DrainDriveBounds {
    pub overall_deadline: Instant,
    pub per_request_cap: Duration,
    pub page_limit: u16,
    pub max_mutation_attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainDriveOutcome {
    /// The target returned a selection-scoped, locally ready identity after
    /// its final CAS. This is not an ordered DrainSet decision.
    LocallyReady {
        identity: DrainUnionIdentity,
        mutation_attempts: u32,
    },
    /// The configured step budget was exhausted. Durable signer or union
    /// progress may already have advanced; rerun with the same selection.
    Incomplete { mutation_attempts: u32 },
}

#[derive(Debug)]
pub enum DrainDriveError {
    InvalidConfig(&'static str),
    EndpointConfig(FastVoteEndpointConfigError),
    NetworkBound(Box<FastVoteNetworkError>),
    Frontier(consensus::FrontierError),
    Client(Box<ClientError>),
    Mismatch(&'static str),
}

impl fmt::Display for DrainDriveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid drain driver config: {reason}")
            }
            Self::EndpointConfig(error) => write!(formatter, "drain source mapping: {error}"),
            Self::NetworkBound(error) => write!(formatter, "drain request deadline: {error}"),
            Self::Frontier(error) => write!(formatter, "drain selection: {error}"),
            Self::Client(error) => write!(formatter, "drain transport: {error}"),
            Self::Mismatch(reason) => write!(formatter, "drain progress mismatch: {reason}"),
        }
    }
}

impl Error for DrainDriveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EndpointConfig(error) => Some(error),
            Self::NetworkBound(error) => Some(error),
            Self::Frontier(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::InvalidConfig(_) | Self::Mismatch(_) => None,
        }
    }
}

impl From<ClientError> for DrainDriveError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

/// One configured source endpoint per exact selected signer. The target is a
/// separately configured client; its transport must independently validate
/// its endpoint identity (TLS for a remote endpoint). The protocol pin comes
/// only from `fast_certifier` and `resolver`, never an HTTP context response.
///
/// A progress read is a scheduling hint, not proof that the target actually
/// holds a publication. Every staged page and member confirmation is still
/// checked by the target's fenced CAS and full retained proof verification.
/// Ambiguous mutation responses are followed by a fresh durable progress
/// read before any retry. A crash simply ends this call: the next invocation
/// resumes from the target's durable signer/union rows.
#[allow(clippy::too_many_arguments)]
pub fn drive_drain_to_local_ready<T: Transport>(
    target: &Client<T>,
    sources: &[FastVoteEndpoint<T>],
    selected_votes: &[FrozenFrontierVote],
    fast_certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    freeze: ExpectedDrainFreeze,
    bounds: DrainDriveBounds,
) -> Result<DrainDriveOutcome, DrainDriveError> {
    if bounds.page_limit == 0 || bounds.page_limit > MAX_FRONTIER_PAGE_LIMIT {
        return Err(DrainDriveError::InvalidConfig(
            "page limit is outside the bounded wire range",
        ));
    }
    if bounds.max_mutation_attempts == 0 {
        return Err(DrainDriveError::InvalidConfig(
            "mutation attempt budget is zero",
        ));
    }
    bounded_deadline(bounds.overall_deadline, bounds.per_request_cap)
        .map_err(|error| DrainDriveError::NetworkBound(Box::new(error)))?;
    if resolver.chain_id() != fast_certifier.chain_id()
        || resolver.protocol_version() != fast_certifier.protocol_version()
    {
        return Err(DrainDriveError::Mismatch(
            "hash resolver differs from local genesis pin",
        ));
    }
    validate_fastvote_endpoints(sources, fast_certifier)
        .map_err(DrainDriveError::EndpointConfig)?;
    if sources.len() != selected_votes.len() {
        return Err(DrainDriveError::Mismatch(
            "source mapping does not match selection",
        ));
    }
    let frontier_certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        fast_certifier.chain_id().clone(),
        fast_certifier.protocol_version(),
        fast_certifier.epoch(),
        fast_certifier.validator_set().clone(),
    )
    .map_err(DrainDriveError::Frontier)?;
    verify_frozen_frontier_quorum(
        &frontier_certifier,
        selected_votes,
        freeze.domain,
        freeze.closure_request_id,
        freeze.closure_height,
        &FastPathEd25519Verifier,
    )
    .map_err(DrainDriveError::Frontier)?;
    for vote in selected_votes {
        if !sources
            .iter()
            .any(|source| source.validator_id == vote.validator)
        {
            return Err(DrainDriveError::Mismatch(
                "selected signer has no configured source",
            ));
        }
    }

    let mut mutation_attempts: u32 = 0;
    for vote in selected_votes {
        let source: &FastVoteEndpoint<T> = sources
            .iter()
            .find(|source| source.validator_id == vote.validator)
            .ok_or(DrainDriveError::Mismatch(
                "selected signer source disappeared",
            ))?;
        loop {
            let progress = target.read_drain_signer_progress(
                &frontier_certifier,
                vote.validator,
                freeze,
                resolver,
                Some(request_deadline(bounds)?),
            )?;
            if let Some(record) = &progress {
                if record.vote != *vote {
                    return Err(DrainDriveError::Mismatch(
                        "durable signer vote differs from selection",
                    ));
                }
                if record.complete {
                    if record.confirmed_identity != vote.identity || record.staged_page.is_some() {
                        return Err(DrainDriveError::Mismatch(
                            "complete signer progress disagrees with vote",
                        ));
                    }
                    break;
                }
            }
            if mutation_attempts >= bounds.max_mutation_attempts {
                return Ok(DrainDriveOutcome::Incomplete { mutation_attempts });
            }
            let cursor: Option<[u8; 32]> = progress
                .as_ref()
                .and_then(|record| record.confirmed_last_request_id);
            let staged: Option<&FrozenFrontierPage> = progress
                .as_ref()
                .and_then(|record| record.staged_page.as_ref());
            // Re-fetch exactly the page already staged even when a later
            // invocation changed its page cap. A terminal staged page may
            // need one spare slot to observe the next out-of-prefix key;
            // a full page can also be terminal when the scan has no
            // continuation, so staying within the current cap is safe.
            let page_limit: u16 = match staged {
                Some(page) => {
                    staged_page_limit(page.entries.len(), page.terminal, bounds.page_limit)?
                }
                None => bounds.page_limit,
            };
            let page_request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
                epoch: fast_certifier.epoch(),
                after_request_id: staged.map_or(cursor, |page| page.after_request_id),
                limit: page_limit,
            };
            let (served_vote, page): (FrozenFrontierVote, FrozenFrontierPage) =
                source.client.fetch_signed_frozen_frontier_page(
                    &page_request,
                    &frontier_certifier,
                    vote.validator,
                    Some(request_deadline(bounds)?),
                )?;
            if served_vote != *vote {
                return Err(DrainDriveError::Mismatch(
                    "source changed its selected signed frontier",
                ));
            }
            if let Some(staged_page) = staged {
                if staged_page != &page {
                    return Err(DrainDriveError::Mismatch(
                        "staged page differs from configured source",
                    ));
                }
                let pending = page
                    .entries
                    .iter()
                    .find(|entry| cursor.is_none_or(|last| entry.request_id > last))
                    .ok_or(DrainDriveError::Mismatch(
                        "staged page has no unconfirmed member",
                    ))?;
                let bundle = source.client.source_retained_fastvote_publication(
                    fast_certifier,
                    resolver,
                    history,
                    pending,
                    Some(request_deadline(bounds)?),
                )?;
                mutation_attempts += 1;
                let imported = target.import_staged_drain_publication(
                    vote.validator,
                    &bundle,
                    pending,
                    fast_certifier,
                    resolver,
                    history,
                    Some(request_deadline(bounds)?),
                );
                if let Err(error) = imported {
                    if mutation_requires_reconcile(&error) {
                        continue;
                    }
                    return Err(DrainDriveError::Client(Box::new(error)));
                }
                if mutation_attempts >= bounds.max_mutation_attempts {
                    return Ok(DrainDriveOutcome::Incomplete { mutation_attempts });
                }
                mutation_attempts += 1;
                let confirmed = target.confirm_drain_member(
                    fast_certifier.epoch(),
                    vote.validator,
                    pending.request_id,
                    Some(request_deadline(bounds)?),
                );
                if let Err(error) = confirmed {
                    if mutation_requires_reconcile(&error) {
                        continue;
                    }
                    return Err(DrainDriveError::Client(Box::new(error)));
                }
            } else {
                mutation_attempts += 1;
                let staged = target.stage_drain_signer_page(
                    &frontier_certifier,
                    vote.validator,
                    freeze,
                    vote,
                    &page,
                    Some(request_deadline(bounds)?),
                );
                if let Err(error) = staged {
                    if mutation_requires_reconcile(&error) {
                        continue;
                    }
                    return Err(DrainDriveError::Client(Box::new(error)));
                }
            }
        }
    }

    loop {
        if mutation_attempts >= bounds.max_mutation_attempts {
            return Ok(DrainDriveOutcome::Incomplete { mutation_attempts });
        }
        mutation_attempts += 1;
        match target.advance_drain_union(
            &frontier_certifier,
            selected_votes,
            freeze,
            Some(request_deadline(bounds)?),
        ) {
            Ok(Some(identity)) => {
                return Ok(DrainDriveOutcome::LocallyReady {
                    identity,
                    mutation_attempts,
                });
            }
            Ok(None) => {}
            // There is no bounded union-progress read yet. An ambiguous
            // union commit must be surfaced to the operator; a fresh run
            // can replay the *same* selection against the idempotent CAS.
            Err(error) => return Err(DrainDriveError::Client(Box::new(error))),
        }
    }
}

fn request_deadline(bounds: DrainDriveBounds) -> Result<Instant, DrainDriveError> {
    bounded_deadline(bounds.overall_deadline, bounds.per_request_cap)
        .map_err(|error| DrainDriveError::NetworkBound(Box::new(error)))
}

fn staged_page_limit(entry_count: usize, terminal: bool, cap: u16) -> Result<u16, DrainDriveError> {
    let length: u16 = u16::try_from(entry_count)
        .map_err(|_| DrainDriveError::Mismatch("staged page exceeds wire entry count"))?;
    if length == 0 || length > cap {
        return Err(DrainDriveError::InvalidConfig(
            "page limit cannot reproduce the already-staged page",
        ));
    }
    if terminal && length < cap {
        return length.checked_add(1).ok_or(DrainDriveError::Mismatch(
            "terminal staged page limit overflow",
        ));
    }
    Ok(length)
}

fn mutation_requires_reconcile(error: &ClientError) -> bool {
    match error {
        ClientError::Transport(_) => true,
        ClientError::UnexpectedStatus { status: 409, body } => body == "drain-not-ready",
        ClientError::UnexpectedStatus { status: 503, body } => {
            body == "drain-storage-indeterminate"
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_retryable_drain_outcomes_enter_progress_reconciliation() {
        let status = |status: u16, body: &str| ClientError::UnexpectedStatus {
            status,
            body: body.to_owned(),
        };
        assert!(mutation_requires_reconcile(&status(409, "drain-not-ready")));
        assert!(mutation_requires_reconcile(&status(
            503,
            "drain-storage-indeterminate"
        )));
        assert!(!mutation_requires_reconcile(&status(
            409,
            "drain-epoch-repin-required"
        )));
        assert!(!mutation_requires_reconcile(&status(400, "drain-invalid")));
        assert!(!mutation_requires_reconcile(&status(
            503,
            "drain-storage-unavailable"
        )));
    }

    #[test]
    fn staged_page_replay_limit_preserves_terminal_room_without_exceeding_cap() {
        assert_eq!(staged_page_limit(1, true, 4).unwrap(), 2);
        assert_eq!(staged_page_limit(1, false, 4).unwrap(), 1);
        assert_eq!(staged_page_limit(128, true, 128).unwrap(), 128);
        assert!(staged_page_limit(2, true, 1).is_err());
    }
}
