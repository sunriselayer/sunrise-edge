//! Bounded, restartable transport driver for a selected outgoing quorum's
//! post-Freeze publication drain. This reaches only a target's *local* union
//! readiness; it never forms an ordered DrainSet vote or activates an epoch.

use core::fmt;
use std::error::Error;
use std::time::{Duration, Instant};

use consensus::bundle::PublicationBundle;
use consensus::{
    AvailabilityIdentity, DrainUnionIdentity, FastPathCertifier, FrozenFrontierCertifier,
    FrozenFrontierPage, FrozenFrontierVote, verify_frozen_frontier_quorum,
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
/// source page and a cap on possible durable mutations. A confirmation's
/// exact pre-write proof-absence response does not consume this mutation
/// budget; there is at most one such bounded probe per import attempt.
/// An incomplete run is safe to
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

/// One descriptor endpoint per exact selected signer, independently from
/// the configured artifact-source cohort. Any configured outgoing replica
/// may relay a fully re-verified bundle; it never replaces a selected vote.
/// Already staged pages resume from verified durable progress, so they do
/// not depend on their original descriptor signer remaining available.
/// The target is a
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
    artifact_sources: &[FastVoteEndpoint<T>],
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
    validate_fastvote_endpoints(artifact_sources, fast_certifier)
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
            if let Some(page) = staged {
                // read_drain_signer_progress has verified the staged page's
                // context, selected signature and running accumulator. It
                // is a scheduling hint only: core rechecks the full proof.
                let pending: &AvailabilityIdentity = page
                    .entries
                    .iter()
                    .find(|entry| cursor.is_none_or(|last| entry.request_id > last))
                    .ok_or(DrainDriveError::Mismatch(
                        "staged page has no unconfirmed member",
                    ))?;
                let confirmed = target.confirm_drain_member(
                    fast_certifier.epoch(),
                    vote.validator,
                    pending.request_id,
                    Some(request_deadline(bounds)?),
                );
                match confirmed {
                    Ok(()) => count_mutation(&mut mutation_attempts)?,
                    Err(error) if proof_not_retained(&error) => {
                        // This exact result is guaranteed pre-write by core.
                        // Never infer possession from a source's HTTP hint.
                        let bundle: PublicationBundle = source_bundle(
                            artifact_sources,
                            fast_certifier,
                            resolver,
                            history,
                            pending,
                            bounds,
                        )?;
                        count_mutation(&mut mutation_attempts)?;
                        if let Err(error) = target.import_staged_drain_publication(
                            vote.validator,
                            &bundle,
                            pending,
                            fast_certifier,
                            resolver,
                            history,
                            Some(request_deadline(bounds)?),
                        ) && !mutation_requires_reconcile(&error)
                        {
                            return Err(DrainDriveError::Client(Box::new(error)));
                        }
                    }
                    Err(error) => {
                        // An ambiguous response may have committed.
                        count_mutation(&mut mutation_attempts)?;
                        if !mutation_requires_reconcile(&error) {
                            return Err(DrainDriveError::Client(Box::new(error)));
                        }
                    }
                }
            } else {
                let page_request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
                    epoch: fast_certifier.epoch(),
                    after_request_id: cursor,
                    limit: bounds.page_limit,
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
                count_mutation(&mut mutation_attempts)?;
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
        count_mutation(&mut mutation_attempts)?;
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

fn count_mutation(attempts: &mut u32) -> Result<(), DrainDriveError> {
    *attempts = attempts
        .checked_add(1)
        .ok_or(DrainDriveError::InvalidConfig("mutation count overflow"))?;
    Ok(())
}

fn proof_not_retained(error: &ClientError) -> bool {
    matches!(error, ClientError::UnexpectedStatus { status: 409, body }
        if body == "drain-proof-not-retained")
}

fn source_bundle<T: Transport>(
    sources: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    identity: &AvailabilityIdentity,
    bounds: DrainDriveBounds,
) -> Result<PublicationBundle, DrainDriveError> {
    let mut last_error: Option<ClientError> = None;
    // Configuration validation caps this finite cohort. Each request and
    // the entire cohort traversal share bounded monotonic deadlines.
    for source in sources {
        match source.client.source_retained_fastvote_publication(
            certifier,
            resolver,
            history,
            identity,
            Some(request_deadline(bounds)?),
        ) {
            Ok(bundle) => return Ok(bundle),
            Err(error) => last_error = Some(error),
        }
    }
    Err(match last_error {
        Some(error) => DrainDriveError::Client(Box::new(error)),
        None => DrainDriveError::InvalidConfig("no artifact sources"),
    })
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
    use crate::transport::{TransportError, WireRequest, WireResponse};
    use consensus::bundle::{
        LOGICAL_COMMITMENT_PROFILE, encode_publication_bundle, verify_publication_bundle,
    };
    use consensus::{ConsensusSigner, DrainUnionAccumulator, FrozenFrontierAccumulator};
    use ed25519_zebra::{SigningKey, VerificationKey};
    use node_wire::{
        DrainSignerProgressResponse, FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
        FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH, FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
        FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH, NODE_RESULT_MEDIA_TYPE,
    };
    use protocol_types::{
        Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
        SignatureSchemeId, ValidatorId,
    };
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use validator_set::{ValidatorInfo, ValidatorSet};

    struct Signer {
        id: ValidatorId,
        key: SigningKey,
    }
    impl ConsensusSigner for Signer {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
            let signature: [u8; 64] = self.key.sign(frame).into();
            Ok(signature.to_vec())
        }
    }

    struct ScriptedTransport {
        responses: RefCell<VecDeque<WireResponse>>,
        requests: RefCell<Vec<WireRequest>>,
    }
    impl Transport for ScriptedTransport {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            assert!(request.deadline.is_some());
            self.requests.borrow_mut().push(request.clone());
            Ok(self
                .responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected network request"))
        }
    }
    fn endpoint(
        id: ValidatorId,
        responses: Vec<WireResponse>,
    ) -> FastVoteEndpoint<ScriptedTransport> {
        FastVoteEndpoint {
            validator_id: id,
            endpoint_label: format!("{id:?}"),
            client: Client::new(ScriptedTransport {
                responses: RefCell::new(responses.into()),
                requests: RefCell::new(Vec::new()),
            }),
        }
    }
    fn response(status: u16, body: Vec<u8>) -> WireResponse {
        WireResponse {
            status,
            content_type: (status == 200).then(|| NODE_RESULT_MEDIA_TYPE.to_owned()),
            body,
        }
    }
    fn progress(
        vote: &FrozenFrontierVote,
        page: Option<&FrozenFrontierPage>,
        empty: &consensus::FrozenFrontierIdentity,
    ) -> WireResponse {
        response(
            200,
            DrainSignerProgressResponse {
                chain_id: vote.identity.chain_id.as_str().to_owned(),
                epoch: vote.identity.epoch,
                signer: vote.validator,
                vote: consensus::encode_frozen_frontier_vote(vote).unwrap(),
                confirmed_identity: consensus::encode_frozen_frontier_identity(if page.is_some() {
                    empty
                } else {
                    &vote.identity
                })
                .unwrap(),
                cursor: if page.is_some() {
                    None
                } else {
                    Some([0x51; 32])
                },
                staged_page: page
                    .map(|value| consensus::encode_frozen_frontier_page(value).unwrap()),
                complete: page.is_none(),
            }
            .encode()
            .unwrap(),
        )
    }

    #[test]
    fn successive_one_step_runs_resume_cached_descriptor_and_imported_relay_without_original_holder()
     {
        // Reuse a real prepare's witness/artifacts. This transport scheduling
        // fixture signs that unchanged business witness with its own four-key
        // test committee; it is not a four-replica execution acceptance test.
        let prepared: crate::fastvote_drain_client::closure_tests::MemberFixture =
            crate::fastvote_drain_client::closure_tests::member_fixture();
        let signed: execution::paid_execution::SignedPaidIntent = prepared.signed;
        let context = signed.intent.context.clone();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            context.chain_id().clone(),
            context.protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let mut signers: Vec<Signer> = [0x42, 0x53, 0x64, 0x75]
            .into_iter()
            .map(|byte: u8| {
                let key: SigningKey = SigningKey::from([byte; 32]);
                let verification: VerificationKey = (&key).into();
                Signer {
                    id: ValidatorId::new(verification.into()),
                    key,
                }
            })
            .collect();
        signers.sort_by_key(|signer| signer.id);
        let set: ValidatorSet = ValidatorSet::new(
            context.epoch(),
            signers
                .iter()
                .map(|signer| ValidatorInfo {
                    id: signer.id,
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: signer.id.as_bytes().to_vec(),
                })
                .collect(),
        )
        .unwrap();
        let certifier: FastPathCertifier = FastPathCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            set.clone(),
        )
        .unwrap();
        let frontier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            set,
        )
        .unwrap();
        let tx_hash: Digest32 =
            execution::paid_execution::paid_invocation_digest(&resolver, &signed).unwrap();
        let witness: Vec<u8> = prepared.bundle.witness;
        let effect_hash: Digest32 = resolver
            .hash_for_purpose(context.epoch(), HashPurpose::ExecutionEffects, &witness)
            .unwrap();
        let lock_hash: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x52; 32]);
        let fast_votes: Vec<consensus::FastVote> = signers
            .iter()
            .take(3)
            .map(|signer| {
                certifier
                    .cast_vote(tx_hash, effect_hash, lock_hash, signer)
                    .unwrap()
            })
            .collect();
        let certificate = certifier
            .try_form_certificate(
                tx_hash,
                effect_hash,
                lock_hash,
                &fast_votes,
                &FastPathEd25519Verifier,
            )
            .unwrap()
            .unwrap();
        let domain = protocol_types::AtomicityDomainId::new([9; 32]).unwrap();
        let bundle: PublicationBundle = PublicationBundle {
            domain,
            request_id: signed.intent.request_id,
            commitment_profile: LOGICAL_COMMITMENT_PROFILE,
            signed_intent: execution::paid_execution::encode_signed_paid_intent(&signed).unwrap(),
            certificate,
            witness,
            manifest: prepared.bundle.manifest,
            contents: prepared.bundle.contents,
        };
        let identity: AvailabilityIdentity = verify_publication_bundle(
            &bundle,
            &certifier,
            &FastPathEd25519Verifier,
            &resolver,
            &[],
        )
        .unwrap()
        .identity;
        let freeze: ExpectedDrainFreeze = ExpectedDrainFreeze {
            domain,
            closure_request_id: [7; 32],
            closure_height: 11,
        };
        let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
            &resolver,
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            domain,
            freeze.closure_request_id,
            freeze.closure_height,
        )
        .unwrap();
        let empty = accumulator.clone().into_identity();
        accumulator.push(&resolver, &identity).unwrap();
        let final_identity = accumulator.into_identity();
        let votes: Vec<FrozenFrontierVote> = signers
            .iter()
            .take(3)
            .map(|signer| frontier.cast_vote(final_identity.clone(), signer).unwrap())
            .collect();
        let page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id: None,
            entries: vec![identity],
            terminal: true,
        };
        let descriptor_sources: Vec<FastVoteEndpoint<ScriptedTransport>> = signers
            .iter()
            .take(3)
            .map(|signer| endpoint(signer.id, Vec::new()))
            .collect();
        let artifacts: Vec<FastVoteEndpoint<ScriptedTransport>> = vec![
            // B's response is invalid; independently verified C relay works.
            endpoint(
                signers[1].id,
                vec![response(200, b"forged bundle".to_vec())],
            ),
            endpoint(
                signers[2].id,
                vec![response(200, encode_publication_bundle(&bundle).unwrap())],
            ),
        ];
        let mut ready_accumulator: DrainUnionAccumulator = DrainUnionAccumulator::new(
            &resolver,
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            domain,
            freeze.closure_request_id,
            freeze.closure_height,
            &votes
                .iter()
                .map(|vote| (vote.validator, vote.identity.clone()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        ready_accumulator
            .push_member(&resolver, &page.entries[0])
            .unwrap();
        let ready = ready_accumulator.into_identity();
        let mut replies: Vec<WireResponse> = vec![
            progress(&votes[0], Some(&page), &empty),
            response(409, b"drain-proof-not-retained".to_vec()),
            response(
                200,
                consensus::encode_availability_identity(&page.entries[0]).unwrap(),
            ),
            progress(&votes[0], Some(&page), &empty),
            // Fresh invocation confirms the prior import without reimport.
            progress(&votes[0], Some(&page), &empty),
            response(204, Vec::new()),
            progress(&votes[0], None, &empty),
            progress(&votes[1], None, &empty),
            progress(&votes[2], None, &empty),
            // Next invocation spends its single step on union completion.
            progress(&votes[0], None, &empty),
            progress(&votes[1], None, &empty),
            progress(&votes[2], None, &empty),
        ];
        replies.push(response(
            200,
            consensus::encode_drain_union_identity(&ready).unwrap(),
        ));
        let target = endpoint(signers[3].id, replies);
        let bounds: DrainDriveBounds = DrainDriveBounds {
            overall_deadline: Instant::now().checked_add(Duration::from_secs(3)).unwrap(),
            per_request_cap: Duration::from_secs(1),
            page_limit: 1,
            max_mutation_attempts: 1,
        };
        for _ in 0..2 {
            assert_eq!(
                drive_drain_to_local_ready(
                    &target.client,
                    &descriptor_sources,
                    &artifacts,
                    &votes,
                    &certifier,
                    &resolver,
                    &[],
                    freeze,
                    bounds
                )
                .unwrap(),
                DrainDriveOutcome::Incomplete {
                    mutation_attempts: 1
                }
            );
        }
        assert_eq!(
            drive_drain_to_local_ready(
                &target.client,
                &descriptor_sources,
                &artifacts,
                &votes,
                &certifier,
                &resolver,
                &[],
                freeze,
                bounds
            )
            .unwrap(),
            DrainDriveOutcome::LocallyReady {
                identity: ready,
                mutation_attempts: 1
            }
        );
        assert!(
            descriptor_sources.iter().all(|source| source
                .client
                .transport()
                .requests
                .borrow()
                .is_empty())
        );
        for source in &artifacts {
            let requests = source.client.transport().requests.borrow();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].path, FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH);
        }
        let requests = target.client.transport().requests.borrow();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.path.starts_with("/v1/fastvote/drain/import/"))
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.path == FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH)
                .count(),
            2
        );
        assert_eq!(
            requests.last().unwrap().path,
            FASTVOTE_DRAIN_UNION_ADVANCE_PATH
        );
        assert!(
            requests
                .iter()
                .any(|request| request.path == FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH)
        );
    }

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
    fn only_exact_prewrite_proof_absence_allows_import() {
        let status = |status: u16, body: &str| ClientError::UnexpectedStatus {
            status,
            body: body.to_owned(),
        };
        assert!(proof_not_retained(&status(409, "drain-proof-not-retained")));
        assert!(!proof_not_retained(&status(409, "drain-not-ready")));
        assert!(!proof_not_retained(&status(
            503,
            "drain-proof-not-retained"
        )));
        let mut attempts: u32 = u32::MAX;
        assert!(count_mutation(&mut attempts).is_err());
    }
}
