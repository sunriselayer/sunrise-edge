//! Stateless response binding only. Core remains the live authority/retention owner.
use super::*;
use consensus::{Ed25519ConsensusVerifier, UnsupportedSignatureSchemeResponse};
use execution::paid_execution::{
    PaidApplication, PaidExecutionResult, PaidExecutionStatus, PaidResultKind, PaidResultTarget,
    SignedPaidIntent, authenticate_paid_intent, decode_paid_execution_result,
    decode_signed_paid_intent, paid_invocation_digest,
};

impl Frontend {
    pub(super) fn verifier() -> Ed25519ConsensusVerifier {
        Ed25519ConsensusVerifier::new(UnsupportedSignatureSchemeResponse::FastPathProfileError)
    }
    fn verify_frontier_vote(
        &self,
        vote: &consensus::FrozenFrontierVote,
        validator: ValidatorId,
    ) -> io::Result<()> {
        if vote.validator != validator || vote.identity.domain != self.identity.domain {
            return Err(refused());
        }
        self.frontier
            .verify_vote(vote, &Self::verifier())
            .map_err(|_| refused())
    }
    pub(super) fn verify_availability_vote(
        &self,
        vote: &consensus::AvailabilityVote,
        identity: &consensus::AvailabilityIdentity,
    ) -> io::Result<()> {
        if vote.validator != self.identity.validator || &vote.identity != identity {
            return Err(refused());
        }
        self.availability
            .verify_vote(vote, &Self::verifier())
            .map_err(|_| refused())
    }
    fn verify_bundle(
        &self,
        bundle: &consensus::bundle::PublicationBundle,
    ) -> io::Result<consensus::AvailabilityIdentity> {
        let verified: consensus::bundle::VerifiedPublicationBundle =
            consensus::bundle::verify_publication_bundle(
                bundle,
                &self.fast,
                &Self::verifier(),
                &self.resolver,
                &[],
            )
            .map_err(|_| refused())?;
        let signed: SignedPaidIntent =
            decode_signed_paid_intent(&bundle.signed_intent).map_err(|_| refused())?;
        authenticate_paid_intent(&self.resolver, &self.context, &bundle.signed_intent)
            .map_err(|_| refused())?;
        if bundle.domain != self.identity.domain
            || bundle.request_id != signed.intent.request_id
            || bundle.certificate.tx_hash
                != paid_invocation_digest(&self.resolver, &signed).map_err(|_| refused())?
        {
            return Err(refused());
        }
        // Stateless bundle verification does not prove witness closure. That
        // remains the real retainer's responsibility before confirmed output.
        Ok(verified.identity)
    }
    fn verify_paid_result(
        &self,
        bytes: &[u8],
        request_id: [u8; 32],
        signed: Option<&SignedPaidIntent>,
    ) -> io::Result<()> {
        let outer: HttpNodeResult = HttpNodeResult::decode(bytes).map_err(|_| refused())?;
        let bound: BoundHttpNodeResult = outer
            .bind_request(node_core::RequestId::new(request_id).map_err(|_| refused())?)
            .map_err(|_| refused())?;
        let ack: SingleAcknowledgement<'_> =
            bound.single_acknowledgement().map_err(|_| refused())?;
        let result: PaidExecutionResult =
            decode_paid_execution_result(ack.payload()).map_err(|_| refused())?;
        let status: node_core::NodeResponseStatus = if result.status == PaidExecutionStatus::Success
        {
            node_core::NodeResponseStatus::Accepted
        } else {
            node_core::NodeResponseStatus::Rejected
        };
        if result.request_id != request_id || ack.status() != status {
            return Err(refused());
        }
        if let Some(signed) = signed {
            if result.effects.tx_hash
                != paid_invocation_digest(&self.resolver, signed).map_err(|_| refused())?
            {
                return Err(refused());
            }
            // Same pure application-kind/target rules as SDK acknowledgement
            // validation. No nonce, fee balance, store or commit decision here.
            let matches: bool = match (&signed.intent.application, &result.kind, &result.target) {
                (
                    PaidApplication::Publish(artifact),
                    PaidResultKind::Publish,
                    PaidResultTarget::Package(origin),
                ) => origin == artifact.origin(),
                (
                    PaidApplication::Instantiate(call),
                    PaidResultKind::Instantiate,
                    PaidResultTarget::Instance(record),
                ) => {
                    execution::local_execution::instance_target(&self.resolver, record)
                        .map_err(|_| refused())?
                        == call.instance
                }
                (
                    PaidApplication::Call(call),
                    PaidResultKind::Call,
                    PaidResultTarget::Instance(record),
                ) => {
                    execution::local_execution::instance_target(&self.resolver, record)
                        .map_err(|_| refused())?
                        == call.instance
                }
                _ => false,
            };
            if !matches {
                return Err(refused());
            }
        }
        Ok(())
    }
    pub(super) fn verify(&self, input: &Input, output: &Output) -> io::Result<()> {
        let route: Route = input.route;
        let headers: HeaderMap = output.header_map()?;
        if output.status == 204 {
            if !route.empty_success()
                || !output.body.is_empty()
                || headers.contains_key(header::CONTENT_TYPE)
            {
                return Err(refused());
            }
            return Ok(());
        }
        if output.status != 200 {
            return if output.status >= 400 {
                Ok(())
            } else {
                Err(refused())
            };
        }
        if matches!(
            route,
            Route::Live | Route::SignerPage | Route::MemberConfirm
        ) || output.body.len() > route.spec().response
        {
            return Err(refused());
        }
        let media: &str = if route.method() == Method::GET {
            QUERY_RESULT_MEDIA_TYPE
        } else {
            NODE_RESULT_MEDIA_TYPE
        };
        let types: Vec<&HeaderValue> = headers.get_all(header::CONTENT_TYPE).iter().collect();
        if types.len() != 1 || types[0].as_bytes() != media.as_bytes() {
            return Err(refused());
        }
        match route {
            Route::Prepare => {
                let signed: SignedPaidIntent =
                    decode_signed_paid_intent(&input.body).map_err(|_| refused())?;
                authenticate_paid_intent(&self.resolver, &self.context, &input.body)
                    .map_err(|_| refused())?;
                let vote: consensus::FastVote =
                    consensus::decode_fast_vote(&output.body).map_err(|_| refused())?;
                if vote.validator != self.identity.validator
                    || vote.tx_hash
                        != paid_invocation_digest(&self.resolver, &signed).map_err(|_| refused())?
                {
                    return Err(refused());
                }
                self.fast
                    .verify_vote(&vote, &Self::verifier())
                    .map_err(|_| refused())?;
            }
            Route::Apply | Route::PublishedApply => {
                let signed_bytes: Vec<u8> = if route == Route::Apply {
                    FastVoteApplyRequest::decode(&input.body)
                        .map_err(|_| refused())?
                        .signed_paid_intent
                } else {
                    FastVotePublishedApplyRequest::decode(&input.body)
                        .map_err(|_| refused())?
                        .signed_paid_intent
                };
                let signed: SignedPaidIntent =
                    decode_signed_paid_intent(&signed_bytes).map_err(|_| refused())?;
                // Deliberately no fixed/current epoch rejection: core receipt-
                // first replay must remain valid after the epoch advances.
                self.verify_paid_result(&output.body, signed.intent.request_id, Some(&signed))?;
            }
            Route::Source | Route::RetainedSource => {
                let bundle: consensus::bundle::PublicationBundle =
                    consensus::bundle::decode_publication_bundle(&output.body)
                        .map_err(|_| refused())?;
                self.verify_bundle(&bundle)?;
                if route == Route::Source {
                    let request: FastVoteApplyRequest =
                        FastVoteApplyRequest::decode(&input.body).map_err(|_| refused())?;
                    if bundle.signed_intent != request.signed_paid_intent
                        || bundle.certificate.tx_hash != request.certificate.tx_hash
                        || bundle.certificate.execution_effects_hash
                            != request.certificate.execution_effects_hash
                        || bundle.certificate.locked_objects_digest
                            != request.certificate.locked_objects_digest
                    {
                        return Err(refused());
                    }
                } else {
                    let request: RetainedPublicationSourceRequest =
                        RetainedPublicationSourceRequest::decode(&input.body)
                            .map_err(|_| refused())?;
                    if bundle.request_id != request.request_id
                        || bundle.certificate.epoch != request.epoch
                    {
                        return Err(refused());
                    }
                }
            }
            Route::Retain | Route::Import => {
                let bundle: consensus::bundle::PublicationBundle =
                    consensus::bundle::decode_publication_bundle(&input.body)
                        .map_err(|_| refused())?;
                let identity: consensus::AvailabilityIdentity = self.verify_bundle(&bundle)?;
                if route == Route::Retain {
                    let vote: consensus::AvailabilityVote =
                        consensus::decode_availability_vote(&output.body).map_err(|_| refused())?;
                    self.verify_availability_vote(&vote, &identity)?;
                } else if consensus::decode_availability_identity(&output.body)
                    .map_err(|_| refused())?
                    != identity
                {
                    return Err(refused());
                }
            }
            Route::FrontierAdvance => {
                let vote: consensus::FrozenFrontierVote =
                    consensus::decode_frozen_frontier_vote(&output.body).map_err(|_| refused())?;
                self.verify_frontier_vote(&vote, self.identity.validator)?;
            }
            Route::FrontierPage => {
                let request: FrozenFrontierPageRequest =
                    FrozenFrontierPageRequest::decode(&input.body).map_err(|_| refused())?;
                let envelope: FrozenFrontierPageResponse =
                    FrozenFrontierPageResponse::decode(&output.body).map_err(|_| refused())?;
                let vote: consensus::FrozenFrontierVote =
                    consensus::decode_frozen_frontier_vote(&envelope.vote)
                        .map_err(|_| refused())?;
                self.verify_frontier_vote(&vote, self.identity.validator)?;
                let page: consensus::FrozenFrontierPage =
                    consensus::decode_frozen_frontier_page(&envelope.page)
                        .map_err(|_| refused())?;
                if vote.identity.epoch != request.epoch
                    || page.after_request_id != request.after_request_id
                    || page.entries.len() > usize::from(request.limit)
                {
                    return Err(refused());
                }
            }
            Route::UnionAdvance => {
                let request: DrainUnionAdvanceRequest =
                    DrainUnionAdvanceRequest::decode(&input.body).map_err(|_| refused())?;
                let identity: consensus::DrainUnionIdentity =
                    consensus::decode_drain_union_identity(&output.body).map_err(|_| refused())?;
                let first: &consensus::FrozenFrontierVote =
                    request.votes.first().ok_or_else(refused)?;
                for vote in &request.votes {
                    self.verify_frontier_vote(vote, vote.validator)?;
                }
                if identity.chain_id != *self.context.chain_id()
                    || identity.protocol_version != self.context.protocol_version()
                    || identity.epoch != request.epoch
                    || identity.domain != self.identity.domain
                    || identity.closure_request_id != first.identity.closure_request_id
                    || identity.closure_height != first.identity.closure_height
                    || identity.signer_count
                        != u64::try_from(request.votes.len()).map_err(|_| refused())?
                {
                    return Err(refused());
                }
            }
            Route::SignerProgress => {
                let request: DrainSignerProgressRequest =
                    DrainSignerProgressRequest::decode(&input.body).map_err(|_| refused())?;
                let progress: DrainSignerProgressResponse =
                    DrainSignerProgressResponse::decode(&output.body).map_err(|_| refused())?;
                let vote: consensus::FrozenFrontierVote =
                    consensus::decode_frozen_frontier_vote(&progress.vote)
                        .map_err(|_| refused())?;
                self.verify_frontier_vote(&vote, request.signer)?;
                let identity: consensus::FrozenFrontierIdentity =
                    consensus::decode_frozen_frontier_identity(&progress.confirmed_identity)
                        .map_err(|_| refused())?;
                if progress.chain_id != self.context.chain_id().as_str()
                    || progress.epoch != request.epoch
                    || progress.signer != request.signer
                    || identity.chain_id != vote.identity.chain_id
                    || identity.protocol_version != vote.identity.protocol_version
                    || identity.epoch != vote.identity.epoch
                    || identity.domain != vote.identity.domain
                    || identity.closure_request_id != vote.identity.closure_request_id
                    || identity.closure_height != vote.identity.closure_height
                    || progress.complete && identity != vote.identity
                {
                    return Err(refused());
                }
                if let Some(page) = progress.staged_page {
                    consensus::decode_frozen_frontier_page(&page).map_err(|_| refused())?;
                }
            }
            Route::DrainApply => {
                let request: DrainMemberApplyRequest =
                    DrainMemberApplyRequest::decode(&input.body).map_err(|_| refused())?;
                self.verify_paid_result(&output.body, request.member_request_id, None)?;
            }
            Route::Context => {
                let context: HttpContextQueryResult =
                    HttpContextQueryResult::decode(&output.body).map_err(|_| refused())?;
                let config: protocol_config::ProtocolConfig = crate::resolve_query_protocol_config(
                    &self.resolver,
                    self.context.chain_id(),
                    self.context.protocol_version(),
                    context.epoch(),
                    &self.query_config,
                )
                .map_err(|_| refused())?;
                let profile: &protocol_config::TransactionAuthProfile =
                    protocol_config::resolve_transaction_auth_profile(&config)
                        .map_err(|_| refused())?;
                if context.chain_id() != self.context.chain_id()
                    || context.protocol_version() != self.context.protocol_version()
                    || context.domain() != self.identity.domain
                    || context.hash_suite_id() != config.hash_suite_id
                    || context.protocol_config_bytes()
                        != config.canonical_bytes().map_err(|_| refused())?
                    || context.transaction_auth_profile_id() != profile.profile_id()
                    || context.signature_scheme_id() != profile.signature_scheme_id().as_u16()
                    || context.address_binding_id() != profile.address_binding().as_u16()
                {
                    return Err(refused());
                }
            }
            Route::Object => {
                let result: HttpObjectQueryResult =
                    HttpObjectQueryResult::decode(&output.body).map_err(|_| refused())?;
                if result.object_id().as_bytes() != &input.selectors[0] {
                    return Err(refused());
                }
            }
            Route::Receipt => {
                let result: HttpReceiptQueryResult =
                    HttpReceiptQueryResult::decode(&output.body).map_err(|_| refused())?;
                if result.request_id().as_bytes() != &input.selectors[0] {
                    return Err(refused());
                }
            }
            Route::Nonce => {
                let result: HttpNextNonceQueryResult =
                    HttpNextNonceQueryResult::decode(&output.body).map_err(|_| refused())?;
                if result.sender().as_bytes() != &input.selectors[0] {
                    return Err(refused());
                }
            }
            Route::FeePolicy => {
                let policy: execution::paid_execution::PaidFeePolicy =
                    execution::paid_execution::decode_paid_fee_policy(&output.body)
                        .map_err(|_| refused())?;
                if policy.context.chain_id() != self.context.chain_id()
                    || policy.context.protocol_version() != self.context.protocol_version()
                {
                    return Err(refused());
                }
            }
            Route::Instance => {
                let record: execution::local_execution::InstanceRecord =
                    execution::local_execution::decode_instance_record(&output.body)
                        .map_err(|_| refused())?;
                if record.creator != input.selectors[0]
                    || record.seed != input.selectors[1]
                    || record.context.chain_id() != self.context.chain_id()
                {
                    return Err(refused());
                }
            }
            Route::Publication => {
                let result: execution::publication::PublicationQueryResult =
                    execution::publication::decode_publication_query_result(&output.body)
                        .map_err(|_| refused())?;
                let origin: &abi::package_types::PackageOrigin = match &result {
                    execution::publication::PublicationQueryResult::Legacy(submission) => {
                        submission.request().artifact().origin()
                    }
                    execution::publication::PublicationQueryResult::Paid(signed) => {
                        match &signed.intent.application {
                            PaidApplication::Publish(artifact) => artifact.origin(),
                            _ => return Err(refused()),
                        }
                    }
                };
                if origin.chain_id() != self.context.chain_id()
                    || origin.publisher() != &input.selectors[0]
                    || origin.seed() != &input.selectors[1]
                {
                    return Err(refused());
                }
            }
            Route::Live | Route::SignerPage | Route::MemberConfirm => return Err(refused()),
        }
        Ok(())
    }
}
