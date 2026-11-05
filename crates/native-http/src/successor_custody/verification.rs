//! Public response checks only. These checks never attest to a live warrant,
//! retained state, an unsigned outcome, or a partial frozen-frontier page.
use super::*;
use consensus::{
    AvailabilityCertifier, ConsensusMessage, Ed25519ConsensusVerifier, FastPathCertifier,
    FrozenFrontierCertifier, UnsupportedSignatureSchemeResponse,
};
use execution::{
    paid_execution::{authenticate_paid_intent, decode_signed_paid_intent, paid_invocation_digest},
    publication::PublicationContext,
};
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, decode_ordered_candidate, decode_ordered_event_output,
    decode_ordered_proposal,
};
use node_wire::ordered_economics::*;

pub(super) struct PublicEvidence {
    validator: ValidatorId,
    context: PublicationContext,
    domain: protocol_types::AtomicityDomainId,
    resolver: HashSuiteResolver,
    query_config: protocol_config::ProtocolConfig,
    ordered: OrderedEconomicsPolicy,
    fast: FastPathCertifier,
    availability: AvailabilityCertifier,
    frontier: FrozenFrontierCertifier,
}
impl PublicEvidence {
    pub(super) fn new(
        validator: ValidatorId,
        root: &VerifiedGenesisRoot,
        verified: &VerifiedSuccessorAuthority,
        resolver: HashSuiteResolver,
        query_config: protocol_config::ProtocolConfig,
    ) -> io::Result<Self> {
        let context: PublicationContext = verified.policy_inputs().context().clone();
        let domain: protocol_types::AtomicityDomainId = verified.policy_inputs().domain();
        if resolver.chain_id() != context.chain_id()
            || resolver.protocol_version() != context.protocol_version()
            || resolver.schedules() != root.genesis_resolver().schedules()
            || verified.validator_set().get(validator).is_none()
            || root.digest() != verified.policy_inputs().genesis_digest()
        {
            return Err(refused());
        }
        let committee = verified.validator_set().clone();
        let ordered: OrderedEconomicsPolicy =
            verified.ordered_policy(root).map_err(|_| refused())?;
        let fast: FastPathCertifier = FastPathCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            committee.clone(),
        )
        .map_err(|_| refused())?;
        let availability: AvailabilityCertifier = AvailabilityCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            committee.clone(),
        )
        .map_err(|_| refused())?;
        let frontier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            committee,
        )
        .map_err(|_| refused())?;
        Ok(Self {
            validator,
            context,
            domain,
            resolver,
            query_config,
            ordered,
            fast,
            availability,
            frontier,
        })
    }
    fn verifier() -> Ed25519ConsensusVerifier {
        Ed25519ConsensusVerifier::new(UnsupportedSignatureSchemeResponse::InvalidSignature)
    }
    fn one_media(output: &Output, expected: &str) -> io::Result<()> {
        let headers: HeaderMap = header_map(&output.headers)?;
        let values: Vec<&HeaderValue> = headers
            .get_all(axum::http::header::CONTENT_TYPE)
            .iter()
            .collect();
        if values.len() != 1 || values[0].as_bytes() != expected.as_bytes() {
            return Err(refused());
        }
        Ok(())
    }
    fn verify_proposal(&self, input: &Input, bytes: &[u8]) -> io::Result<()> {
        let proposal = decode_ordered_proposal(bytes).map_err(|_| refused())?;
        if proposal.proposal.leader != self.validator {
            return Err(refused());
        }
        self.ordered
            .engine()
            .verify_proposal(&proposal.proposal, &Self::verifier())
            .map_err(|_| refused())?;
        match &proposal.candidate {
            Some(candidate) => {
                self.ordered
                    .authenticate_candidate(candidate)
                    .map_err(|_| refused())?;
                let digest = self
                    .ordered
                    .candidate_digest(candidate)
                    .map_err(|_| refused())?;
                if proposal.proposal.transactions.as_slice() != [digest] {
                    return Err(refused());
                }
            }
            None if !proposal.proposal.transactions.is_empty() => return Err(refused()),
            None => {}
        }
        if input.uri.path() == ORDERED_ECONOMICS_PROPOSE_PATH {
            let request = OrderedProposeRequest::decode(&input.body).map_err(|_| refused())?;
            let expected = request
                .candidate
                .as_deref()
                .map(decode_ordered_candidate)
                .transpose()
                .map_err(|_| refused())?;
            if expected != proposal.candidate {
                return Err(refused());
            }
        }
        Ok(())
    }
    fn verify_ordered_event(&self, bytes: &[u8]) -> io::Result<()> {
        let event = decode_ordered_event_output(bytes).map_err(|_| refused())?;
        for message in &event.messages {
            match message {
                ConsensusMessage::Proposal(proposal) => {
                    if proposal.leader != self.validator {
                        return Err(refused());
                    }
                    self.ordered
                        .engine()
                        .verify_proposal(proposal, &Self::verifier())
                        .map_err(|_| refused())?;
                }
                ConsensusMessage::Vote(vote) => {
                    if vote.validator != self.validator {
                        return Err(refused());
                    }
                    self.ordered
                        .engine()
                        .verify_vote(vote, &Self::verifier())
                        .map_err(|_| refused())?;
                }
                ConsensusMessage::Certificate(certificate) => self
                    .ordered
                    .engine()
                    .verify_certificate(certificate, &Self::verifier())
                    .map_err(|_| refused())?,
            }
        }
        // `event.committed` is deliberately not treated as a signed proof.
        Ok(())
    }
    fn verify_fastvote(&self, input: &Input, output: &Output) -> io::Result<()> {
        let signed = decode_signed_paid_intent(&input.body).map_err(|_| refused())?;
        authenticate_paid_intent(&self.resolver, &self.context, &input.body)
            .map_err(|_| refused())?;
        let vote = consensus::decode_fast_vote(&output.body).map_err(|_| refused())?;
        if vote.validator != self.validator
            || vote.tx_hash
                != paid_invocation_digest(&self.resolver, &signed).map_err(|_| refused())?
        {
            return Err(refused());
        }
        self.fast
            .verify_vote(&vote, &Self::verifier())
            .map_err(|_| refused())
    }
    fn verify_bundle(
        &self,
        bundle: &consensus::bundle::PublicationBundle,
    ) -> io::Result<consensus::AvailabilityIdentity> {
        let verified = consensus::bundle::verify_publication_bundle(
            bundle,
            &self.fast,
            &Self::verifier(),
            &self.resolver,
            &[],
        )
        .map_err(|_| refused())?;
        authenticate_paid_intent(&self.resolver, &self.context, &bundle.signed_intent)
            .map_err(|_| refused())?;
        if bundle.domain != self.domain {
            return Err(refused());
        }
        Ok(verified.identity)
    }
    fn verify_retention(&self, input: &Input, output: &Output) -> io::Result<()> {
        let bundle =
            consensus::bundle::decode_publication_bundle(&input.body).map_err(|_| refused())?;
        let identity = self.verify_bundle(&bundle)?;
        let vote = consensus::decode_availability_vote(&output.body).map_err(|_| refused())?;
        if vote.validator != self.validator || vote.identity != identity {
            return Err(refused());
        }
        self.availability
            .verify_vote(&vote, &Self::verifier())
            .map_err(|_| refused())
    }
    fn verify_source(&self, input: &Input, output: &Output) -> io::Result<()> {
        let bundle =
            consensus::bundle::decode_publication_bundle(&output.body).map_err(|_| refused())?;
        self.verify_bundle(&bundle)?;
        if input.uri.path() == node_wire::FASTVOTE_PUBLICATION_SOURCE_PATH {
            let request =
                node_wire::FastVoteApplyRequest::decode(&input.body).map_err(|_| refused())?;
            let certificate =
                consensus::decode_fast_certificate(&request.certificate).map_err(|_| refused())?;
            if bundle.signed_intent != request.signed_paid_intent
                || bundle.certificate.tx_hash != certificate.tx_hash
                || bundle.certificate.execution_effects_hash != certificate.execution_effects_hash
                || bundle.certificate.locked_objects_digest != certificate.locked_objects_digest
            {
                return Err(refused());
            }
        } else {
            let request = node_wire::RetainedPublicationSourceRequest::decode(&input.body)
                .map_err(|_| refused())?;
            if bundle.request_id != request.request_id || bundle.certificate.epoch != request.epoch
            {
                return Err(refused());
            }
        }
        Ok(())
    }
    fn verify_frontier_vote(&self, bytes: &[u8]) -> io::Result<()> {
        let vote = consensus::decode_frozen_frontier_vote(bytes).map_err(|_| refused())?;
        if vote.validator != self.validator || vote.identity.domain != self.domain {
            return Err(refused());
        }
        self.frontier
            .verify_vote(&vote, &Self::verifier())
            .map_err(|_| refused())
    }
    fn verify_frontier_page(&self, input: &Input, output: &Output) -> io::Result<()> {
        let request =
            node_wire::FrozenFrontierPageRequest::decode(&input.body).map_err(|_| refused())?;
        let response =
            node_wire::FrozenFrontierPageResponse::decode(&output.body).map_err(|_| refused())?;
        let vote = consensus::decode_frozen_frontier_vote(&response.vote).map_err(|_| refused())?;
        let page = consensus::decode_frozen_frontier_page(&response.page).map_err(|_| refused())?;
        if vote.validator != self.validator
            || vote.identity.domain != self.domain
            || vote.identity.epoch != request.epoch
            || page.after_request_id != request.after_request_id
            || page.entries.len() > usize::from(request.limit)
        {
            return Err(refused());
        }
        self.frontier
            .verify_vote(&vote, &Self::verifier())
            .map_err(|_| refused())?;
        // A single page is not authenticated by the vote. Only a caller-owned
        // complete stream can reproduce the terminal signed digest.
        Ok(())
    }
    fn verify_signer_progress(&self, input: &Input, output: &Output) -> io::Result<()> {
        let request =
            node_wire::DrainSignerProgressRequest::decode(&input.body).map_err(|_| refused())?;
        let progress =
            node_wire::DrainSignerProgressResponse::decode(&output.body).map_err(|_| refused())?;
        let vote = consensus::decode_frozen_frontier_vote(&progress.vote).map_err(|_| refused())?;
        if vote.validator != request.signer
            || vote.identity.domain != self.domain
            || vote.identity.epoch != request.epoch
            || progress.epoch != request.epoch
            || progress.signer != request.signer
        {
            return Err(refused());
        }
        self.frontier
            .verify_vote(&vote, &Self::verifier())
            .map_err(|_| refused())?;
        Ok(())
    }
    pub(super) fn verify(&self, input: &Input, output: &Output) -> io::Result<()> {
        if output.status.is_success()
            && !crate::successor::permits_success(&input.method, input.uri.path())
        {
            return Err(refused());
        }
        if output.status == StatusCode::NO_CONTENT {
            if !output.body.is_empty() {
                return Err(refused());
            }
            return Ok(());
        }
        if output.status != StatusCode::OK {
            return if output.status.is_client_error() || output.status.is_server_error() {
                Ok(())
            } else {
                Err(refused())
            };
        }
        match (input.method.clone(), input.uri.path()) {
            (Method::POST, ORDERED_ECONOMICS_PROPOSE_PATH) => {
                let headers = header_map(&output.headers)?;
                let media = headers
                    .get(axum::http::header::CONTENT_TYPE)
                    .ok_or_else(refused)?;
                if media.as_bytes() == ORDERED_PROPOSAL_MEDIA_TYPE.as_bytes() {
                    Self::one_media(output, ORDERED_PROPOSAL_MEDIA_TYPE)?;
                    self.verify_proposal(input, &output.body)
                } else {
                    Self::one_media(output, ORDERED_EVENT_OUTPUT_MEDIA_TYPE)?;
                    self.verify_ordered_event(&output.body)
                }
            }
            (
                Method::POST,
                ORDERED_ECONOMICS_PROPOSAL_PATH
                | ORDERED_ECONOMICS_CERTIFICATE_PATH
                | ORDERED_ECONOMICS_OBSERVE_PATH
                | ORDERED_ECONOMICS_TICK_PATH,
            ) => {
                Self::one_media(output, ORDERED_EVENT_OUTPUT_MEDIA_TYPE)?;
                self.verify_ordered_event(&output.body)
            }
            (Method::POST, node_wire::FASTVOTE_PREPARE_PATH) => {
                Self::one_media(output, node_wire::NODE_RESULT_MEDIA_TYPE)?;
                self.verify_fastvote(input, output)
            }
            (Method::POST, node_wire::FASTVOTE_PUBLICATION_RETAIN_PATH) => {
                Self::one_media(output, node_wire::NODE_RESULT_MEDIA_TYPE)?;
                self.verify_retention(input, output)
            }
            (
                Method::POST,
                node_wire::FASTVOTE_PUBLICATION_SOURCE_PATH
                | node_wire::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
            ) => {
                Self::one_media(output, node_wire::NODE_RESULT_MEDIA_TYPE)?;
                self.verify_source(input, output)
            }
            (Method::POST, node_wire::FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH) => {
                Self::one_media(output, node_wire::NODE_RESULT_MEDIA_TYPE)?;
                self.verify_frontier_vote(&output.body)
            }
            (Method::POST, node_wire::FASTVOTE_FROZEN_FRONTIER_PAGE_PATH) => {
                Self::one_media(output, node_wire::NODE_RESULT_MEDIA_TYPE)?;
                self.verify_frontier_page(input, output)
            }
            (Method::POST, node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH) => {
                Self::one_media(output, node_wire::NODE_RESULT_MEDIA_TYPE)?;
                self.verify_signer_progress(input, output)
            }
            (Method::GET, ORDERED_ECONOMICS_STATUS_PATH) => {
                Self::one_media(output, ORDERED_STATUS_MEDIA_TYPE)?;
                let status = node_core::ordered_economics::decode_ordered_status(&output.body)
                    .map_err(|_| refused())?;
                self.ordered
                    .engine()
                    .verify_certificate(&status.high_qc, &Self::verifier())
                    .map_err(|_| refused())
            }
            (Method::GET, node_wire::QUERY_CONTEXT_PATH) => {
                Self::one_media(output, node_wire::QUERY_RESULT_MEDIA_TYPE)?;
                let query = node_wire::HttpContextQueryResult::decode(&output.body)
                    .map_err(|_| refused())?;
                let config: protocol_config::ProtocolConfig = crate::resolve_query_protocol_config(
                    &self.resolver,
                    self.context.chain_id(),
                    self.context.protocol_version(),
                    query.epoch(),
                    &self.query_config,
                )
                .map_err(|_| refused())?;
                let profile = protocol_config::resolve_transaction_auth_profile(&config)
                    .map_err(|_| refused())?;
                if query.chain_id() != self.context.chain_id()
                    || query.protocol_version() != self.context.protocol_version()
                    || query.epoch() != self.context.epoch()
                    || query.domain() != self.domain
                    || query.hash_suite_id() != config.hash_suite_id
                    || query.protocol_config_bytes()
                        != config.canonical_bytes().map_err(|_| refused())?
                    || query.transaction_auth_profile_id() != profile.profile_id()
                    || query.signature_scheme_id() != profile.signature_scheme_id().as_u16()
                    || query.address_binding_id() != profile.address_binding().as_u16()
                {
                    return Err(refused());
                }
                Ok(())
            }
            // The remaining successful payloads are worker-owned observations,
            // never promoted to independently signed commitment proofs.
            _ => Ok(()),
        }
    }
}
