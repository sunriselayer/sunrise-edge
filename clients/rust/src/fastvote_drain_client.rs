//! Bounded, locally pinned transport for DR-0168 post-Freeze member drain.
//!
//! Progress calls stage/confirm local possession and reconstruct its union;
//! explicit member application additionally requires the host's committed
//! DrainSet. An HTTP response is not an ordered DrainSet decision, a portable
//! cut, or permission to activate the next epoch. The endpoint rechecks its
//! authority; this client checks signatures and exact response identities.

use std::time::Instant;

use consensus::bundle::{PublicationBundle, encode_publication_bundle};
use consensus::{
    AvailabilityIdentity, DrainUnionIdentity, FastPathCertifier, FrozenFrontierAccumulator,
    FrozenFrontierCertifier, FrozenFrontierIdentity, FrozenFrontierPage, FrozenFrontierVote,
    decode_availability_identity, decode_drain_union_identity, decode_frozen_frontier_identity,
    decode_frozen_frontier_page, decode_frozen_frontier_vote, encode_frozen_frontier_page,
    encode_frozen_frontier_vote, verify_frozen_frontier_quorum,
};
use execution::paid_execution::{
    PaidExecutionResult, SignedPaidIntent, authenticate_paid_intent, decode_signed_paid_intent,
    encode_paid_execution_result, encode_signed_paid_intent, paid_invocation_digest,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::fast_path::drain_publication::verify_drain_publication_bundle;
use node_core::ordered_economics::DrainSignerProgress;
use node_wire::{
    DrainMemberApplyRequest, DrainMemberConfirmRequest, DrainSignerPageRequest,
    DrainSignerProgressRequest, DrainSignerProgressResponse, DrainUnionAdvanceRequest,
    FASTVOTE_DRAIN_APPLY_PATH, FASTVOTE_DRAIN_IMPORT_PATH, FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
    FASTVOTE_DRAIN_SIGNER_PAGE_PATH, FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
    FASTVOTE_DRAIN_UNION_ADVANCE_PATH, FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
    NODE_EVENT_MEDIA_TYPE, NODE_RESULT_MEDIA_TYPE, RetainedPublicationSourceRequest,
};
use protocol_types::{AtomicityDomainId, ValidatorId};

use crate::Client;
use crate::FastPathEd25519Verifier;
use crate::client::expect_success;
use crate::error::ClientError;
use crate::transport::{Method, Transport, WireRequest, WireResponse};

/// The caller's expected committed Freeze, separate from TLS endpoint
/// validation and never inferred from an HTTP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedDrainFreeze {
    pub domain: AtomicityDomainId,
    pub closure_request_id: [u8; 32],
    pub closure_height: u64,
}

/// Authenticates the signed request and checks its complete canonical response
/// binding, including accepted or charged-trap receipt status. This is not
/// certificate verification: the apply methods additionally require exact
/// agreement with the independently verified retained certificate witness.
pub fn validate_drain_member_output(
    signed: &SignedPaidIntent,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    bytes: &[u8],
) -> Result<PaidExecutionResult, ClientError> {
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(signed)?;
    authenticate_paid_intent(resolver, expected, &signed_bytes)?;
    crate::fastvote_client::validate_fastvote_apply_response(signed, resolver, bytes)
}

fn expect_no_content(response: WireResponse) -> Result<(), ClientError> {
    if response.status != 204 {
        return Err(ClientError::UnexpectedStatus {
            status: response.status,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        });
    }
    if !response.body.is_empty() {
        return Err(ClientError::DrainMismatch(
            "no-content drain response carried a body",
        ));
    }
    Ok(())
}

fn validator_path(validator: ValidatorId) -> String {
    let mut hex: String = String::with_capacity(64);
    for byte in validator.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    FASTVOTE_DRAIN_IMPORT_PATH.replacen("{validator_id}", &hex, 1)
}

impl<T: Transport> Client<T> {
    /// Applies one member only after the server independently proves its own
    /// committed DrainSet membership and retained full certificate. The wire
    /// request contains only a locator; the locally supplied original signed
    /// intent is independently authenticated and matched to the target's
    /// verified retained certificate/witness before mutation, then binds the
    /// returned original canonical result. A transport connection is not
    /// a protocol-context pin: `expected` must come from local configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_drain_member(
        &self,
        signed: &SignedPaidIntent,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        expected: &PublicationContext,
        domain: AtomicityDomainId,
        deadline: Option<Instant>,
    ) -> Result<PaidExecutionResult, ClientError> {
        self.apply_drain_member_output(
            signed, certifier, resolver, history, expected, domain, deadline,
        )
        .map(|(result, _)| result)
    }

    /// Returns the authenticated paid result together with the exact full
    /// original HttpNodeResult bytes. Callers must retain these bytes, rather
    /// than reconstructing a smaller receipt or a fresh replay response.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_drain_member_output(
        &self,
        signed: &SignedPaidIntent,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        expected: &PublicationContext,
        domain: AtomicityDomainId,
        deadline: Option<Instant>,
    ) -> Result<(PaidExecutionResult, Vec<u8>), ClientError> {
        self.apply_drain_member_output_with_saved(
            signed, certifier, resolver, history, expected, domain, None, deadline,
        )
    }

    /// As above, but authenticates exact saved original output against the
    /// freshly verified certificate witness before any member mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_drain_member_output_with_saved(
        &self,
        signed: &SignedPaidIntent,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        expected: &PublicationContext,
        domain: AtomicityDomainId,
        saved: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<(PaidExecutionResult, Vec<u8>), ClientError> {
        let signed_bytes: Vec<u8> = encode_signed_paid_intent(signed)?;
        authenticate_paid_intent(resolver, expected, &signed_bytes)?;
        let bundle: PublicationBundle = self.source_retained_drain_member(
            signed, certifier, resolver, history, expected, domain, deadline,
        )?;
        let (event_digest, certified_result): (protocol_types::Digest32, PaidExecutionResult) =
            node_core::fast_path::publication::decode_certified_execution_witness(&bundle.witness)?;
        let tx_hash: protocol_types::Digest32 = paid_invocation_digest(resolver, signed)?;
        if event_digest != tx_hash
            || certified_result.effects.tx_hash != tx_hash
            || certified_result.request_id != signed.intent.request_id
        {
            return Err(ClientError::DrainMismatch(
                "certified witness differs from original member",
            ));
        }
        crate::paid_execution_client::validate_paid_execution_target(
            &signed.intent.application,
            &certified_result,
            resolver,
        )?;
        let certified_bytes: Vec<u8> = encode_paid_execution_result(&certified_result)?;
        if let Some(bytes) = saved {
            let original: PaidExecutionResult =
                validate_drain_member_output(signed, resolver, expected, bytes)?;
            if encode_paid_execution_result(&original)? != certified_bytes {
                return Err(ClientError::DrainMismatch(
                    "saved original differs from certified witness",
                ));
            }
        }
        let body: Vec<u8> = DrainMemberApplyRequest {
            epoch: expected.epoch(),
            member_request_id: signed.intent.request_id,
        }
        .encode()?;
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_DRAIN_APPLY_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        let response_body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let result: PaidExecutionResult =
            validate_drain_member_output(signed, resolver, expected, &response_body)?;
        if encode_paid_execution_result(&result)? != certified_bytes {
            return Err(ClientError::DrainMismatch(
                "member result differs from certified original witness",
            ));
        }
        Ok((result, response_body))
    }

    /// Sources one member's complete retained certificate/material without
    /// accepting a peer-selected identity as authority. The exact supplied
    /// original signed bytes, locally pinned domain/context and quorum are
    /// checked independently before this can authorize a member POST.
    #[allow(clippy::too_many_arguments)]
    pub fn source_retained_drain_member(
        &self,
        signed: &SignedPaidIntent,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        expected: &PublicationContext,
        domain: AtomicityDomainId,
        deadline: Option<Instant>,
    ) -> Result<PublicationBundle, ClientError> {
        let signed_bytes: Vec<u8> = encode_signed_paid_intent(signed)?;
        authenticate_paid_intent(resolver, expected, &signed_bytes)?;
        if certifier.chain_id() != expected.chain_id()
            || certifier.protocol_version() != expected.protocol_version()
            || certifier.epoch() != expected.epoch()
        {
            return Err(ClientError::DrainMismatch(
                "member committee differs from local context pin",
            ));
        }
        let body: Vec<u8> = RetainedPublicationSourceRequest {
            epoch: expected.epoch(),
            request_id: signed.intent.request_id,
        }
        .encode()?;
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        let bytes: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let bundle: PublicationBundle = consensus::bundle::decode_publication_bundle(&bytes)?;
        if bundle.domain != domain
            || bundle.request_id != signed.intent.request_id
            || bundle.signed_intent != signed_bytes
        {
            return Err(ClientError::DrainMismatch(
                "retained member differs from exact signed input or domain",
            ));
        }
        verify_drain_publication_bundle(resolver, history, expected, domain, certifier, &bundle)?;
        let tx_hash: protocol_types::Digest32 = paid_invocation_digest(resolver, signed)?;
        if bundle.certificate.tx_hash != tx_hash {
            return Err(ClientError::DrainMismatch(
                "retained member certificate has a different original digest",
            ));
        }
        Ok(bundle)
    }

    /// Reads one bounded durable signer-progress snapshot. A pristine row is
    /// represented by `None` only for the exact `drain-progress-pristine`
    /// response;
    /// epoch re-pin, corrupt state and storage failures remain errors. The
    /// response is checked against the caller's *local* resolver, outgoing
    /// committee, endpoint signer and committed Freeze expectation. It is a
    /// scheduling hint, never an authority for an ACK, cut or DrainSet vote.
    pub fn read_drain_signer_progress(
        &self,
        certifier: &FrozenFrontierCertifier,
        expected_signer: ValidatorId,
        freeze: ExpectedDrainFreeze,
        resolver: &HashSuiteResolver,
        deadline: Option<Instant>,
    ) -> Result<Option<DrainSignerProgress>, ClientError> {
        let request: DrainSignerProgressRequest = DrainSignerProgressRequest {
            epoch: certifier.epoch(),
            signer: expected_signer,
        };
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: request.encode()?,
            deadline,
        })?;
        if response.status == 409 && response.body == b"drain-progress-pristine" {
            return Ok(None);
        }
        let body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let envelope: DrainSignerProgressResponse = DrainSignerProgressResponse::decode(&body)?;
        if envelope.chain_id != resolver.chain_id().as_str()
            || envelope.epoch != certifier.epoch()
            || envelope.signer != expected_signer
        {
            return Err(ClientError::DrainMismatch(
                "progress envelope differs from local chain, epoch or signer",
            ));
        }
        let vote: FrozenFrontierVote = decode_frozen_frontier_vote(&envelope.vote)?;
        if vote.validator != expected_signer
            || vote.identity.chain_id != *resolver.chain_id()
            || vote.identity.protocol_version != resolver.protocol_version()
            || vote.identity.epoch != certifier.epoch()
            || vote.identity.domain != freeze.domain
            || vote.identity.closure_request_id != freeze.closure_request_id
            || vote.identity.closure_height != freeze.closure_height
        {
            return Err(ClientError::DrainMismatch(
                "progress vote differs from local signer, resolver or Freeze",
            ));
        }
        certifier.verify_vote(&vote, &FastPathEd25519Verifier)?;
        let confirmed_identity: FrozenFrontierIdentity =
            decode_frozen_frontier_identity(&envelope.confirmed_identity)?;
        if confirmed_identity.chain_id != vote.identity.chain_id
            || confirmed_identity.protocol_version != vote.identity.protocol_version
            || confirmed_identity.epoch != vote.identity.epoch
            || confirmed_identity.domain != vote.identity.domain
            || confirmed_identity.closure_request_id != vote.identity.closure_request_id
            || confirmed_identity.closure_height != vote.identity.closure_height
            || confirmed_identity.entry_count > vote.identity.entry_count
        {
            return Err(ClientError::DrainMismatch(
                "progress accumulator differs from signed frontier context or count",
            ));
        }
        FrozenFrontierAccumulator::resume(resolver, confirmed_identity.clone(), envelope.cursor)?;
        let staged_page: Option<FrozenFrontierPage> = envelope
            .staged_page
            .as_deref()
            .map(decode_frozen_frontier_page)
            .transpose()?;
        if envelope.complete {
            if confirmed_identity != vote.identity || staged_page.is_some() {
                return Err(ClientError::DrainMismatch(
                    "complete progress differs from signed terminal frontier",
                ));
            }
        } else if let Some(page) = &staged_page
            && (page.entries.is_empty()
                || (envelope.cursor.is_none() && page.after_request_id.is_some())
                || page
                    .after_request_id
                    .is_some_and(|prior| envelope.cursor.is_some_and(|cursor| prior > cursor))
                || !page.entries.iter().any(|entry| {
                    envelope
                        .cursor
                        .is_none_or(|cursor| entry.request_id > cursor)
                }))
        {
            return Err(ClientError::DrainMismatch(
                "staged progress page has no consecutive pending member",
            ));
        }
        Ok(Some(DrainSignerProgress {
            signer: expected_signer,
            vote,
            confirmed_identity,
            confirmed_last_request_id: envelope.cursor,
            staged_page,
            complete: envelope.complete,
        }))
    }

    /// Stages one signed, consecutive page on the target. A valid signature
    /// and endpoint mapping are checked locally; the target independently
    /// fences its installed Freeze and verifies the page before durable CAS.
    pub fn stage_drain_signer_page(
        &self,
        certifier: &FrozenFrontierCertifier,
        expected_signer: ValidatorId,
        freeze: ExpectedDrainFreeze,
        vote: &FrozenFrontierVote,
        page: &FrozenFrontierPage,
        deadline: Option<Instant>,
    ) -> Result<(), ClientError> {
        if vote.validator != expected_signer {
            return Err(ClientError::DrainMismatch(
                "frontier vote signer differs from configured source",
            ));
        }
        if vote.identity.domain != freeze.domain
            || vote.identity.closure_request_id != freeze.closure_request_id
            || vote.identity.closure_height != freeze.closure_height
        {
            return Err(ClientError::DrainMismatch(
                "frontier vote differs from expected committed Freeze",
            ));
        }
        certifier.verify_vote(vote, &FastPathEd25519Verifier)?;
        let body: Vec<u8> = DrainSignerPageRequest {
            epoch: certifier.epoch(),
            vote: encode_frozen_frontier_vote(vote)?,
            page: encode_frozen_frontier_page(page)?,
        }
        .encode()?;
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_DRAIN_SIGNER_PAGE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        expect_no_content(response)
    }

    /// Imports one exact full publication that this target's staged signer
    /// page must already identify. The supplied bundle is independently
    /// authenticated against the caller's pinned outgoing committee before
    /// any POST; the target derives its expected identity from its own page.
    #[allow(clippy::too_many_arguments)]
    pub fn import_staged_drain_publication(
        &self,
        source_signer: ValidatorId,
        bundle: &PublicationBundle,
        expected_identity: &AvailabilityIdentity,
        certifier: &FastPathCertifier,
        resolver: &HashSuiteResolver,
        history: &[HashSuiteResolver],
        deadline: Option<Instant>,
    ) -> Result<(), ClientError> {
        if certifier.validator_set().get(source_signer).is_none() {
            return Err(ClientError::DrainMismatch(
                "source signer is absent from the pinned outgoing set",
            ));
        }
        let expected_context: PublicationContext = PublicationContext::new(
            certifier.chain_id().clone(),
            certifier.protocol_version(),
            certifier.epoch(),
        )?;
        let identity: AvailabilityIdentity = verify_drain_publication_bundle(
            resolver,
            history,
            &expected_context,
            expected_identity.domain,
            certifier,
            bundle,
        )?;
        if identity != *expected_identity {
            return Err(ClientError::DrainMismatch(
                "bundle differs from signed frontier member",
            ));
        }
        authenticate_paid_intent(resolver, &expected_context, &bundle.signed_intent)?;
        let signed = decode_signed_paid_intent(&bundle.signed_intent)?;
        let signed_digest = paid_invocation_digest(resolver, &signed)?;
        if signed_digest != bundle.certificate.tx_hash
            || signed_digest != expected_identity.signed_intent_digest
            || signed.intent.request_id != expected_identity.request_id
        {
            return Err(ClientError::DrainMismatch(
                "bundle signed intent differs from frontier member",
            ));
        }
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: validator_path(source_signer),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: encode_publication_bundle(bundle)?,
            deadline,
        })?;
        let body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let observed: AvailabilityIdentity = decode_availability_identity(&body)?;
        if observed != *expected_identity {
            return Err(ClientError::DrainMismatch(
                "import acknowledgement differs from frontier member",
            ));
        }
        Ok(())
    }

    /// Confirms the exact pending request ID after its full proof was
    /// durably imported. The server checks the request ID in its CAS read
    /// set; this call does not accept a response for a different member.
    pub fn confirm_drain_member(
        &self,
        epoch: protocol_types::Epoch,
        signer: ValidatorId,
        request_id: [u8; 32],
        deadline: Option<Instant>,
    ) -> Result<(), ClientError> {
        let body: Vec<u8> = DrainMemberConfirmRequest {
            epoch,
            validator: signer,
            request_id,
        }
        .encode()?;
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        expect_no_content(response)
    }

    /// Advances at most one locally durable union member. `None` is a 204
    /// progress response, never evidence of readiness. `Some` is the
    /// target's selection-scoped local-ready claim, checked for context and
    /// shape but not independently proven by this untrusted HTTP response;
    /// a future ordered voter must re-read the matching marker under CAS.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_drain_union(
        &self,
        certifier: &FrozenFrontierCertifier,
        selected_votes: &[FrozenFrontierVote],
        freeze: ExpectedDrainFreeze,
        deadline: Option<Instant>,
    ) -> Result<Option<DrainUnionIdentity>, ClientError> {
        verify_frozen_frontier_quorum(
            certifier,
            selected_votes,
            freeze.domain,
            freeze.closure_request_id,
            freeze.closure_height,
            &FastPathEd25519Verifier,
        )?;
        let request: DrainUnionAdvanceRequest = DrainUnionAdvanceRequest {
            epoch: certifier.epoch(),
            votes: selected_votes.to_vec(),
        };
        let response: WireResponse = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_DRAIN_UNION_ADVANCE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: request.encode()?,
            deadline,
        })?;
        if response.status == 204 {
            expect_no_content(response)?;
            return Ok(None);
        }
        let body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let identity: DrainUnionIdentity = decode_drain_union_identity(&body)?;
        let selected_count: u64 = u64::try_from(selected_votes.len())
            .map_err(|_| ClientError::DrainMismatch("selected signer count overflow"))?;
        let minimum_members: u64 = selected_votes
            .iter()
            .map(|vote| vote.identity.entry_count)
            .max()
            .unwrap_or(0);
        let expected: &consensus::FrozenFrontierIdentity = &selected_votes
            .first()
            .ok_or(ClientError::DrainMismatch("no selected frontier votes"))?
            .identity;
        if identity.chain_id != expected.chain_id
            || identity.protocol_version != expected.protocol_version
            || identity.epoch != certifier.epoch()
            || identity.domain != freeze.domain
            || identity.closure_request_id != freeze.closure_request_id
            || identity.closure_height != freeze.closure_height
            || identity.signer_count != selected_count
            || identity.member_count < minimum_members
        {
            return Err(ClientError::DrainMismatch(
                "ready identity disagrees with locally selected Freeze",
            ));
        }
        Ok(Some(identity))
    }
}

#[cfg(test)]
pub(crate) mod closure_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::key::LocalSigner;
    use consensus::{ConsensusSigner, FrozenFrontierAccumulator};
    use crypto::SignatureSigner;
    use ed25519_zebra::{SigningKey, VerificationKey};
    use execution::call::{CallIntent, InstanceTarget};
    use execution::paid_execution::{
        FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind,
        paid_intent_signing_frame,
    };
    use execution::publication::UnverifiedDependencyRef;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
        SignatureSchemeId,
    };
    use std::cell::{Cell, RefCell};
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
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            let bytes: [u8; 64] = self.key.sign(framed).into();
            Ok(bytes.to_vec())
        }
    }

    struct FixedTransport {
        response: WireResponse,
        calls: Cell<u32>,
        last_request: RefCell<Option<WireRequest>>,
    }

    impl Transport for FixedTransport {
        fn send(
            &self,
            request: &WireRequest,
        ) -> Result<WireResponse, crate::transport::TransportError> {
            assert_eq!(request.method, Method::Post);
            self.calls.set(self.calls.get() + 1);
            self.last_request.replace(Some(request.clone()));
            Ok(self.response.clone())
        }
    }

    fn fixture() -> (
        HashSuiteResolver,
        FrozenFrontierCertifier,
        FrozenFrontierVote,
        ValidatorId,
        AtomicityDomainId,
    ) {
        let chain: ChainId = ChainId::new("drain-client-test").unwrap();
        let version: ProtocolVersion = ProtocolVersion::new(4);
        let epoch: Epoch = Epoch::new(8);
        let key: SigningKey = SigningKey::from([0x42; 32]);
        let verification: VerificationKey = (&key).into();
        let id_bytes: [u8; 32] = verification.into();
        let signer: Signer = Signer {
            id: ValidatorId::new(id_bytes),
            key,
        };
        let set: ValidatorSet = ValidatorSet::new(
            epoch,
            vec![ValidatorInfo {
                id: signer.id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: id_bytes.to_vec(),
            }],
        )
        .unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain.clone(),
            version,
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let certifier: FrozenFrontierCertifier =
            FrozenFrontierCertifier::new(chain.clone(), version, epoch, set).unwrap();
        let domain: AtomicityDomainId = AtomicityDomainId::new([9; 32]).unwrap();
        let identity =
            FrozenFrontierAccumulator::new(&resolver, chain, version, epoch, domain, [7; 32], 11)
                .unwrap()
                .into_identity();
        let vote: FrozenFrontierVote = certifier.cast_vote(identity, &signer).unwrap();
        (resolver, certifier, vote, signer.id, domain)
    }

    fn client(status: u16, body: Vec<u8>) -> Client<FixedTransport> {
        Client::new(FixedTransport {
            response: WireResponse {
                status,
                content_type: (status == 200).then(|| NODE_RESULT_MEDIA_TYPE.to_owned()),
                body,
            },
            calls: Cell::new(0),
            last_request: RefCell::new(None),
        })
    }

    pub(crate) fn signed_drain_member() -> SignedPaidIntent {
        let signer: LocalSigner = LocalSigner::from_seed([0x31; 32]);
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("drain-client-test").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(8),
        )
        .unwrap();
        let sender: [u8; 32] = *signer.address().as_bytes();
        let digest = |byte: u8| Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]);
        let request_id: [u8; 32] = [0x51; 32];
        let intent: PaidIntent = PaidIntent {
            context: context.clone(),
            request_id,
            sender,
            nonce: 1,
            fee_policy_digest: digest(0x11),
            consent: FeeSourceConsent {
                source: objects::ObjectRef {
                    id: objects::ObjectId::new([0x22; 32]),
                    version: 1,
                    digest: digest(0x33),
                },
                access: ReservationAccessKind::Write,
                max_fee: fees::Amount::new(1),
                refund_recipient: sender,
            },
            application: PaidApplication::Call(CallIntent {
                context: context.clone(),
                request_id,
                sender,
                nonce: 1,
                code: UnverifiedDependencyRef::new(
                    abi::package_types::PackageOrigin::unverified(
                        context.chain_id().clone(),
                        sender,
                        [0x44; 32],
                    )
                    .unwrap(),
                    1,
                    context.clone(),
                    digest(0x45),
                )
                .unwrap(),
                instance: InstanceTarget {
                    creator: sender,
                    seed: [0x46; 32],
                    revision: 1,
                    record_digest: digest(0x47),
                },
                entrypoint: "transfer".to_owned(),
                type_arguments: Vec::new(),
                access: abi::AccessManifest::new(),
                arguments: Vec::new(),
                gas_limit: 1,
            }),
            gas_limit: 1,
            authorizations: Vec::new(),
        };
        let frame: Vec<u8> = paid_intent_signing_frame(&context, &intent).unwrap();
        let signature_bytes: Vec<u8> = signer.sign_framed(&frame).unwrap();
        let signature: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
        SignedPaidIntent { intent, signature }
    }

    #[test]
    fn drain_apply_client_authenticates_before_post_and_binds_request_id() {
        let (resolver, _, vote, id, domain) = fixture();
        let certifier: FastPathCertifier = FastPathCertifier::new(
            vote.identity.chain_id.clone(),
            vote.identity.protocol_version,
            vote.identity.epoch,
            ValidatorSet::new(
                vote.identity.epoch,
                vec![ValidatorInfo {
                    id,
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: id.as_bytes().to_vec(),
                }],
            )
            .unwrap(),
        )
        .unwrap();
        let signed: SignedPaidIntent = signed_drain_member();
        let expected: PublicationContext = signed.intent.context.clone();
        let endpoint: Client<FixedTransport> = client(409, b"drain-member-not-ready".to_vec());
        assert!(matches!(
            endpoint.apply_drain_member(
                &signed,
                &certifier,
                &resolver,
                &[],
                &expected,
                domain,
                None
            ),
            Err(ClientError::UnexpectedStatus { status: 409, .. })
        ));
        assert_eq!(endpoint.transport().calls.get(), 1);
        let captured: WireRequest = endpoint.transport().last_request.borrow().clone().unwrap();
        assert_eq!(captured.path, FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH);
        assert_eq!(
            RetainedPublicationSourceRequest::decode(&captured.body).unwrap(),
            RetainedPublicationSourceRequest {
                epoch: expected.epoch(),
                request_id: signed.intent.request_id,
            }
        );

        let wrong_context: PublicationContext = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            Epoch::new(expected.epoch().get() + 1),
        )
        .unwrap();
        let untouched: Client<FixedTransport> = client(409, Vec::new());
        assert!(
            untouched
                .apply_drain_member(
                    &signed,
                    &certifier,
                    &resolver,
                    &[],
                    &wrong_context,
                    domain,
                    None
                )
                .is_err()
        );
        assert_eq!(untouched.transport().calls.get(), 0);
        let mut forged: SignedPaidIntent = signed.clone();
        forged.signature[0] ^= 1;
        assert!(
            untouched
                .apply_drain_member(&forged, &certifier, &resolver, &[], &expected, domain, None)
                .is_err()
        );
        assert_eq!(untouched.transport().calls.get(), 0);

        let wrong_id_result: Vec<u8> = node_wire::HttpNodeResult::new(
            node_core::RequestId::new([0x52; 32]).unwrap(),
            Vec::new(),
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(matches!(
            validate_drain_member_output(&signed, &resolver, &expected, &wrong_id_result),
            Err(ClientError::SubmitResponseRequestIdMismatch { .. })
        ));
    }

    #[test]
    fn signer_progress_read_accepts_only_locally_pinned_complete_snapshot() {
        let (resolver, certifier, vote, signer, domain) = fixture();
        let freeze: ExpectedDrainFreeze = ExpectedDrainFreeze {
            domain,
            closure_request_id: [7; 32],
            closure_height: 11,
        };
        let envelope: DrainSignerProgressResponse = DrainSignerProgressResponse {
            chain_id: vote.identity.chain_id.as_str().to_owned(),
            epoch: certifier.epoch(),
            signer,
            vote: encode_frozen_frontier_vote(&vote).unwrap(),
            confirmed_identity: consensus::encode_frozen_frontier_identity(&vote.identity).unwrap(),
            cursor: None,
            staged_page: None,
            complete: true,
        };
        let valid: Client<FixedTransport> = client(200, envelope.encode().unwrap());
        let progress: DrainSignerProgress = valid
            .read_drain_signer_progress(&certifier, signer, freeze, &resolver, None)
            .unwrap()
            .unwrap();
        assert_eq!(progress.vote, vote);
        assert_eq!(progress.confirmed_identity, vote.identity);
        assert!(progress.complete);

        let pristine: Client<FixedTransport> = client(409, b"drain-progress-pristine".to_vec());
        assert!(
            pristine
                .read_drain_signer_progress(&certifier, signer, freeze, &resolver, None)
                .unwrap()
                .is_none()
        );
        let repin: Client<FixedTransport> = client(409, b"drain-epoch-repin-required".to_vec());
        assert!(matches!(
            repin.read_drain_signer_progress(&certifier, signer, freeze, &resolver, None),
            Err(ClientError::UnexpectedStatus { status: 409, .. })
        ));
        let conflicting: Client<FixedTransport> = client(409, b"drain-not-ready".to_vec());
        assert!(matches!(
            conflicting.read_drain_signer_progress(&certifier, signer, freeze, &resolver, None),
            Err(ClientError::UnexpectedStatus { status: 409, .. })
        ));

        let mut foreign: DrainSignerProgressResponse = envelope.clone();
        foreign.signer = ValidatorId::new([0x99; 32]);
        assert!(matches!(
            client(200, foreign.encode().unwrap())
                .read_drain_signer_progress(&certifier, signer, freeze, &resolver, None),
            Err(ClientError::DrainMismatch(_))
        ));
        let mut forged: FrozenFrontierVote = vote.clone();
        forged.signature[0] ^= 1;
        let mut forged_envelope: DrainSignerProgressResponse = envelope;
        forged_envelope.vote = encode_frozen_frontier_vote(&forged).unwrap();
        assert!(matches!(
            client(200, forged_envelope.encode().unwrap())
                .read_drain_signer_progress(&certifier, signer, freeze, &resolver, None),
            Err(ClientError::FrozenFrontier(_))
        ));
    }

    #[test]
    fn stage_checks_endpoint_identity_and_signature_before_http() {
        let (_, certifier, vote, signer, domain) = fixture();
        let freeze: ExpectedDrainFreeze = ExpectedDrainFreeze {
            domain,
            closure_request_id: [7; 32],
            closure_height: 11,
        };
        let page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id: None,
            entries: Vec::new(),
            terminal: true,
        };
        let endpoint = client(204, Vec::new());
        assert!(matches!(
            endpoint.stage_drain_signer_page(
                &certifier,
                ValidatorId::new([0x11; 32]),
                freeze,
                &vote,
                &page,
                None,
            ),
            Err(ClientError::DrainMismatch(_))
        ));
        assert_eq!(endpoint.transport().calls.get(), 0);
        assert!(matches!(
            endpoint.stage_drain_signer_page(
                &certifier,
                signer,
                ExpectedDrainFreeze {
                    closure_request_id: [8; 32],
                    ..freeze
                },
                &vote,
                &page,
                None,
            ),
            Err(ClientError::DrainMismatch(_))
        ));
        assert_eq!(endpoint.transport().calls.get(), 0);
        let mut forged: FrozenFrontierVote = vote.clone();
        forged.signature[0] ^= 1;
        assert!(
            endpoint
                .stage_drain_signer_page(&certifier, signer, freeze, &forged, &page, None)
                .is_err()
        );
        assert_eq!(endpoint.transport().calls.get(), 0);
        endpoint
            .stage_drain_signer_page(&certifier, signer, freeze, &vote, &page, None)
            .unwrap();
        assert_eq!(endpoint.transport().calls.get(), 1);
    }

    #[test]
    fn confirm_and_union_reject_success_shaped_mismatches() {
        let (_, certifier, vote, signer, domain) = fixture();
        let freeze: ExpectedDrainFreeze = ExpectedDrainFreeze {
            domain,
            closure_request_id: [7; 32],
            closure_height: 11,
        };
        let with_body = client(204, vec![1]);
        assert!(matches!(
            with_body.confirm_drain_member(Epoch::new(8), signer, [2; 32], None),
            Err(ClientError::DrainMismatch(_))
        ));
        assert!(matches!(
            with_body.confirm_drain_member(Epoch::new(8), signer, [0; 32], None),
            Err(ClientError::DrainWire(_))
        ));
        assert_eq!(with_body.transport().calls.get(), 1);

        let mut wrong: DrainUnionIdentity = DrainUnionIdentity {
            chain_id: vote.identity.chain_id.clone(),
            protocol_version: vote.identity.protocol_version,
            epoch: vote.identity.epoch,
            domain,
            closure_request_id: [7; 32],
            closure_height: 12,
            signer_count: 1,
            member_count: 0,
            entries_digest: vote.identity.entries_digest,
        };
        let endpoint = client(200, consensus::encode_drain_union_identity(&wrong).unwrap());
        assert!(matches!(
            endpoint.advance_drain_union(&certifier, std::slice::from_ref(&vote), freeze, None,),
            Err(ClientError::DrainMismatch(_))
        ));
        assert_eq!(endpoint.transport().calls.get(), 1);
        wrong.closure_height = 11;
        let endpoint = client(200, consensus::encode_drain_union_identity(&wrong).unwrap());
        assert!(
            endpoint
                .advance_drain_union(&certifier, &[vote], freeze, None)
                .unwrap()
                .is_some()
        );
    }
}
