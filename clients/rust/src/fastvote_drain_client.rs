//! Bounded, locally pinned transport for DR-0157 post-Freeze drain progress.
//!
//! These calls only stage/confirm local possession and union progress. An HTTP
//! response is not an ordered DrainSet decision, a portable cut, or permission
//! to activate the next epoch. The endpoint rechecks the committed Freeze;
//! this client additionally checks signatures and exact response identities.

use std::time::Instant;

use consensus::bundle::{PublicationBundle, encode_publication_bundle, verify_publication_bundle};
use consensus::{
    AvailabilityIdentity, DrainUnionIdentity, FastPathCertifier, FrozenFrontierCertifier,
    FrozenFrontierPage, FrozenFrontierVote, decode_availability_identity,
    decode_drain_union_identity, encode_frozen_frontier_page, encode_frozen_frontier_vote,
    verify_frozen_frontier_quorum,
};
use execution::paid_execution::{
    authenticate_paid_intent, decode_signed_paid_intent, paid_invocation_digest,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_wire::{
    DrainMemberConfirmRequest, DrainSignerPageRequest, DrainUnionAdvanceRequest,
    FASTVOTE_DRAIN_IMPORT_PATH, FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
    FASTVOTE_DRAIN_SIGNER_PAGE_PATH, FASTVOTE_DRAIN_UNION_ADVANCE_PATH, NODE_EVENT_MEDIA_TYPE,
    NODE_RESULT_MEDIA_TYPE,
};
use protocol_types::{AtomicityDomainId, ValidatorId};

use crate::Client;
use crate::FastPathEd25519Verifier;
use crate::client::expect_success;
use crate::error::ClientError;
use crate::transport::{Method, Transport, WireRequest, WireResponse};

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
    /// Stages one signed, consecutive page on the target. A valid signature
    /// and endpoint mapping are checked locally; the target independently
    /// fences its installed Freeze and verifies the page before durable CAS.
    pub fn stage_drain_signer_page(
        &self,
        certifier: &FrozenFrontierCertifier,
        expected_signer: ValidatorId,
        vote: &FrozenFrontierVote,
        page: &FrozenFrontierPage,
        deadline: Option<Instant>,
    ) -> Result<(), ClientError> {
        if vote.validator != expected_signer {
            return Err(ClientError::DrainMismatch(
                "frontier vote signer differs from configured source",
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
        let verified = verify_publication_bundle(
            bundle,
            certifier,
            &FastPathEd25519Verifier,
            resolver,
            history,
        )?;
        if verified.identity != *expected_identity {
            return Err(ClientError::DrainMismatch(
                "bundle differs from signed frontier member",
            ));
        }
        let expected_context: PublicationContext = PublicationContext::new(
            certifier.chain_id().clone(),
            certifier.protocol_version(),
            certifier.epoch(),
        )?;
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
        expected_domain: AtomicityDomainId,
        expected_closure_request_id: [u8; 32],
        expected_closure_height: u64,
        deadline: Option<Instant>,
    ) -> Result<Option<DrainUnionIdentity>, ClientError> {
        verify_frozen_frontier_quorum(
            certifier,
            selected_votes,
            expected_domain,
            expected_closure_request_id,
            expected_closure_height,
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
        let expected: &consensus::FrozenFrontierIdentity = &selected_votes[0].identity;
        if identity.chain_id != expected.chain_id
            || identity.protocol_version != expected.protocol_version
            || identity.epoch != certifier.epoch()
            || identity.domain != expected_domain
            || identity.closure_request_id != expected_closure_request_id
            || identity.closure_height != expected_closure_height
            || identity.signer_count != selected_count
        {
            return Err(ClientError::DrainMismatch(
                "ready identity disagrees with locally selected Freeze",
            ));
        }
        Ok(Some(identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{ConsensusSigner, FrozenFrontierAccumulator};
    use ed25519_zebra::{SigningKey, VerificationKey};
    use protocol_types::{
        ChainId, Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion, SignatureSchemeId,
    };
    use std::cell::Cell;
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
    }

    impl Transport for FixedTransport {
        fn send(
            &self,
            request: &WireRequest,
        ) -> Result<WireResponse, crate::transport::TransportError> {
            assert_eq!(request.method, Method::Post);
            self.calls.set(self.calls.get() + 1);
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
        })
    }

    #[test]
    fn stage_checks_endpoint_identity_and_signature_before_http() {
        let (_, certifier, vote, signer, _) = fixture();
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
                .stage_drain_signer_page(&certifier, signer, &forged, &page, None)
                .is_err()
        );
        assert_eq!(endpoint.transport().calls.get(), 0);
        endpoint
            .stage_drain_signer_page(&certifier, signer, &vote, &page, None)
            .unwrap();
        assert_eq!(endpoint.transport().calls.get(), 1);
    }

    #[test]
    fn confirm_and_union_reject_success_shaped_mismatches() {
        let (_, certifier, vote, signer, domain) = fixture();
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
            endpoint.advance_drain_union(
                &certifier,
                std::slice::from_ref(&vote),
                domain,
                [7; 32],
                11,
                None,
            ),
            Err(ClientError::DrainMismatch(_))
        ));
        assert_eq!(endpoint.transport().calls.get(), 1);
        wrong.closure_height = 11;
        let endpoint = client(200, consensus::encode_drain_union_identity(&wrong).unwrap());
        assert!(
            endpoint
                .advance_drain_union(&certifier, &[vote], domain, [7; 32], 11, None)
                .unwrap()
                .is_some()
        );
    }
}
