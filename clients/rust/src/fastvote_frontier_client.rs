//! Locally pinned, bounded transport for one outgoing validator's frozen
//! frontier. A signed page is still provisional until a caller verifies the
//! whole consecutive stream and obtains every full retained artifact.

use std::time::Instant;

use consensus::{
    FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierVote, decode_frozen_frontier_page,
    decode_frozen_frontier_vote,
};
use node_core::fast_path::FastPathEd25519Verifier;
use node_wire::{
    FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH, FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
    FrozenFrontierPageRequest, FrozenFrontierPageResponse, NODE_EVENT_MEDIA_TYPE,
    NODE_RESULT_MEDIA_TYPE,
};
use protocol_types::ValidatorId;

use crate::Client;
use crate::client::expect_success;
use crate::error::ClientError;
use crate::transport::{Method, Transport, WireRequest};

impl<T: Transport> Client<T> {
    /// Asks one locally configured validator to advance at most one
    /// CAS-fenced frozen-frontier step. `None` means the endpoint reported
    /// progress, not authenticated finality; `Some` is the exact final vote, cryptographically checked
    /// against the caller's pinned outgoing set and endpoint identity.
    pub fn advance_frozen_frontier(
        &self,
        certifier: &FrozenFrontierCertifier,
        expected_validator: ValidatorId,
        deadline: Option<Instant>,
    ) -> Result<Option<FrozenFrontierVote>, ClientError> {
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: Vec::new(),
            deadline,
        })?;
        if response.status == 204 {
            if !response.body.is_empty() {
                return Err(ClientError::FrozenFrontierMismatch(
                    "progress response carried a body",
                ));
            }
            return Ok(None);
        }
        let body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let vote: FrozenFrontierVote = decode_frozen_frontier_vote(&body)?;
        verify_endpoint_vote(certifier, expected_validator, &vote)?;
        Ok(Some(vote))
    }

    /// Fetches one page and independently authenticates the returned final
    /// vote against the locally pinned validator set and endpoint identity.
    /// The caller must keep the same vote across pages, feed every page into
    /// `FrozenFrontierPageVerifier`, and require a terminal page before
    /// treating the log as complete. This call does not fetch full bundles.
    pub fn fetch_signed_frozen_frontier_page(
        &self,
        request: &FrozenFrontierPageRequest,
        certifier: &FrozenFrontierCertifier,
        expected_validator: ValidatorId,
        deadline: Option<Instant>,
    ) -> Result<(FrozenFrontierVote, FrozenFrontierPage), ClientError> {
        if request.epoch != certifier.epoch() {
            return Err(ClientError::FrozenFrontierMismatch(
                "request epoch differs from locally pinned outgoing set",
            ));
        }
        let body: Vec<u8> = request.encode()?;
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: FASTVOTE_FROZEN_FRONTIER_PAGE_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        let response_body: Vec<u8> = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let envelope: FrozenFrontierPageResponse =
            FrozenFrontierPageResponse::decode(&response_body)?;
        let vote: FrozenFrontierVote = decode_frozen_frontier_vote(&envelope.vote)?;
        verify_endpoint_vote(certifier, expected_validator, &vote)?;
        let page: FrozenFrontierPage = decode_frozen_frontier_page(&envelope.page)?;
        if page.after_request_id != request.after_request_id
            || page.entries.len() > usize::from(request.limit)
        {
            return Err(ClientError::FrozenFrontierMismatch(
                "page cursor or limit differs from request",
            ));
        }
        Ok((vote, page))
    }
}

fn verify_endpoint_vote(
    certifier: &FrozenFrontierCertifier,
    expected_validator: ValidatorId,
    vote: &FrozenFrontierVote,
) -> Result<(), ClientError> {
    if vote.validator != expected_validator {
        return Err(ClientError::FrozenFrontierMismatch(
            "vote signer differs from locally configured endpoint",
        ));
    }
    certifier.verify_vote(vote, &FastPathEd25519Verifier)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::{
        ConsensusSigner, FrozenFrontierAccumulator, encode_frozen_frontier_page,
        encode_frozen_frontier_vote,
    };
    use ed25519_zebra::{SigningKey, VerificationKey};
    use hashing::HashSuiteResolver;
    use protocol_types::{
        AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule,
        ProtocolVersion, SignatureSchemeId,
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

    fn fixture() -> (
        HashSuiteResolver,
        FrozenFrontierCertifier,
        Signer,
        FrozenFrontierVote,
    ) {
        let chain: ChainId = ChainId::new("frontier-client-test").unwrap();
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
        let identity = FrozenFrontierAccumulator::new(
            &resolver,
            chain,
            version,
            epoch,
            AtomicityDomainId::new([9; 32]).unwrap(),
            [7; 32],
            11,
        )
        .unwrap()
        .into_identity();
        let vote: FrozenFrontierVote = certifier.cast_vote(identity, &signer).unwrap();
        (resolver, certifier, signer, vote)
    }

    struct FixedTransport {
        response: crate::transport::WireResponse,
        calls: Cell<u32>,
    }

    impl Transport for FixedTransport {
        fn send(
            &self,
            request: &WireRequest,
        ) -> Result<crate::transport::WireResponse, crate::transport::TransportError> {
            assert_eq!(request.method, Method::Post);
            self.calls.set(self.calls.get() + 1);
            Ok(self.response.clone())
        }
    }

    fn client(body: Vec<u8>) -> Client<FixedTransport> {
        Client::new(FixedTransport {
            response: crate::transport::WireResponse {
                status: 200,
                content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                body,
            },
            calls: Cell::new(0),
        })
    }

    #[test]
    fn signed_empty_page_requires_pinned_endpoint_and_still_needs_terminal_verification() {
        let (resolver, certifier, signer, vote) = fixture();
        let page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id: None,
            entries: Vec::new(),
            terminal: true,
        };
        let response: FrozenFrontierPageResponse = FrozenFrontierPageResponse {
            vote: encode_frozen_frontier_vote(&vote).unwrap(),
            page: encode_frozen_frontier_page(&page).unwrap(),
        };
        let client: Client<FixedTransport> = client(response.encode().unwrap());
        let request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            epoch: Epoch::new(8),
            after_request_id: None,
            limit: 1,
        };
        let (got_vote, got_page) = client
            .fetch_signed_frozen_frontier_page(&request, &certifier, signer.id, None)
            .unwrap();
        assert_eq!(got_vote, vote);
        assert_eq!(got_page, page);
        let mut verifier = consensus::FrozenFrontierPageVerifier::new(
            &resolver,
            &certifier,
            got_vote.clone(),
            &FastPathEd25519Verifier,
        )
        .unwrap();
        verifier.push_page(&resolver, &got_page).unwrap();
        assert_eq!(verifier.finish().unwrap(), got_vote);
        assert!(
            client
                .fetch_signed_frozen_frontier_page(
                    &request,
                    &certifier,
                    ValidatorId::new([0x99; 32]),
                    None,
                )
                .is_err()
        );
        let stale: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            epoch: Epoch::new(9),
            ..request
        };
        assert!(
            client
                .fetch_signed_frozen_frontier_page(&stale, &certifier, signer.id, None)
                .is_err()
        );
        assert_eq!(client.transport().calls.get(), 2);
    }

    #[test]
    fn advance_final_vote_is_verified_and_progress_is_not_final() {
        let (_resolver, certifier, signer, vote) = fixture();
        let client: Client<FixedTransport> = client(encode_frozen_frontier_vote(&vote).unwrap());
        assert_eq!(
            client
                .advance_frozen_frontier(&certifier, signer.id, None)
                .unwrap(),
            Some(vote)
        );
        let progress: Client<FixedTransport> = Client::new(FixedTransport {
            response: crate::transport::WireResponse {
                status: 204,
                content_type: None,
                body: Vec::new(),
            },
            calls: Cell::new(0),
        });
        assert_eq!(
            progress
                .advance_frozen_frontier(&certifier, signer.id, None)
                .unwrap(),
            None
        );
        let nonempty_progress: Client<FixedTransport> = Client::new(FixedTransport {
            response: crate::transport::WireResponse {
                status: 204,
                content_type: None,
                body: vec![0xAA],
            },
            calls: Cell::new(0),
        });
        assert!(
            nonempty_progress
                .advance_frozen_frontier(&certifier, signer.id, None)
                .is_err()
        );
    }

    #[test]
    fn page_client_rejects_cursor_limit_and_signature_mismatches() {
        let (_resolver, certifier, signer, vote) = fixture();
        let request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            epoch: Epoch::new(8),
            after_request_id: None,
            limit: 1,
        };
        let encode_response = |vote: &FrozenFrontierVote, page: &FrozenFrontierPage| {
            FrozenFrontierPageResponse {
                vote: encode_frozen_frontier_vote(vote).unwrap(),
                page: encode_frozen_frontier_page(page).unwrap(),
            }
            .encode()
            .unwrap()
        };
        let cursor_page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id: Some([0x10; 32]),
            entries: Vec::new(),
            terminal: true,
        };
        assert!(
            client(encode_response(&vote, &cursor_page))
                .fetch_signed_frozen_frontier_page(&request, &certifier, signer.id, None)
                .is_err()
        );
        let entry = |request_byte: u8| consensus::AvailabilityIdentity {
            chain_id: vote.identity.chain_id.clone(),
            protocol_version: vote.identity.protocol_version,
            epoch: vote.identity.epoch,
            domain: vote.identity.domain,
            request_id: [request_byte; 32],
            signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte; 32]),
            execution_commitment: Digest32::new(HashAlgorithmId::Sha2_256, [0xA1; 32]),
            semantic_artifacts_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xA2; 32]),
        };
        let over_limit_page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id: None,
            entries: vec![entry(1), entry(2)],
            terminal: true,
        };
        assert!(
            client(encode_response(&vote, &over_limit_page))
                .fetch_signed_frozen_frontier_page(&request, &certifier, signer.id, None)
                .is_err()
        );
        let empty_page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id: None,
            entries: Vec::new(),
            terminal: true,
        };
        let mut forged: FrozenFrontierVote = vote.clone();
        forged.signature[0] ^= 1;
        assert!(
            client(encode_response(&forged, &empty_page))
                .fetch_signed_frozen_frontier_page(&request, &certifier, signer.id, None)
                .is_err()
        );
        let unavailable: Client<FixedTransport> = Client::new(FixedTransport {
            response: crate::transport::WireResponse {
                status: 503,
                content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                body: encode_response(&vote, &empty_page),
            },
            calls: Cell::new(0),
        });
        assert!(
            unavailable
                .fetch_signed_frozen_frontier_page(&request, &certifier, signer.id, None)
                .is_err()
        );
    }
}
