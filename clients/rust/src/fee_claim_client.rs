//! Successor fee-claim preparation client (DR-0137 prepare transport,
//! DR-0189 successor scope).
//!
//! The host prepares an unsigned canonical FeeClaimIntent; the response is
//! never authority. Before any signature this client requires the intent to
//! bind exactly the independently verified e+1 context, the requested claim
//! selectors, the recipient and the presence and bytes of the signed leg.
//! The signed claim is then submitted as an ordered e+1 FeeClaim candidate
//! through the existing successor-scoped ordered workflow.

use crate::client::expect_success;
use crate::successor_authority::SuccessorWorkflowAuthority;
use crate::{
    Client, ClientError, Digest32, HashSuiteResolver, Method, Transport, WireRequest, WireResponse,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::PublicationContext;
use node_core::NodeCoreError;
use node_core::fee_claims::codec::{
    FeeClaimCodecError, FeeClaimIntent, FeeClaimOperation, SignedFeeClaimIntent,
    decode_fee_claim_intent, encode_signed_fee_claim_intent,
};
use node_core::fee_claims::{FeeClaimError, fee_claim_intent_digest, fee_claim_signing_frame};
use node_core::ordered_economics::{OrderedCandidate, OrderedOperationKind, encode_ordered_candidate};
use node_wire::{
    FEE_CLAIM_INTENT_MEDIA_TYPE, FEE_CLAIM_PREPARE_PATH, FEE_CLAIM_PREPARE_REQUEST_MEDIA_TYPE,
    FeeClaimPrepareRequest, FeeClaimPrepareRequestError,
};
use std::{error::Error, fmt, time::Instant};

/// Refusal of successor fee-claim preparation, verification or signing.
#[derive(Debug)]
pub enum FeeClaimPreparationError {
    /// Transport or HTTP status failure.
    Client(ClientError),
    /// The request frame refused to encode.
    RequestWire(FeeClaimPrepareRequestError),
    /// The response is not one canonical unsigned FeeClaimIntent.
    IntentCodec(FeeClaimCodecError),
    /// Digest or signing-frame derivation failed.
    Core(FeeClaimError),
    /// Candidate encoding failed.
    Candidate(NodeCoreError),
    /// The request or prepared intent differs from the verified scope or
    /// the requested selectors.
    Mismatch(&'static str),
}

impl fmt::Display for FeeClaimPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "fee claim preparation transport failed: {error}"),
            Self::RequestWire(error) => write!(f, "fee claim request refused: {error}"),
            Self::IntentCodec(error) => write!(f, "prepared fee claim refused: {error:?}"),
            Self::Core(error) => write!(f, "fee claim signing frame refused: {error:?}"),
            Self::Candidate(error) => write!(f, "fee claim candidate refused: {error}"),
            Self::Mismatch(reason) => write!(f, "prepared fee claim mismatch: {reason}"),
        }
    }
}

impl Error for FeeClaimPreparationError {}

impl From<ClientError> for FeeClaimPreparationError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

/// Requires the request to target exactly the verified e+1 context. Run
/// before sending, so a wrong scope never reaches a host.
pub fn require_successor_fee_claim_request(
    workflow: &SuccessorWorkflowAuthority,
    request: &FeeClaimPrepareRequest,
) -> Result<(), FeeClaimPreparationError> {
    workflow
        .require_signing_context(&request.context)
        .map_err(|_| FeeClaimPreparationError::Mismatch("request context is not the verified e+1 context"))
}

/// Checks an untrusted prepared intent against the verified scope and the
/// exact request before any signature is created.
pub fn verify_prepared_fee_claim(
    workflow: &SuccessorWorkflowAuthority,
    request: &FeeClaimPrepareRequest,
    intent: &FeeClaimIntent,
) -> Result<(), FeeClaimPreparationError> {
    require_successor_fee_claim_request(workflow, request)?;
    let expected: &PublicationContext = workflow.expected_context();
    let mismatch = FeeClaimPreparationError::Mismatch;
    if intent.context != *expected {
        return Err(mismatch("intent context is not the verified e+1 context"));
    }
    if intent.request_id != request.request_id {
        return Err(mismatch("intent request id differs"));
    }
    if intent.escrow_request_id != request.escrow_request_id {
        return Err(mismatch("intent escrow request id differs"));
    }
    if intent.validator_id != request.validator_id {
        return Err(mismatch("intent claimant validator differs"));
    }
    if intent.recipient != request.recipient {
        return Err(mismatch("intent recipient differs"));
    }
    if intent.certificate_epoch > expected.epoch() {
        return Err(mismatch("intent certificate epoch is after the verified e+1 epoch"));
    }
    let leg_matches: bool = match (&intent.operation, request.signed_leg.as_deref()) {
        (FeeClaimOperation::ZeroShare, None) => true,
        (FeeClaimOperation::Split { leg, .. }, Some(requested))
        | (FeeClaimOperation::FinalTransfer { leg }, Some(requested)) => leg.as_slice() == requested,
        _ => false,
    };
    if !leg_matches {
        return Err(mismatch("intent operation or signed leg differs from the request"));
    }
    Ok(())
}

/// Signs a verified prepared intent with the historical claimant key seed,
/// after requiring that key to be exactly the requested claimant public key.
/// Callers must run [verify_prepared_fee_claim] first; the seed is never
/// retained.
pub fn sign_prepared_fee_claim(
    resolver: &HashSuiteResolver,
    request: &FeeClaimPrepareRequest,
    intent: FeeClaimIntent,
    claimant_seed: [u8; 32],
) -> Result<Vec<u8>, FeeClaimPreparationError> {
    let key: SigningKey = SigningKey::from(claimant_seed);
    let public: [u8; 32] = VerificationKey::from(&key).into();
    if public != request.claimant_public_key {
        return Err(FeeClaimPreparationError::Mismatch(
            "signing key is not the requested claimant public key",
        ));
    }
    let digest: Digest32 =
        fee_claim_intent_digest(resolver, &intent).map_err(FeeClaimPreparationError::Core)?;
    let frame: Vec<u8> =
        fee_claim_signing_frame(&intent.context, digest).map_err(FeeClaimPreparationError::Core)?;
    let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
        signature: key.sign(&frame).into(),
        intent,
    };
    encode_signed_fee_claim_intent(&signed).map_err(FeeClaimPreparationError::IntentCodec)
}

/// Wraps signed claim bytes as the ordered e+1 FeeClaim candidate the
/// existing ordered submission workflow carries.
pub fn fee_claim_candidate(
    workflow: &SuccessorWorkflowAuthority,
    request_id: [u8; 32],
    signed_claim: Vec<u8>,
    created_checkpoint: u64,
) -> Result<Vec<u8>, FeeClaimPreparationError> {
    encode_ordered_candidate(&OrderedCandidate {
        context: workflow.expected_context().clone(),
        request_id,
        kind: OrderedOperationKind::FeeClaim,
        intent: signed_claim,
        created_checkpoint,
    })
    .map_err(FeeClaimPreparationError::Candidate)
}

impl<T: Transport> Client<T> {
    /// POST the prepare route and return the verified unsigned intent.
    pub fn prepare_successor_fee_claim(
        &self,
        workflow: &SuccessorWorkflowAuthority,
        request: &FeeClaimPrepareRequest,
        deadline: Option<Instant>,
    ) -> Result<FeeClaimIntent, FeeClaimPreparationError> {
        require_successor_fee_claim_request(workflow, request)?;
        let body: Vec<u8> = request.encode().map_err(FeeClaimPreparationError::RequestWire)?;
        let response: WireResponse = self
            .transport()
            .send(&WireRequest {
                method: Method::Post,
                path: FEE_CLAIM_PREPARE_PATH.to_owned(),
                content_type: Some(FEE_CLAIM_PREPARE_REQUEST_MEDIA_TYPE),
                body,
                deadline,
            })
            .map_err(ClientError::from)?;
        let bytes: Vec<u8> = expect_success(response, FEE_CLAIM_INTENT_MEDIA_TYPE)?;
        let intent: FeeClaimIntent =
            decode_fee_claim_intent(&bytes).map_err(FeeClaimPreparationError::IntentCodec)?;
        verify_prepared_fee_claim(workflow, request, &intent)?;
        Ok(intent)
    }
}
