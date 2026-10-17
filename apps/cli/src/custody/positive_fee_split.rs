//! Owned genuine workflow; typed preparation, exact approval and both key uses.
use super::positive_fee_split_approvals::{self as approvals, Content};
use super::positive_fee_split_wire::{self as wire, Request};
use super::{config::CustodyConfig, error::CustodyError};
use crate::positive_fee_claim_split::{
    HistoricalClaimantPin, PreparedPositiveSplitClaim, PreparedPositiveSplitLeg,
    SignedPositiveSplitLeg, StandardAssetPositiveSplitPolicy,
};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{
    ExternalSigner, LocalSigner, PublicationContext, RequestId, SignatureSchemeId,
    SuccessorWorkflowAuthority,
};

pub(super) fn rejected(_: impl std::fmt::Debug) -> CustodyError {
    CustodyError::PositiveSplitRejected
}

pub(super) fn now() -> Result<u64, CustodyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(rejected)
}

/// Owns authority; prepared values borrow it without a self-referential object.
pub(super) struct PositiveFeeSplitTrust {
    workflow: SuccessorWorkflowAuthority,
    claimant: HistoricalClaimantPin,
}

impl PositiveFeeSplitTrust {
    pub(super) fn new(
        config: &CustodyConfig,
        workflow: SuccessorWorkflowAuthority,
        claimant: HistoricalClaimantPin,
    ) -> Result<Self, CustodyError> {
        let expected: sunrise_edge_client::ExpectedProtocolContext = config.expected_context()?;
        let context: PublicationContext = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .map_err(rejected)?;
        workflow
            .require_signing_context(&context)
            .map_err(rejected)?;
        if workflow.ordered_policy().domain() != expected.domain()
            || workflow
                .ordered_policy()
                .resolver()
                .suite_for_epoch(context.epoch())
                .map_err(rejected)?
                .id
                != expected.hash_suite_id()
            || config.publisher() != claimant.public_key
        {
            return Err(CustodyError::PositiveSplitRejected);
        }
        StandardAssetPositiveSplitPolicy::new(&workflow, claimant).map_err(rejected)?;
        Ok(Self { workflow, claimant })
    }

    fn binding(
        &self,
        request: &Request,
        meaning: &str,
        frame: &[u8],
    ) -> Result<Content, CustodyError> {
        let context: &PublicationContext = self.workflow.expected_context();
        let trust: String = format!(
            "genesis={}\nchain={}\nprotocol={}\nexecution_epoch={}\nhash_suite_id={}\ndomain={}\nanchor={}\ncertificate_epoch={}\nvalidator={}\nclaimant={}\n",
            self.workflow.genesis_root().digest(),
            context.chain_id(),
            context.protocol_version().get(),
            context.epoch().get(),
            self.workflow
                .ordered_policy()
                .resolver()
                .suite_for_epoch(context.epoch())
                .map_err(rejected)?
                .id
                .get(),
            self.workflow.ordered_policy().domain(),
            self.workflow.ordered_policy().anchor(),
            self.claimant.certificate_epoch.get(),
            self.claimant.validator,
            self.claimant.public_key
        );
        if trust.len() > approvals::MAX_TRUST_BYTES
            || meaning.len() > approvals::MAX_MEANING_BYTES
            || frame.len() > approvals::MAX_FRAME_BYTES
        {
            return Err(CustodyError::PositiveSplitRejected);
        }
        Ok(Content {
            phase: request.phase(),
            request_id: RequestId::new(request.leg().terms.request_id).map_err(rejected)?,
            claimant: self.claimant.public_key,
            payload: wire::encode(request).map_err(CustodyError::Wire)?,
            trust: trust.into_bytes(),
            meaning: meaning.as_bytes().to_vec(),
            frame: frame.to_vec(),
        })
    }

    pub(super) fn prepare(&self, request: &Request) -> Result<Prepared<'_>, CustodyError> {
        let policy: StandardAssetPositiveSplitPolicy<'_> =
            StandardAssetPositiveSplitPolicy::new(&self.workflow, self.claimant)
                .map_err(rejected)?;
        let leg: PreparedPositiveSplitLeg<'_> = policy
            .prepare_leg(request.leg().terms.clone(), request.leg().object.clone())
            .map_err(rejected)?;
        let leg_request: Request = Request::Leg(request.leg().clone());
        let leg_content: Content = self.binding(
            &leg_request,
            leg.review().render_text(),
            leg.signable_frame(),
        )?;
        match request {
            Request::Leg(_) => Ok(Prepared {
                content: leg_content,
                leg_content: None,
                owner: Owner::Leg(Box::new(leg)),
            }),
            Request::Claim {
                signed_leg,
                request: saved_request,
                intent,
                ..
            } => {
                let decoded: sunrise_edge_client::local_execution::SignedLocalExecutionIntent =
                    sunrise_edge_client::local_execution::decode_signed_local_execution(signed_leg)
                        .map_err(rejected)?;
                let signed: SignedPositiveSplitLeg<'_> =
                    leg.finalize(decoded.signature.to_vec()).map_err(rejected)?;
                if signed.canonical_signed_leg() != signed_leg.as_slice() {
                    return Err(CustodyError::PositiveSplitRejected);
                }
                let claim: PreparedPositiveSplitClaim<'_> = signed
                    .prepare_claim(saved_request, intent)
                    .map_err(rejected)?;
                let content: Content =
                    self.binding(request, claim.review_text(), claim.signable_frame())?;
                Ok(Prepared {
                    content,
                    leg_content: Some(leg_content),
                    owner: Owner::Claim(Box::new(claim)),
                })
            }
        }
    }

    /// Private endpoint decision. The caller cannot select a frame or signer family.
    pub(super) fn sign_approved(
        &self,
        signer: &LocalSigner,
        dir: &Path,
        request: &Request,
    ) -> Result<[u8; 64], CustodyError> {
        if signer.address() != self.claimant.public_key
            || signer.signature_scheme_id() != SignatureSchemeId::Ed25519
        {
            return Err(CustodyError::KeyFileAddressMismatch);
        }
        let prepared: Prepared<'_> = self.prepare(request)?;
        prepared.authorize(dir, now()?)?;
        let content: Content = prepared.content.clone();
        let leg_content: Option<Content> = prepared.leg_content.clone();
        let signature: Vec<u8> = signer.sign_frame(prepared.frame()).map_err(rejected)?;
        prepared.finalize(signature.clone())?;
        if let Some(leg) = leg_content {
            approvals::authorize(dir, &leg, now()?)?;
        }
        approvals::authorize(dir, &content, now()?)?;
        signature.try_into().map_err(rejected)
    }

    pub(super) fn candidate(
        &self,
        id: RequestId,
        signed: Vec<u8>,
        checkpoint: u64,
    ) -> Result<Vec<u8>, CustodyError> {
        let bytes: Vec<u8> = sunrise_edge_client::fee_claim_candidate(
            &self.workflow,
            *id.as_bytes(),
            signed,
            checkpoint,
        )
        .map_err(rejected)?;
        let candidate: sunrise_edge_client::ordered_economics_core::OrderedCandidate =
            sunrise_edge_client::ordered_economics_core::decode_ordered_candidate(&bytes)
                .map_err(rejected)?;
        sunrise_edge_client::ordered_economics_client::authenticate_ordered_candidate(
            self.workflow.ordered_policy(),
            &candidate,
        )
        .map_err(rejected)?;
        Ok(bytes)
    }
}

enum Owner<'a> {
    Leg(Box<PreparedPositiveSplitLeg<'a>>),
    Claim(Box<PreparedPositiveSplitClaim<'a>>),
}
pub(super) struct Prepared<'a> {
    pub(super) content: Content,
    leg_content: Option<Content>,
    owner: Owner<'a>,
}
impl Prepared<'_> {
    pub(super) fn frame(&self) -> &[u8] {
        &self.content.frame
    }
    pub(super) fn authorize_leg(&self, dir: &Path, time: u64) -> Result<(), CustodyError> {
        if let Some(leg) = &self.leg_content {
            approvals::authorize(dir, leg, time)?;
        }
        Ok(())
    }
    fn authorize(&self, dir: &Path, time: u64) -> Result<(), CustodyError> {
        self.authorize_leg(dir, time)?;
        approvals::authorize(dir, &self.content, time)
    }
    pub(super) fn finalize(self, signature: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        match self.owner {
            Owner::Leg(leg) => {
                let signed: SignedPositiveSplitLeg<'_> =
                    (*leg).finalize(signature).map_err(rejected)?;
                Ok(signed.canonical_signed_leg().to_vec())
            }
            Owner::Claim(claim) => (*claim).finalize(signature).map_err(rejected),
        }
    }
}
