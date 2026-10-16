//! Protected ZeroShare fee-claim custody (DR-0257): the pure profile guard
//! and the family's own trust binding.
//!
//! ZeroShare carries no embedded transaction and releases no value: the
//! codec admits it only as a fixed field set with `share_amount == 0` and no
//! `signed_leg`, and execution checks the same before installing the claim.
//! Custody adds nothing economic of its own; it only ever (re)verifies the
//! existing [`sunrise_edge_client::PreparedFeeClaim::prepare`] contract
//! (historical certificate-committee claimant, never the current committee)
//! under its own pinned successor workflow, and requires the request's own
//! claimed `claimant_public_key` to equal custody's pinned publisher before
//! any workflow or socket I/O.

use sunrise_edge_client::{
    Address, FeeClaimIntent, FeeClaimOperation, FeeClaimPrepareRequest, FeeClaimReview,
    PreparedFeeClaim, SuccessorWorkflowAuthority,
};

use crate::error::CliError;

use super::config::CustodyConfig;
use super::error::CustodyError;

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

/// Pure, cheap profile guard: refuses `Split`/`FinalTransfer`, a nonzero
/// `share_amount`, a present `signed_leg`, a request/intent `request_id`
/// mismatch, a zero `request_id`, or a claimant key custody is not pinned to
/// sign for. Runs before `PreparedFeeClaim::prepare`, before any workflow is
/// loaded, and before any socket is touched, with no fallback.
pub(super) fn require_zero_share_profile(
    request: &FeeClaimPrepareRequest,
    intent: &FeeClaimIntent,
    expected_claimant_public_key: [u8; 32],
) -> Result<(), CustodyError> {
    if !matches!(intent.operation, FeeClaimOperation::ZeroShare) {
        return Err(CustodyError::NotZeroShare);
    }
    if intent.share_amount != 0 {
        return Err(CustodyError::NonZeroShareAmount);
    }
    if request.signed_leg.is_some() {
        return Err(CustodyError::UnexpectedSignedLeg);
    }
    if request.request_id != intent.request_id {
        return Err(CustodyError::RequestIdMismatch);
    }
    if intent.request_id == [0_u8; 32] {
        return Err(CustodyError::ZeroRequestId);
    }
    if request.claimant_public_key != expected_claimant_public_key {
        return Err(CustodyError::ZeroShareClaimantMismatch);
    }
    Ok(())
}

/// One immutable prepared ZeroShare fee claim plus its bounded review.
pub(super) struct PreparedFeeClaimZero<'a> {
    pub(super) prepared: PreparedFeeClaim<'a>,
    pub(super) review: FeeClaimReview,
}

impl PreparedFeeClaimZero<'_> {
    /// The full bounded review text, prefixed with one custody profile
    /// line, suitable for direct terminal display.
    pub(super) fn render_text(&self) -> String {
        let mut text: String = String::from("profile=protected_zero_share_fee_claim\n");
        text.push_str(&self.review.render_text());
        text
    }
}

/// The ZeroShare fee-claim family's own trust: custody's pinned
/// configuration plus the independently verified successor workflow.
pub(super) struct FeeClaimZeroTrust {
    config: CustodyConfig,
    workflow: SuccessorWorkflowAuthority,
}

impl FeeClaimZeroTrust {
    pub(super) fn new(config: CustodyConfig, workflow: SuccessorWorkflowAuthority) -> Self {
        Self { config, workflow }
    }

    pub(super) fn workflow(&self) -> &SuccessorWorkflowAuthority {
        &self.workflow
    }

    /// Runs the pure profile guard, then `PreparedFeeClaim::prepare` under
    /// this trust's own pinned successor workflow, then requires the
    /// resulting historical claimant to equal custody's pinned publisher.
    /// Builds the full bounded [`FeeClaimReview`] on success, prefixed with
    /// one custody profile line.
    pub(super) fn prepare_zero_share(
        &self,
        request: &FeeClaimPrepareRequest,
        intent: FeeClaimIntent,
    ) -> Result<PreparedFeeClaimZero<'_>, CliError> {
        require_zero_share_profile(request, &intent, *self.config.publisher().as_bytes())?;
        let prepared: PreparedFeeClaim<'_> =
            PreparedFeeClaim::prepare(&self.workflow, request, intent).map_err(failure)?;
        if prepared.claimant() != self.config.publisher() {
            return Err(CustodyError::ZeroShareClaimantMismatch.into());
        }
        let review: FeeClaimReview = FeeClaimReview::build(&prepared).map_err(failure)?;
        Ok(PreparedFeeClaimZero { prepared, review })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunrise_edge_client::{
        ChainId, Digest32, Epoch, HashAlgorithmId, ObjectId, ObjectRef, ProtocolVersion,
        PublicationContext, ValidatorId,
    };

    fn sample() -> (FeeClaimPrepareRequest, FeeClaimIntent) {
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("fee-claim-zero-profile-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(1),
        )
        .unwrap();
        let request: FeeClaimPrepareRequest = FeeClaimPrepareRequest {
            context: context.clone(),
            escrow_request_id: [2; 32],
            request_id: [1; 32],
            validator_id: ValidatorId::new([3; 32]),
            claimant_public_key: [4; 32],
            recipient: Address::new([5; 32]),
            signed_leg: None,
        };
        let intent: FeeClaimIntent = FeeClaimIntent {
            context,
            request_id: [1; 32],
            escrow_request_id: [2; 32],
            certificate_epoch: Epoch::new(0),
            validator_id: request.validator_id,
            resource_id: sunrise_edge_client::bond_registration::BondResourceId::new(1, [6; 32])
                .unwrap(),
            expected_generation: 7,
            expected_fee_output: ObjectRef {
                id: ObjectId::new([8; 32]),
                version: 9,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [10; 32]),
            },
            expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
            expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [12; 32]),
            share_amount: 0,
            recipient: request.recipient,
            operation: FeeClaimOperation::ZeroShare,
        };
        (request, intent)
    }

    #[test]
    fn accepts_a_self_consistent_zero_share_profile() {
        let (request, intent) = sample();
        require_zero_share_profile(&request, &intent, request.claimant_public_key).unwrap();
    }

    #[test]
    fn refuses_split_and_final_transfer() {
        let (request, mut intent) = sample();
        intent.share_amount = 5;
        intent.operation = FeeClaimOperation::Split {
            leg: vec![0xAB; 4],
            expected_payout: None,
        };
        assert!(matches!(
            require_zero_share_profile(&request, &intent, request.claimant_public_key),
            Err(CustodyError::NotZeroShare)
        ));
        intent.operation = FeeClaimOperation::FinalTransfer { leg: vec![0xAB; 4] };
        assert!(matches!(
            require_zero_share_profile(&request, &intent, request.claimant_public_key),
            Err(CustodyError::NotZeroShare)
        ));
    }

    #[test]
    fn refuses_a_nonzero_share_amount() {
        let (request, mut intent) = sample();
        intent.share_amount = 1;
        assert!(matches!(
            require_zero_share_profile(&request, &intent, request.claimant_public_key),
            Err(CustodyError::NonZeroShareAmount)
        ));
    }

    #[test]
    fn refuses_a_request_carrying_a_signed_leg() {
        let (mut request, intent) = sample();
        request.signed_leg = Some(vec![0xAB; 4]);
        assert!(matches!(
            require_zero_share_profile(&request, &intent, request.claimant_public_key),
            Err(CustodyError::UnexpectedSignedLeg)
        ));
    }

    #[test]
    fn refuses_a_request_intent_id_mismatch() {
        let (request, mut intent) = sample();
        intent.request_id = [9; 32];
        assert!(matches!(
            require_zero_share_profile(&request, &intent, request.claimant_public_key),
            Err(CustodyError::RequestIdMismatch)
        ));
    }

    #[test]
    fn refuses_a_zero_request_id() {
        let (mut request, mut intent) = sample();
        request.request_id = [0; 32];
        intent.request_id = [0; 32];
        assert!(matches!(
            require_zero_share_profile(&request, &intent, request.claimant_public_key),
            Err(CustodyError::ZeroRequestId)
        ));
    }

    #[test]
    fn refuses_a_claimant_key_custody_is_not_pinned_to() {
        let (request, intent) = sample();
        assert!(matches!(
            require_zero_share_profile(&request, &intent, [0xFF; 32]),
            Err(CustodyError::ZeroShareClaimantMismatch)
        ));
    }
}
