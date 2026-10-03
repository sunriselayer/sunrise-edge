//! Structural comparison only: these tests exercise the private, pure
//! `fee_claim_selectors_match` helper directly. None of them carries a
//! `SuccessorWorkflowAuthority`, a certificate committee or a real
//! signature, and none proves authorization; the trusted committee/key
//! lookup inside `verify_prepared_fee_claim` is intentionally out of scope
//! here and needs separate acceptance through a real verified workflow.

use super::*;
use crate::bond_registration::BondResourceId;
use abi::AccessManifest;
use abi::package_types::PackageOrigin;
use execution::call::{CallIntent, InstanceTarget};
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, encode_signed_local_execution,
};
use execution::publication::UnverifiedDependencyRef;
use objects::{Address, ObjectId, ObjectRef};
use protocol_types::{ChainId, Epoch, HashAlgorithmId, ProtocolVersion, ValidatorId};

fn sample_context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("fee-claim-selectors-test").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(1),
    )
    .unwrap()
}

fn other_context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("fee-claim-selectors-test").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(2),
    )
    .unwrap()
}

fn encode_minimal_signed_leg(context: &PublicationContext, request_id: [u8; 32]) -> Vec<u8> {
    let origin: PackageOrigin =
        PackageOrigin::unverified(context.chain_id().clone(), [0x11; 32], [0x22; 32]).unwrap();
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        origin,
        1,
        context.clone(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
    )
    .unwrap();
    let instance: InstanceTarget = InstanceTarget {
        creator: [0x44; 32],
        seed: [0x55; 32],
        revision: 1,
        record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
    };
    let call: CallIntent = CallIntent {
        context: context.clone(),
        request_id,
        sender: [0x44; 32],
        nonce: 0,
        code,
        instance,
        entrypoint: "noop".to_owned(),
        type_arguments: Vec::new(),
        access: AccessManifest::default(),
        arguments: Vec::new(),
        gas_limit: 1,
    };
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x88; 32]),
        call,
        authorizations: Vec::new(),
    };
    let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent,
        signature: [0; 64],
    };
    encode_signed_local_execution(&signed).unwrap()
}

fn sample_request(signed_leg: Option<Vec<u8>>) -> FeeClaimPrepareRequest {
    FeeClaimPrepareRequest {
        context: sample_context(),
        escrow_request_id: [1; 32],
        request_id: [2; 32],
        validator_id: ValidatorId::new([3; 32]),
        claimant_public_key: [4; 32],
        recipient: Address::new([5; 32]),
        signed_leg,
    }
}

fn sample_intent(operation: FeeClaimOperation) -> FeeClaimIntent {
    FeeClaimIntent {
        context: sample_context(),
        request_id: [2; 32],
        escrow_request_id: [1; 32],
        certificate_epoch: Epoch::new(3),
        validator_id: ValidatorId::new([3; 32]),
        resource_id: BondResourceId::new(1, [9; 32]).unwrap(),
        expected_generation: 1,
        expected_fee_output: ObjectRef {
            id: ObjectId::new([10; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
        },
        expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [12; 32]),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [13; 32]),
        share_amount: 0,
        recipient: Address::new([5; 32]),
        operation,
    }
}

#[test]
fn zero_share_selectors_match_the_exact_request() {
    let context: PublicationContext = sample_context();
    let request: FeeClaimPrepareRequest = sample_request(None);
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_ok());
}

#[test]
fn split_leg_selectors_match_when_leg_bytes_are_identical() {
    let context: PublicationContext = sample_context();
    let leg: Vec<u8> = encode_minimal_signed_leg(&context, [2; 32]);
    let request: FeeClaimPrepareRequest = sample_request(Some(leg.clone()));
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::Split {
        leg,
        expected_payout: None,
    });
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_ok());
}

#[test]
fn final_transfer_leg_selectors_match_when_leg_bytes_are_identical() {
    let context: PublicationContext = sample_context();
    let leg: Vec<u8> = encode_minimal_signed_leg(&context, [2; 32]);
    let request: FeeClaimPrepareRequest = sample_request(Some(leg.clone()));
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::FinalTransfer { leg });
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_ok());
}

#[test]
fn intent_context_mismatch_is_refused() {
    let context: PublicationContext = sample_context();
    let request: FeeClaimPrepareRequest = sample_request(None);
    let mut intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    intent.context = other_context();
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn intent_request_id_mismatch_is_refused() {
    let context: PublicationContext = sample_context();
    let request: FeeClaimPrepareRequest = sample_request(None);
    let mut intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    intent.request_id = [0x66; 32];
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn intent_escrow_request_id_mismatch_is_refused() {
    let context: PublicationContext = sample_context();
    let request: FeeClaimPrepareRequest = sample_request(None);
    let mut intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    intent.escrow_request_id = [0x67; 32];
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn intent_validator_mismatch_is_refused() {
    let context: PublicationContext = sample_context();
    let request: FeeClaimPrepareRequest = sample_request(None);
    let mut intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    intent.validator_id = ValidatorId::new([0x68; 32]);
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn intent_recipient_mismatch_is_refused() {
    let context: PublicationContext = sample_context();
    let request: FeeClaimPrepareRequest = sample_request(None);
    let mut intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    intent.recipient = Address::new([0x69; 32]);
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn malformed_signed_leg_bytes_are_refused() {
    let context: PublicationContext = sample_context();
    let garbage: Vec<u8> = vec![0xFF; 8];
    let request: FeeClaimPrepareRequest = sample_request(Some(garbage.clone()));
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::FinalTransfer { leg: garbage });
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn signed_leg_outside_the_verified_context_is_refused() {
    let context: PublicationContext = sample_context();
    let leg: Vec<u8> = encode_minimal_signed_leg(&other_context(), [2; 32]);
    let request: FeeClaimPrepareRequest = sample_request(Some(leg.clone()));
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::FinalTransfer { leg });
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn zero_share_operation_with_a_supplied_leg_is_refused() {
    let context: PublicationContext = sample_context();
    let leg: Vec<u8> = encode_minimal_signed_leg(&context, [2; 32]);
    let request: FeeClaimPrepareRequest = sample_request(Some(leg));
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::ZeroShare);
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn positive_operation_without_a_supplied_leg_is_refused() {
    let context: PublicationContext = sample_context();
    let leg: Vec<u8> = encode_minimal_signed_leg(&context, [2; 32]);
    let request: FeeClaimPrepareRequest = sample_request(None);
    let intent: FeeClaimIntent = sample_intent(FeeClaimOperation::FinalTransfer { leg });
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}

#[test]
fn positive_operation_leg_bytes_differing_from_the_request_is_refused() {
    let context: PublicationContext = sample_context();
    let requested_leg: Vec<u8> = encode_minimal_signed_leg(&context, [2; 32]);
    let intent_leg: Vec<u8> = encode_minimal_signed_leg(&context, [0x6A; 32]);
    let request: FeeClaimPrepareRequest = sample_request(Some(requested_leg));
    let intent: FeeClaimIntent =
        sample_intent(FeeClaimOperation::FinalTransfer { leg: intent_leg });
    assert!(fee_claim_selectors_match(&context, &request, &intent).is_err());
}
