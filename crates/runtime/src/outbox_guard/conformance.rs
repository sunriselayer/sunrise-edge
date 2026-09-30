//! Test-only outbox-exclusion fixtures. These assertions are storage
//! conformance, NOT proof of atomic freeze/cut readiness; see the module
//! doc comment on [`StructuredOutboxExclusionGuard`].

use super::*;
use crate::{
    DurableCommitOutcome, DurableInvocationTransaction, DurableObjectChanges,
    DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome, DurableOutboxBatch,
    DurableOutboxClaim, DurableOutboxClaimOutcome, DurableOutboxLeaseId, DurableOutboxMessage,
    DurableRequestId, DurableRequestReceipt, IndexedOutboxRepository, OutboxRequestId,
    RequestOutboxClaimRequest,
};
use protocol_types::{Digest32, HashAlgorithmId};

const CONFORMANCE_NOW: u64 = 10_000;
const CONFORMANCE_LEASE_MILLIS: u64 = 1_000;

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

fn commit_batch<S: StructuredOutboxExclusionGuard>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_byte: u8,
    messages: Vec<DurableOutboxMessage>,
) -> DurableRequestId {
    let request_id: DurableRequestId = DurableRequestId::new([request_byte; 32]).unwrap();
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request_id, digest(request_byte), vec![request_byte]).unwrap();
    let batch: DurableOutboxBatch =
        DurableOutboxBatch::new(request_id, digest(request_byte), messages).unwrap();
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        None,
        DurableObjectChanges::default(),
        receipt,
        Some(batch),
    )
    .unwrap();
    assert!(matches!(
        store.commit_invocation(context, invocation),
        DurableCommitOutcome::Committed
    ));
    request_id
}

/// A fresh domain with no committed requests reports no obligation.
pub fn assert_clear_when_unseeded<S: StructuredOutboxExclusionGuard>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) {
    let inventory: StructuredOutboxInventory =
        store.inspect_outbox_exclusion(context, domain).unwrap();
    assert!(!inventory.blocks_exclusion());
    assert!(!inventory.pending_delivery_present());
}

/// An explicit empty batch's own rows must not, by themselves, block
/// exclusion: presence alone is not equated with an obligation.
pub fn assert_clear_after_empty_batch<S: StructuredOutboxExclusionGuard>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_byte: u8,
) {
    commit_batch(store, context, domain, request_byte, Vec::new());
    let inventory: StructuredOutboxInventory =
        store.inspect_outbox_exclusion(context, domain).unwrap();
    assert!(!inventory.blocks_exclusion());
}

/// A nonempty, undelivered batch must block exclusion.
pub fn assert_blocked_by_pending_message<S: StructuredOutboxExclusionGuard>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_byte: u8,
) -> DurableRequestId {
    let message: DurableOutboxMessage =
        DurableOutboxMessage::new(digest(request_byte.wrapping_add(1)), vec![request_byte])
            .unwrap();
    let request_id: DurableRequestId =
        commit_batch(store, context, domain, request_byte, vec![message]);
    let inventory: StructuredOutboxInventory =
        store.inspect_outbox_exclusion(context, domain).unwrap();
    assert!(inventory.blocks_exclusion());
    assert!(inventory.pending_delivery_present());
    assert!(inventory.message_present());
    assert!(inventory.delivery_present());
    request_id
}

/// A locally acknowledged nonempty batch remains excluded from the initial
/// handoff profile: cross-epoch delivery and reconstruction are not proven.
pub fn assert_blocked_after_full_acknowledgement<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_byte: u8,
) where
    S: StructuredOutboxExclusionGuard + IndexedOutboxRepository,
{
    let message: DurableOutboxMessage =
        DurableOutboxMessage::new(digest(request_byte.wrapping_add(2)), vec![request_byte])
            .unwrap();
    commit_batch(store, context, domain, request_byte, vec![message]);
    let outbox_request_id: OutboxRequestId = OutboxRequestId::new([request_byte; 32]).unwrap();
    let lease_id: DurableOutboxLeaseId = DurableOutboxLeaseId::new([request_byte; 32]).unwrap();
    let claim_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
        domain,
        outbox_request_id,
        CONFORMANCE_NOW,
        lease_id,
        CONFORMANCE_NOW + CONFORMANCE_LEASE_MILLIS,
    )
    .unwrap();
    let claim_outcome: DurableOutboxClaimOutcome =
        store.claim_request_outbox(context, claim_request);
    let claim: DurableOutboxClaim = match claim_outcome {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        other => panic!("expected claim, got {other:?}"),
    };
    let acknowledgement: DurableOutboxAcknowledgement = DurableOutboxAcknowledgement::new(
        domain,
        outbox_request_id,
        claim.message_index(),
        lease_id,
    );
    assert_eq!(
        store.acknowledge_outbox(context, acknowledgement),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    let inventory: StructuredOutboxInventory =
        store.inspect_outbox_exclusion(context, domain).unwrap();
    assert!(inventory.blocks_exclusion());
    assert!(!inventory.pending_delivery_present());
    assert!(inventory.delivery_present());
    assert!(inventory.message_present());
}
