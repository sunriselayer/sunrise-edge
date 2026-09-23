//! Shared receipt, nonce and commit reconciliation for authenticated ingress.
use super::*;

pub(super) fn reconcile_receipt<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_id: RequestId,
    event_digest: Digest32,
) -> Result<Option<NodeOutput>, NodeCoreError> {
    let durable_id: DurableRequestId = DurableRequestId::new(*request_id.as_bytes())
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid durable request identity"))?;
    let Some(receipt) = store.get_request_receipt(context, domain, durable_id)? else {
        return Ok(None);
    };
    if receipt.request_id() != durable_id {
        return Err(NodeCoreError::PersistenceInvariant(
            "durable receipt lookup returned another request",
        ));
    }
    if receipt.event_digest() != event_digest {
        return Err(NodeCoreError::RequestIdReuse);
    }
    let record: NodeDedupRecord = NodeDedupRecord::decode(receipt.canonical_bytes())
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid durable receipt"))?;
    if record.request_id() != request_id
        || record.event_digest() != event_digest
        || record.encode()? != receipt.canonical_bytes()
    {
        return Err(NodeCoreError::PersistenceInvariant(
            "durable receipt projection and canonical record differ",
        ));
    }
    Ok(Some(NodeOutput::new(
        record.responses().to_vec(),
        Vec::new(),
    )?))
}

pub(super) fn reserve_sender_nonce<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    layout: &PersistenceLayout,
    reservation: SenderNonceReservation,
) -> Result<PendingSenderNonceWrite, NodeCoreError> {
    reserve_sender_nonce_range(store, context, domain, layout, reservation, 1)
}

/// Reserves `count` consecutive sender nonces starting at
/// `reservation.nonce`, merged into one pending write: the sequence lives
/// under one `(sender, epoch)` key, so reserving several consecutive values
/// (DR-0137 `bond_lifecycle` multi-leg operations) advances that single row
/// once rather than writing it once per leg. `count == 1` is exactly
/// [`reserve_sender_nonce`]'s existing behavior.
pub(super) fn reserve_sender_nonce_range<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    layout: &PersistenceLayout,
    reservation: SenderNonceReservation,
    count: u64,
) -> Result<PendingSenderNonceWrite, NodeCoreError> {
    if count == 0 {
        return Err(NodeCoreError::PersistenceInvariant(
            "sender nonce reservation count must be nonzero",
        ));
    }
    let key: Vec<u8> = layout.sender_nonce_key(reservation.sender, reservation.epoch);
    let observation: query::SenderNextNonceObservation = query::read_sender_next_nonce(
        store,
        context,
        domain,
        &key,
        reservation.sender,
        reservation.epoch,
    )?;
    if observation.next_nonce != reservation.nonce {
        return Err(NodeCoreError::SenderNonceMismatch {
            sender: reservation.sender,
            expected: observation.next_nonce,
            actual: reservation.nonce,
        });
    }
    let next_nonce: u64 =
        reservation
            .nonce
            .checked_add(count)
            .ok_or(NodeCoreError::SenderNonceOverflow {
                sender: reservation.sender,
            })?;
    Ok(PendingSenderNonceWrite {
        key,
        read_revision: observation.revision,
        record: SenderNonceRecord::new(reservation.sender, reservation.epoch, next_nonce),
    })
}

pub(super) fn committed_output(
    outcome: DurableCommitOutcome,
    output: NodeOutput,
) -> Result<NodeOutput, NodeCoreError> {
    match outcome {
        DurableCommitOutcome::Committed => Ok(output),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(NodeCoreError::StateConflict),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id,
            ..
        }) => Err(NodeCoreError::ObjectConflict { object_id }),
        DurableCommitOutcome::Rejected(reason) => Err(NodeCoreError::DurableCommitRejected(reason)),
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason))
        }
    }
}
