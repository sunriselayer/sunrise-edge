//! Bounded memory OutgoingSealRepository, explicitly single-domain bound.
//!
//! Seal production is granted only when the fixture was constructed with
//! an explicit bound domain matching the transaction domain. An unbound
//! fixture never implicitly gains this capability for an arbitrary domain.

use super::*;

fn seal_outcome(result: Result<(), DurableCommitRejection>) -> DurableCommitOutcome {
    match result {
        Ok(()) => DurableCommitOutcome::Committed,
        Err(reason) => DurableCommitOutcome::Rejected(reason),
    }
}

fn require_seal_domain(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
) -> Result<(), DurableCommitRejection> {
    if data.bound_domain != Some(domain) {
        return Err(DurableCommitRejection::AtomicityDomainMismatch);
    }
    Ok(())
}

pub(super) fn seal_outbox_is_empty(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
) -> bool {
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    let messages_present: bool = data.outboxes.iter().any(|((row_domain, _), batch)| {
        *row_domain == domain_bytes && !batch.messages().is_empty()
    });
    let pending_present: bool = data.deliveries.iter().any(|((row_domain, _), delivery)| {
        *row_domain == domain_bytes && (!delivery.completed || delivery.next_index != 0)
    });
    !messages_present && !pending_present
}

impl OutgoingSealRepository for MemoryDurableStateStore {
    fn commit_seal_retention(
        &self,
        context: &DurableOperationContext,
        token: &portable::PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        seal_outcome((|| {
            let domain: AtomicityDomainId = transaction.domain();
            require_seal_domain(&data, domain)?;
            validate_memory_durable_commit_authority(&data, context)?;
            if !data.lifecycle.is_ordinary() {
                return Err(DurableCommitRejection::InactiveNamespace);
            }
            if data.outgoing_barrier.is_sealed() {
                return Err(DurableCommitRejection::NamespaceSealed);
            }
            let current: u64 = data
                .mutation_sequences
                .get(domain.as_bytes())
                .copied()
                .unwrap_or(0);
            token
                .check(
                    &data.portable_namespace,
                    domain,
                    data.active_writer_fence,
                    current,
                )
                .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            if !seal_outbox_is_empty(&data, domain) {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            let domain_bytes: [u8; 32] = *domain.as_bytes();
            let state = data.state_domains.get(&domain_bytes);
            validate_memory_durable_reads(state, transaction.reads())?;
            let revisions = memory_durable_revisions(state, transaction.mutations())?;
            let next: u64 = memory_next_mutation_sequence(&data, domain)
                .ok_or(DurableCommitRejection::CommitSequenceOverflow)?;
            let state = data.state_domains.entry(domain_bytes).or_default();
            apply_memory_durable_mutations(state, transaction.mutations.mutations, revisions)?;
            data.mutation_sequences.insert(domain_bytes, next);
            Ok(())
        })())
    }

    fn commit_seal_completion(
        &self,
        context: &DurableOperationContext,
        token: &portable::PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        if encode_seal_barrier(&sealed).is_err() {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        seal_outcome((|| {
            let domain: AtomicityDomainId = transaction.domain();
            require_seal_domain(&data, domain)?;
            validate_memory_durable_commit_authority(&data, context)?;
            if !data.lifecycle.is_ordinary() {
                return Err(DurableCommitRejection::InactiveNamespace);
            }
            if data.outgoing_barrier.is_sealed() {
                return Err(DurableCommitRejection::NamespaceSealed);
            }
            if transaction.receipt().request_id().as_bytes() != &sealed.request {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            if !transaction.object_changes().reads().is_empty()
                || !transaction.object_changes().mutations().is_empty()
            {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            if transaction
                .outbox()
                .is_some_and(|outbox| !outbox.messages().is_empty())
            {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            let current: u64 = data
                .mutation_sequences
                .get(domain.as_bytes())
                .copied()
                .unwrap_or(0);
            token
                .check(
                    &data.portable_namespace,
                    domain,
                    data.active_writer_fence,
                    current,
                )
                .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            if !seal_outbox_is_empty(&data, domain) {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            let domain_bytes: [u8; 32] = *domain.as_bytes();
            let request_key: MemoryDurableInvocationKey =
                (domain_bytes, *transaction.receipt().request_id().as_bytes());
            if data.receipts.contains_key(&request_key) {
                return Err(DurableCommitRejection::RequestAlreadyCommitted);
            }
            if data.outboxes.contains_key(&request_key)
                || data.deliveries.contains_key(&request_key)
            {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            let prepared_revisions = if let Some(section) = transaction.state() {
                let current_state = data.state_domains.get(&domain_bytes);
                validate_memory_durable_reads(current_state, section.reads())?;
                Some(memory_durable_revisions(
                    current_state,
                    section.mutations(),
                )?)
            } else {
                None
            };
            let next: u64 = memory_next_mutation_sequence(&data, domain)
                .ok_or(DurableCommitRejection::CommitSequenceOverflow)?;
            if let (Some(section), Some(revisions)) = (transaction.state(), prepared_revisions) {
                let mutations: Vec<StateMutationEntry> = section.mutations().to_vec();
                let state = data.state_domains.entry(domain_bytes).or_default();
                apply_memory_durable_mutations(state, mutations, revisions)?;
            }
            data.receipts
                .insert(request_key, transaction.receipt().clone());
            if let Some(outbox) = transaction.outbox() {
                let outbox = outbox.clone();
                data.deliveries.insert(
                    request_key,
                    MemoryOutboxDelivery {
                        next_index: 0,
                        available_at_unix_millis: 0,
                        active_lease: None,
                        attempt_count: 0,
                        completed: outbox.messages().is_empty(),
                    },
                );
                data.outboxes.insert(request_key, outbox);
            }
            data.outgoing_barrier = OutgoingBarrier::Sealed(sealed);
            data.mutation_sequences.insert(domain_bytes, next);
            Ok(())
        })())
    }
}
