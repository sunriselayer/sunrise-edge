//! Bounded memory SuccessorServingRepository, explicitly single-domain
//! bound through [`MemoryDurableStateStore::new_successor_bound`]. Every
//! other memory constructor keeps the slot mandatory `Inactive` and never
//! exposes this capability.

use super::*;

fn outcome(result: Result<(), DurableCommitRejection>) -> DurableCommitOutcome {
    match result {
        Ok(()) => DurableCommitOutcome::Committed,
        Err(reason) => DurableCommitOutcome::Rejected(reason),
    }
}

fn successor_authority(
    data: &MemoryDurableStoreData,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<ValidatorId, DurableCommitRejection> {
    if data.bound_domain != Some(domain) {
        return Err(DurableCommitRejection::AtomicityDomainMismatch);
    }
    validate_memory_durable_commit_authority(data, context)?;
    data.successor_namespace_validator
        .ok_or(DurableCommitRejection::InvalidPersistedState)
}

impl SuccessorServingRepository for MemoryDurableStateStore {
    fn read_namespace_validator(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError> {
        let data = self
            .inner
            .read()
            .map_err(|_| DurableReadError::Unavailable)?;
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        data.successor_namespace_validator
            .ok_or(DurableReadError::InvalidPersistedState)
    }

    fn commit_successor_activation(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        record: &[u8],
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        outcome((|| {
            let validator = successor_authority(&data, context, domain)?;
            if transaction.domain() != domain {
                return Err(DurableCommitRejection::AtomicityDomainMismatch);
            }
            let current: u64 = data
                .mutation_sequences
                .get(domain.as_bytes())
                .copied()
                .unwrap_or(0);
            fresh_token
                .check(
                    &data.portable_namespace,
                    domain,
                    data.active_writer_fence,
                    current,
                )
                .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            match &data.lifecycle {
                NamespaceLifecycle::CompleteInactive {
                    binding: stored_binding,
                    progress: stored_progress,
                } if stored_binding == binding && stored_progress == progress => {}
                _ => return Err(DurableCommitRejection::ImportBindingMismatch),
            }
            if data.outgoing_barrier.is_sealed() {
                return Err(DurableCommitRejection::NamespaceSealed);
            }
            if data.successor_serving != SuccessorServingSlot::Inactive {
                return Err(DurableCommitRejection::InactiveNamespace);
            }
            let decoded: SuccessorServingRecord = decode_successor_serving_record(record)
                .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            if decoded.binding != *binding
                || decoded.progress != *progress
                || decoded.activation_token != *fresh_token
                || decoded.validator != validator
            {
                return Err(DurableCommitRejection::ImportConflict);
            }
            if !transaction.object_changes().reads().is_empty()
                || !transaction.object_changes().mutations().is_empty()
            {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            if transaction.outbox().is_some() {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
            let domain_bytes: [u8; 32] = *domain.as_bytes();
            let request_key: MemoryDurableInvocationKey =
                (domain_bytes, *transaction.receipt().request_id().as_bytes());
            if data.receipts.contains_key(&request_key) {
                return Err(DurableCommitRejection::RequestAlreadyCommitted);
            }
            let prepared_revisions = if let Some(section) = transaction.state() {
                let state = data.state_domains.get(&domain_bytes);
                validate_memory_durable_reads(state, section.reads())?;
                Some(memory_durable_revisions(state, section.mutations())?)
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
            data.successor_serving = SuccessorServingSlot::Serving(SuccessorServingObservation {
                record: record.to_vec(),
                binding: binding.clone(),
                progress: progress.clone(),
            });
            data.mutation_sequences.insert(domain_bytes, next);
            Ok(())
        })())
    }

    fn commit_successor_durable(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        outcome((|| {
            let domain: AtomicityDomainId = transaction.domain();
            let validator = successor_authority(&data, context, domain)?;
            match &data.lifecycle {
                NamespaceLifecycle::CompleteInactive { binding, progress }
                    if *binding == observation.binding && *progress == observation.progress => {}
                _ => return Err(DurableCommitRejection::ImportBindingMismatch),
            }
            if data.outgoing_barrier.is_sealed() {
                return Err(DurableCommitRejection::NamespaceSealed);
            }
            match &data.successor_serving {
                SuccessorServingSlot::Serving(current) if current.record == observation.record => {}
                _ => return Err(DurableCommitRejection::ImportConflict),
            }
            let decoded: SuccessorServingRecord =
                decode_successor_serving_record(&observation.record)
                    .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            if decoded.validator != validator {
                return Err(DurableCommitRejection::ImportConflict);
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

    fn commit_successor_invocation(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let Ok(mut data) = self.inner.write() else {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
        };
        outcome((|| {
            let domain: AtomicityDomainId = transaction.domain();
            let validator = successor_authority(&data, context, domain)?;
            match &data.lifecycle {
                NamespaceLifecycle::CompleteInactive { binding, progress }
                    if *binding == observation.binding && *progress == observation.progress => {}
                _ => return Err(DurableCommitRejection::ImportBindingMismatch),
            }
            if data.outgoing_barrier.is_sealed() {
                return Err(DurableCommitRejection::NamespaceSealed);
            }
            match &data.successor_serving {
                SuccessorServingSlot::Serving(current) if current.record == observation.record => {}
                _ => return Err(DurableCommitRejection::ImportConflict),
            }
            let decoded: SuccessorServingRecord =
                decode_successor_serving_record(&observation.record)
                    .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            if decoded.validator != validator {
                return Err(DurableCommitRejection::ImportConflict);
            }
            let domain_bytes: [u8; 32] = *domain.as_bytes();
            let request_key: MemoryDurableInvocationKey =
                (domain_bytes, *transaction.receipt.request_id.as_bytes());
            if data.receipts.contains_key(&request_key) {
                return Err(DurableCommitRejection::RequestAlreadyCommitted);
            }
            let revisions = if let Some(state_transaction) = transaction.state.as_ref() {
                let state = data.state_domains.get(&domain_bytes);
                validate_memory_durable_reads(state, state_transaction.reads())?;
                memory_durable_revisions(state, state_transaction.mutations())?
            } else {
                Vec::new()
            };
            validate_memory_object_reads(&data, domain, transaction.objects.reads())?;
            let prepared_objects =
                prepare_memory_object_mutations(&data, domain, &transaction.objects)?;
            let delivery = transaction
                .outbox
                .as_ref()
                .map(|outbox| MemoryOutboxDelivery {
                    next_index: 0,
                    available_at_unix_millis: 0,
                    active_lease: None,
                    attempt_count: 0,
                    completed: outbox.messages().is_empty(),
                });
            let next: u64 = memory_next_mutation_sequence(&data, domain)
                .ok_or(DurableCommitRejection::CommitSequenceOverflow)?;
            if let Some(state_transaction) = transaction.state {
                let state = data.state_domains.entry(domain_bytes).or_default();
                apply_memory_durable_mutations(
                    state,
                    state_transaction.mutations.mutations,
                    revisions,
                )?;
            }
            apply_memory_object_mutations(&mut data, domain, prepared_objects);
            data.receipts.insert(request_key, transaction.receipt);
            if let Some(outbox) = transaction.outbox {
                data.outboxes.insert(request_key, outbox);
            }
            if let Some(delivery) = delivery {
                data.deliveries.insert(request_key, delivery);
            }
            data.mutation_sequences.insert(domain_bytes, next);
            Ok(())
        })())
    }
}

#[cfg(test)]
mod tests;
