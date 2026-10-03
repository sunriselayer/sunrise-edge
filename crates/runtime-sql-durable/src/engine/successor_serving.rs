//! DR-0189 shared SQL statements for first-successor activation and
//! serving. The mandatory phase-gated read lives once in `schema`
//! (`schema::read_successor_serving`); this module owns only the mutating
//! statements (the one-time activation UPDATE and the surrounding
//! transaction rules). A native facade opts in by implementing runtime
//! SuccessorServingRepository and forwarding to these inherent engine
//! methods. No facade gains this capability merely by using
//! SqlDurableEngine for its other traits.

use super::*;
use runtime::inactive_import::{ImportBinding, ImportProgress, NamespaceLifecycle};
use runtime::portable::PortableSnapshotToken;
use runtime::successor_serving::{
    SuccessorServingObservation, SuccessorServingSlot, decode_successor_serving_record,
    encode_successor_serving_slot,
};

fn reject(error: PreCommitFailure) -> DurableCommitRejection {
    error.into_commit_rejection()
}
fn conflict() -> DurableCommitRejection {
    DurableCommitRejection::ImportConflict
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    /// Reads the persisted physical namespace validator. This is raw
    /// continuity data; core independently verifies membership and signing
    /// authority before trusting it.
    pub fn read_namespace_validator(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            let metadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            Ok(self.namespace.validator_id())
        })
        .map_err(PreCommitFailure::into_read_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_successor_activation(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        record: &[u8],
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(domain) || transaction.domain() != domain {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        if !transaction.object_changes().reads().is_empty()
            || !transaction.object_changes().mutations().is_empty()
            || transaction.outbox().is_some()
        {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        let decoded = match decode_successor_serving_record(record) {
            Ok(decoded) => decoded,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::InvalidPersistedState,
                );
            }
        };
        if &decoded.binding != binding
            || &decoded.progress != progress
            || &decoded.activation_token != fresh_token
        {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict);
        }
        let serving_slot: SuccessorServingSlot =
            SuccessorServingSlot::Serving(Box::new(SuccessorServingObservation {
                record: record.to_vec(),
                binding: binding.clone(),
                progress: progress.clone(),
            }));
        let serving_bytes = match encode_successor_serving_slot(&serving_slot) {
            Ok(bytes) => bytes,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::InvalidPersistedState,
                );
            }
        };
        let inactive_bytes = match encode_successor_serving_slot(&SuccessorServingSlot::Inactive) {
            Ok(bytes) => bytes,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::InvalidPersistedState,
                );
            }
        };
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let decision = (|| -> Result<(), DurableCommitRejection> {
                    check_deadline(context, now).map_err(reject)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| reject(error.into()))?;
                    validate_authority(&metadata, context, now).map_err(reject)?;
                    let namespace_bytes = super::portable::portable_namespace_bytes(
                        &self.namespace,
                        &metadata.source_instance_id(),
                    )
                    .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
                    fresh_token
                        .check(
                            &namespace_bytes,
                            domain,
                            metadata.writer_fence(),
                            metadata.mutation_sequence(),
                        )
                        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
                    match metadata.lifecycle() {
                        NamespaceLifecycle::CompleteInactive {
                            binding: stored_binding,
                            progress: stored_progress,
                        } if stored_binding == binding && stored_progress == progress => {}
                        _ => return Err(DurableCommitRejection::ImportBindingMismatch),
                    }
                    if metadata.barrier().is_sealed() {
                        return Err(DurableCommitRejection::NamespaceSealed);
                    }
                    if metadata.successor_serving() != &SuccessorServingSlot::Inactive {
                        return Err(DurableCommitRejection::InactiveNamespace);
                    }
                    if decoded.validator != self.namespace.validator_id() {
                        return Err(conflict());
                    }
                    if receipt_exists(session, transaction.receipt().request_id())
                        .map_err(reject)?
                    {
                        return Err(DurableCommitRejection::RequestAlreadyCommitted);
                    }
                    if let Some(state) = transaction.state() {
                        validate_state_reads(session, state.reads())?;
                    }
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| reject(error.into()))?;
                    if let Some(state) = transaction.state() {
                        apply_state_mutations(session, state.reads(), state.mutations())?;
                    }
                    insert_structured_invocation(session, &transaction)?;
                    let updated = session
                        .exec(
                            "UPDATE durable_successor_serving SET serving = ?1
                             WHERE id = 1 AND serving = ?2",
                            &[
                                SqlValue::Blob(serving_bytes.clone()),
                                SqlValue::Blob(inactive_bytes.clone()),
                            ],
                        )
                        .map_err(|error| reject(error.into()))?;
                    if updated.rows_affected() != 1 {
                        return Err(DurableCommitRejection::InvalidPersistedState);
                    }
                    check_deadline_before_commit(session, context).map_err(reject)
                })();
                Ok(match decision {
                    Ok(()) => TransactionDecision::Commit(DurableCommitOutcome::Committed),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableCommitOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_commit_outcome,
        )
    }

    pub fn commit_successor_durable(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let domain = transaction.domain();
        if !self.domain_is_bound(domain) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        let decoded = match decode_successor_serving_record(&observation.record) {
            Ok(decoded) => decoded,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::InvalidPersistedState,
                );
            }
        };
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let decision = (|| -> Result<(), DurableCommitRejection> {
                    check_deadline(context, now).map_err(reject)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| reject(error.into()))?;
                    validate_authority(&metadata, context, now).map_err(reject)?;
                    match metadata.lifecycle() {
                        NamespaceLifecycle::CompleteInactive { binding, progress }
                            if binding == &observation.binding
                                && progress == &observation.progress => {}
                        _ => return Err(DurableCommitRejection::ImportBindingMismatch),
                    }
                    if metadata.barrier().is_sealed() {
                        return Err(DurableCommitRejection::NamespaceSealed);
                    }
                    if metadata.successor_serving().serving() != Some(observation) {
                        return Err(conflict());
                    }
                    if decoded.validator != self.namespace.validator_id() {
                        return Err(conflict());
                    }
                    validate_state_reads(session, transaction.reads())?;
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| reject(error.into()))?;
                    apply_state_mutations(session, transaction.reads(), transaction.mutations())?;
                    check_deadline_before_commit(session, context).map_err(reject)
                })();
                Ok(match decision {
                    Ok(()) => TransactionDecision::Commit(DurableCommitOutcome::Committed),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableCommitOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_commit_outcome,
        )
    }

    pub fn commit_successor_invocation(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let domain = transaction.domain();
        if !self.domain_is_bound(domain) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        let decoded = match decode_successor_serving_record(&observation.record) {
            Ok(decoded) => decoded,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::InvalidPersistedState,
                );
            }
        };
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let decision = (|| -> Result<(), DurableCommitRejection> {
                    check_deadline(context, now).map_err(reject)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| reject(error.into()))?;
                    validate_authority(&metadata, context, now).map_err(reject)?;
                    match metadata.lifecycle() {
                        NamespaceLifecycle::CompleteInactive { binding, progress }
                            if binding == &observation.binding
                                && progress == &observation.progress => {}
                        _ => return Err(DurableCommitRejection::ImportBindingMismatch),
                    }
                    if metadata.barrier().is_sealed() {
                        return Err(DurableCommitRejection::NamespaceSealed);
                    }
                    if metadata.successor_serving().serving() != Some(observation) {
                        return Err(conflict());
                    }
                    if decoded.validator != self.namespace.validator_id() {
                        return Err(conflict());
                    }
                    let receipt = transaction.receipt();
                    if receipt_exists(session, receipt.request_id()).map_err(reject)? {
                        return Err(DurableCommitRejection::RequestAlreadyCommitted);
                    }
                    if let Some(state) = transaction.state() {
                        validate_state_reads(session, state.reads())?;
                    }
                    validate_object_reads(
                        session,
                        &self.namespace,
                        transaction.object_changes().reads(),
                    )?;
                    let prepared = prepare_object_mutations(session, transaction.object_changes())?;
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| reject(error.into()))?;
                    if let Some(state) = transaction.state() {
                        apply_state_mutations(session, state.reads(), state.mutations())?;
                    }
                    apply_object_mutations(
                        session,
                        &self.namespace,
                        transaction.object_changes(),
                        &prepared,
                    )?;
                    insert_structured_invocation(session, &transaction)?;
                    check_deadline_before_commit(session, context).map_err(reject)
                })();
                Ok(match decision {
                    Ok(()) => TransactionDecision::Commit(DurableCommitOutcome::Committed),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableCommitOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_commit_outcome,
        )
    }
}
