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
use runtime::outgoing_seal::{OutgoingBarrier, SealBarrier, encode_outgoing_barrier};
use runtime::portable::PortableSnapshotToken;
use runtime::successor_serving::{
    SuccessorServingObservation, SuccessorServingRecord, SuccessorServingSlot,
    decode_successor_serving_record, encode_successor_serving_slot,
};

fn reject(error: PreCommitFailure) -> DurableCommitRejection {
    error.into_commit_rejection()
}
fn conflict() -> DurableCommitRejection {
    DurableCommitRejection::ImportConflict
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    /// Shared local continuity checks for all writes to a serving successor.
    /// Record decoding stays at each public entry point to retain its
    /// established preflight rejection order.
    fn successor_serving_preconditions(
        &self,
        session: &mut dyn SqlSession,
        context: &DurableOperationContext,
        now: u64,
        observation: &SuccessorServingObservation,
        decoded: &SuccessorServingRecord,
    ) -> Result<NamespaceMetadata, DurableCommitRejection> {
        check_deadline(context, now).map_err(reject)?;
        let metadata: NamespaceMetadata = schema::verify_namespace(session, &self.namespace)
            .map_err(|error| reject(error.into()))?;
        validate_authority(&metadata, context, now).map_err(reject)?;
        match metadata.lifecycle() {
            NamespaceLifecycle::CompleteInactive { binding, progress }
                if binding == &observation.binding && progress == &observation.progress => {}
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
        Ok(metadata)
    }

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
                    let metadata: NamespaceMetadata = self.successor_serving_preconditions(
                        session,
                        context,
                        now,
                        observation,
                        &decoded,
                    )?;
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
                    let metadata: NamespaceMetadata = self.successor_serving_preconditions(
                        session,
                        context,
                        now,
                        observation,
                        &decoded,
                    )?;
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

impl<B: SqlBackend> SqlDurableEngine<B> {
    /// Seal additionally fences the complete local snapshot and outbox
    /// inventory after the ordinary successor continuity checks.
    fn successor_seal_preconditions(
        &self,
        session: &mut dyn SqlSession,
        context: &DurableOperationContext,
        now: u64,
        observation: &SuccessorServingObservation,
        decoded: &SuccessorServingRecord,
        token: &PortableSnapshotToken,
    ) -> Result<NamespaceMetadata, DurableCommitRejection> {
        let metadata: NamespaceMetadata =
            self.successor_serving_preconditions(session, context, now, observation, decoded)?;
        let namespace_bytes: Vec<u8> = super::portable::portable_namespace_bytes(
            &self.namespace,
            &metadata.source_instance_id(),
        )
        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        token
            .check(
                &namespace_bytes,
                self.namespace.domain(),
                metadata.writer_fence(),
                metadata.mutation_sequence(),
            )
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let inventory = super::outbox_guard::probe(session).map_err(reject)?;
        if inventory.blocks_exclusion() {
            return Err(DurableCommitRejection::InvalidPersistedState);
        }
        Ok(metadata)
    }

    /// Commits one token-checked state transaction while the outgoing
    /// barrier of this successor namespace is still `Unsealed`, after
    /// rechecking the exact installed `Serving` observation inside this
    /// same transaction. This never selects or installs the Seal target,
    /// exactly as `commit_seal_retention` for the Ordinary engine.
    pub fn commit_successor_seal_retention(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken,
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
                    let metadata: NamespaceMetadata = self.successor_seal_preconditions(
                        session,
                        context,
                        now,
                        observation,
                        &decoded,
                        token,
                    )?;
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

    /// Commits the Seal invocation that retires this successor namespace
    /// and installs `sealed` as the permanent barrier record, atomically
    /// with the invocation and the checked mutation-sequence advance.
    /// `sealed` never becomes `Unsealed`. No object reads or mutations are
    /// ever accepted here.
    pub fn commit_successor_seal_completion(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        let domain = transaction.domain();
        if !self.domain_is_bound(domain) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        if transaction.receipt().request_id().as_bytes() != &sealed.request {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        if !transaction.object_changes().reads().is_empty()
            || !transaction.object_changes().mutations().is_empty()
        {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        if transaction
            .outbox()
            .is_some_and(|outbox| !outbox.messages().is_empty())
        {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        let decoded = match decode_successor_serving_record(&observation.record) {
            Ok(decoded) => decoded,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::InvalidPersistedState,
                );
            }
        };
        let unsealed_frame_bytes: Vec<u8> =
            match encode_outgoing_barrier(&OutgoingBarrier::Unsealed) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return DurableCommitOutcome::Rejected(
                        DurableCommitRejection::InvalidPersistedState,
                    );
                }
            };
        let sealed_frame_bytes: Vec<u8> =
            match encode_outgoing_barrier(&OutgoingBarrier::Sealed(sealed)) {
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
                    let metadata: NamespaceMetadata = self.successor_seal_preconditions(
                        session,
                        context,
                        now,
                        observation,
                        &decoded,
                        token,
                    )?;
                    // Structural continuity only; core independently
                    // authenticates the live epoch and Seal request.
                    if observation.binding.context.epoch.get().checked_add(1)
                        != Some(sealed.outgoing_epoch.get())
                    {
                        return Err(conflict());
                    }
                    if receipt_exists(session, transaction.receipt().request_id())
                        .map_err(reject)?
                    {
                        return Err(DurableCommitRejection::RequestAlreadyCommitted);
                    }
                    let request_rows = session
                        .exec(
                            "SELECT 1 FROM durable_outbox_delivery WHERE request_id = ?1
                             UNION ALL
                             SELECT 1 FROM durable_outbox_messages WHERE request_id = ?1
                             LIMIT 1",
                            &[SqlValue::Blob(
                                transaction.receipt().request_id().as_bytes().to_vec(),
                            )],
                        )
                        .map_err(|error| reject(error.into()))?;
                    if request_rows
                        .one()
                        .map_err(|error| reject(error.into()))?
                        .is_some()
                    {
                        return Err(DurableCommitRejection::InvalidPersistedState);
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
                            "UPDATE durable_outgoing_barrier SET barrier = ?1
                             WHERE id = 1 AND barrier = ?2",
                            &[
                                SqlValue::Blob(sealed_frame_bytes.clone()),
                                SqlValue::Blob(unsealed_frame_bytes.clone()),
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
}
