//! DR-0187 shared SQL statements for Seal signing retention and completion.
//!
//! Every statement text and validation rule lives here once; a native
//! facade opts in by implementing runtime OutgoingSealRepository and
//! forwarding to these inherent engine methods. No facade gains this
//! capability merely by using SqlDurableEngine for its other traits.

use super::*;
use runtime::outgoing_seal::{OutgoingBarrier, SealBarrier, encode_outgoing_barrier};
use runtime::portable::PortableSnapshotToken;

impl<B: SqlBackend> SqlDurableEngine<B> {
    /// Commits one token-checked state transaction while the barrier is
    /// still Unsealed. This never selects or installs the Seal target.
    pub fn commit_seal_retention(
        &self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(transaction.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let decision = (|| -> Result<(), DurableCommitRejection> {
                    check_deadline(context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    validate_authority(&metadata, context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    if !metadata.lifecycle().is_ordinary() {
                        return Err(DurableCommitRejection::InactiveNamespace);
                    }
                    if metadata.barrier().is_sealed() {
                        return Err(DurableCommitRejection::NamespaceSealed);
                    }
                    let namespace_bytes = super::portable::portable_namespace_bytes(
                        &self.namespace,
                        &metadata.source_instance_id(),
                    )
                    .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
                    token
                        .check(
                            &namespace_bytes,
                            transaction.domain(),
                            metadata.writer_fence(),
                            metadata.mutation_sequence(),
                        )
                        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
                    let inventory = super::outbox_guard::probe(session)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    if inventory.blocks_exclusion() {
                        return Err(DurableCommitRejection::InvalidPersistedState);
                    }
                    validate_state_reads(session, transaction.reads())?;
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    apply_state_mutations(session, transaction.reads(), transaction.mutations())?;
                    check_deadline_before_commit(session, context)
                        .map_err(PreCommitFailure::into_commit_rejection)
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

    /// Commits the original Seal invocation and installs sealed as the
    /// permanent barrier record, atomically with the invocation and the
    /// checked mutation-sequence advance. sealed never becomes Unsealed.
    pub fn commit_seal_completion(
        &self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(transaction.domain()) {
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
                    check_deadline(context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    validate_authority(&metadata, context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    if !metadata.lifecycle().is_ordinary() {
                        return Err(DurableCommitRejection::InactiveNamespace);
                    }
                    if metadata.barrier().is_sealed() {
                        return Err(DurableCommitRejection::NamespaceSealed);
                    }
                    let namespace_bytes = super::portable::portable_namespace_bytes(
                        &self.namespace,
                        &metadata.source_instance_id(),
                    )
                    .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
                    token
                        .check(
                            &namespace_bytes,
                            transaction.domain(),
                            metadata.writer_fence(),
                            metadata.mutation_sequence(),
                        )
                        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
                    let inventory = super::outbox_guard::probe(session)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    if inventory.blocks_exclusion() {
                        return Err(DurableCommitRejection::InvalidPersistedState);
                    }
                    if receipt_exists(session, transaction.receipt().request_id())
                        .map_err(PreCommitFailure::into_commit_rejection)?
                    {
                        return Err(DurableCommitRejection::RequestAlreadyCommitted);
                    }
                    if let Some(state) = transaction.state() {
                        validate_state_reads(session, state.reads())?;
                    }
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
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
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    if updated.rows_affected() != 1 {
                        return Err(DurableCommitRejection::InvalidPersistedState);
                    }
                    check_deadline_before_commit(session, context)
                        .map_err(PreCommitFailure::into_commit_rejection)
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
