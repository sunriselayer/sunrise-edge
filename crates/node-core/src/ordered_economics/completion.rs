//! One original-operation evaluator and completion assembler for live order,
//! signerless recovery and private reconstruction. Prepared business effects
//! are never durable confirmation. Coordinator progress is supplied separately
//! and joins the exact original receipt in one actual store invocation.
use super::engine::SealRetention;
use super::engine::{CommittedOrderedOperation, ExecutionWarrant, LegOutcome, MergedWrites};
use super::observed_read::ObservedBusinessReadView;
use super::*;
use crate::serving_authority::SealPort;
use runtime::{DurableObjectHeadRead, StateObservationSet};

/// An independently evaluated original operation, including refusal-deciding
/// observations. Fields and construction stay private to the owning evaluator;
/// decoded source outcomes or an empty reservation cannot manufacture it.
pub(super) struct PreparedOriginalCompletion {
    outcome: OrderedOutcome,
    business: DurableInvocationTransaction,
    reads: StateObservationSet,
    seal: Option<Box<SealRetention>>,
}

/// Actual store confirmation of an original completion. Neither an owning
/// preparation nor an unsigned source companion can construct this value.
pub(super) struct ConfirmedOriginalCompletion {
    outcome: OrderedOutcome,
}

/// The complete bounded invocation is still only a proposal. It contains the
/// original receipt explicitly and cannot expose an output until confirmation.
pub(super) struct AssembledOriginalCompletion {
    outcome: OrderedOutcome,
    transaction: DurableInvocationTransaction,
    seal: Option<Box<SealRetention>>,
}

impl AssembledOriginalCompletion {
    pub(super) fn confirm<S: StructuredDurableDomainStateStore>(
        self,
        gate: crate::serving_authority::ServingGate<'_>,
        store: &S,
        context: &DurableOperationContext,
    ) -> Result<ConfirmedOriginalCompletion, OrderedEconomicsError> {
        let AssembledOriginalCompletion {
            outcome: original_outcome,
            transaction,
            seal,
        } = self;
        let commit_outcome: DurableCommitOutcome = match seal {
            // DR-0187/DR-0191: the actual sealed-record commit is a different
            // port than the ordinary original-invocation commit; it alone
            // also retains the protected outgoing barrier. Resolved here
            // through the invocation gate (rather than carried inside
            // `SealRetention`) because this is the one real atomic commit
            // site, and the port must be the exact issuing store's own.
            Some(retention) => match gate.seal_port(store) {
                Ok(port) => port.commit_completion(
                    context,
                    &retention.token,
                    transaction,
                    retention.barrier,
                ),
                Err(_) => {
                    return Err(OrderedEconomicsError::Prerequisite(
                        "ordered Seal completion requires the OutgoingSealRepository capability",
                    ));
                }
            },
            None => gate.commit_invocation(store, context, transaction),
        };
        match commit_outcome {
            DurableCommitOutcome::Committed => Ok(ConfirmedOriginalCompletion {
                outcome: original_outcome,
            }),
            outcome => Err(super::engine::commit_outcome_error(outcome)),
        }
    }
}

impl ConfirmedOriginalCompletion {
    pub(super) fn into_outcome(self) -> OrderedOutcome {
        self.outcome
    }
}

impl PreparedOriginalCompletion {
    pub(super) const fn outcome(&self) -> &OrderedOutcome {
        &self.outcome
    }

    pub(super) fn receipt(&self) -> &DurableRequestReceipt {
        self.business.receipt()
    }

    /// The only original-completion assembly path. The runtime owner merges
    /// state contributions; this owner merges object-head observations and
    /// preserves original object mutations, receipt and outbox unchanged.
    pub(super) fn confirm<S: StructuredDurableDomainStateStore>(
        self,
        gate: crate::serving_authority::ServingGate<'_>,
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        coordinator: MergedWrites,
        prerequisite_heads: &[DurableObjectHeadRead],
    ) -> Result<ConfirmedOriginalCompletion, OrderedEconomicsError> {
        self.assemble(domain, coordinator, prerequisite_heads)?
            .confirm(gate, store, context)
    }

    pub(super) fn assemble(
        self,
        domain: AtomicityDomainId,
        mut coordinator: MergedWrites,
        prerequisite_heads: &[DurableObjectHeadRead],
    ) -> Result<AssembledOriginalCompletion, OrderedEconomicsError> {
        if self.business.domain() != domain {
            return Err(RuntimeError::AtomicityDomainMismatch.into());
        }
        coordinator.merge_observations(&self.reads)?;
        if let Some(state) = self.business.state() {
            coordinator.merge_handler_state(state)?;
        }
        let mut heads: BTreeMap<ObjectId, DurableObjectHeadRead> = BTreeMap::new();
        for head in self
            .business
            .object_changes()
            .reads()
            .iter()
            .chain(prerequisite_heads)
        {
            if let Some(previous) = heads.get(&head.object_id()) {
                if previous != head {
                    return Err(NodeCoreError::ObjectConflict {
                        object_id: head.object_id(),
                    }
                    .into());
                }
            } else {
                heads.insert(head.object_id(), head.clone());
            }
        }
        let objects: DurableObjectChanges = DurableObjectChanges::new(
            heads.into_values().collect(),
            self.business.object_changes().mutations().to_vec(),
        )?;
        let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
            domain,
            Some(coordinator.into_state_transaction(domain)?),
            objects,
            self.business.receipt().clone(),
            self.business.outbox().cloned(),
        )?;
        Ok(AssembledOriginalCompletion {
            outcome: self.outcome,
            transaction,
            seal: self.seal,
        })
    }
}

/// Finish even if the owner stopped. A poisoned physical read attempt cannot
/// retain a decision or leak a local observation rejection as backend ambiguity.
fn finish_handler_attempt<S: StructuredStateReader>(
    observed: ObservedBusinessReadView<'_, S>,
    result: LegOutcome,
) -> Result<(StateObservationSet, LegOutcome), OrderedEconomicsError> {
    let result: Result<LegOutcome, OrderedEconomicsError> = match result {
        LegOutcome::Stop(error) => Err(error),
        result => Ok(result),
    };
    observed.finish_with(result)
}

/// Evaluates once, from proof-bound original bytes and the owning execution
/// warrant. Original receipt reconciliation must already have run. A typed
/// healthy refusal produces no business effects; unknown prerequisites stop.
pub(super) fn prepare_original_completion<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    operation: &CommittedOrderedOperation<'_>,
    warrant: &ExecutionWarrant<'_>,
    seal_port: Option<SealPort<'_>>,
) -> Result<PreparedOriginalCompletion, OrderedEconomicsError> {
    let candidate: &OrderedCandidate = operation.candidate();
    let admission: &OrderedLegAdmission<'_> = warrant.admission(candidate.request_id)?;
    let (reads, result): (StateObservationSet, LegOutcome) = match admission.gate {
        crate::serving_authority::ServingGate::Replay(_) => {
            admission
                .gate
                .require_reader(store, context, env.policy.domain())?;
            let result: LegOutcome =
                evaluate_original(store, context, env, operation, admission, seal_port);
            match result {
                LegOutcome::Stop(error) => return Err(error),
                result => (StateObservationSet::new(env.policy.domain()), result),
            }
        }
        _ => {
            let observed: ObservedBusinessReadView<'_, S> =
                ObservedBusinessReadView::new(store, env.policy.domain());
            let result: LegOutcome =
                evaluate_original(&observed, context, env, operation, admission, seal_port);
            finish_handler_attempt(observed, result)?
        }
    };
    prepare_evaluated_completion(env, operation, reads, result)
}

/// Exactly one evaluator for the existing owning handlers. Private replay
/// reads the serial memory issuer directly so address identity remains exact;
/// live paths additionally collect refusal-deciding physical CAS reads.
fn evaluate_original<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    operation: &CommittedOrderedOperation<'_>,
    admission: &OrderedLegAdmission<'_>,
    seal_port: Option<SealPort<'_>>,
) -> LegOutcome {
    let candidate: &OrderedCandidate = operation.candidate();
    match super::policy::authenticate_ordered_operation(env, candidate) {
        Ok(authenticated) => {
            if authenticated.digest() != operation.digest() {
                LegOutcome::Stop(OrderedEconomicsError::Prerequisite(
                    "authenticated original differs from committed operation",
                ))
            } else {
                super::engine::execute_candidate(
                    store,
                    context,
                    env,
                    &authenticated,
                    Some(admission),
                    operation,
                    seal_port,
                )
            }
        }
        // Preserve the historical storage-independent refusal contract. This
        // failure does not issue authenticated evidence; causal admission has
        // already required successful authentication before reaching replay.
        Err(error) => super::engine::disposition(candidate.request_id, error),
    }
}

fn prepare_evaluated_completion(
    env: &OrderedEconomicsEnvironment<'_>,
    operation: &CommittedOrderedOperation<'_>,
    reads: StateObservationSet,
    result: LegOutcome,
) -> Result<PreparedOriginalCompletion, OrderedEconomicsError> {
    let candidate: &OrderedCandidate = operation.candidate();
    let digest: Digest32 = operation.digest();
    let domain: AtomicityDomainId = env.policy.domain();
    let (output, business, seal): (
        NodeOutput,
        DurableInvocationTransaction,
        Option<Box<SealRetention>>,
    ) = match result {
        LegOutcome::PreparedInvocation(prepared) => {
            let (business, output) = prepared.into_parts();
            (output, business, None)
        }
        LegOutcome::PreparedState(prepared) => {
            let (state, output) = prepared.into_parts();
            let business: DurableInvocationTransaction = DurableInvocationTransaction::new(
                domain,
                Some(DurableStateTransaction::from(state)),
                DurableObjectChanges::empty(),
                super::engine::build_receipt(candidate.request_id, digest, &output)?,
                None,
            )?;
            (output, business, None)
        }
        LegOutcome::AcceptedRetainedEvidence(output) | LegOutcome::Refused(output) => {
            let business: DurableInvocationTransaction = DurableInvocationTransaction::new(
                domain,
                None,
                DurableObjectChanges::empty(),
                super::engine::build_receipt(candidate.request_id, digest, &output)?,
                None,
            )?;
            (output, business, None)
        }
        LegOutcome::AcceptedSeal { output, retention } => {
            let business: DurableInvocationTransaction = DurableInvocationTransaction::new(
                domain,
                None,
                DurableObjectChanges::empty(),
                super::engine::build_receipt(candidate.request_id, digest, &output)?,
                None,
            )?;
            (output, business, Some(Box::new(retention)))
        }
        LegOutcome::Stop(error) => return Err(error),
    };
    if business.domain() != domain {
        return Err(RuntimeError::AtomicityDomainMismatch.into());
    }
    let request: DurableRequestId = DurableRequestId::new(candidate.request_id)
        .map_err(|_| NodeCoreError::PersistenceInvariant("prepared original request identity"))?;
    let receipt: &DurableRequestReceipt = business.receipt();
    let record: NodeDedupRecord = NodeDedupRecord::decode(receipt.canonical_bytes())?;
    if receipt.request_id() != request
        || record.request_id().as_bytes() != &candidate.request_id
        || record.event_digest() != receipt.event_digest()
        || record.responses() != output.responses()
    {
        return Err(OrderedEconomicsError::Prerequisite(
            "prepared original receipt differs from owning execution output",
        ));
    }
    Ok(PreparedOriginalCompletion {
        outcome: OrderedOutcome {
            candidate_digest: digest,
            request_id: candidate.request_id,
            block_height: operation.height(),
            block_digest: operation.block_digest(),
            output,
        },
        business,
        reads,
        seal,
    })
}

#[cfg(test)]
mod tests;
