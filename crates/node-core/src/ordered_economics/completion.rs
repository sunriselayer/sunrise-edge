//! One original-operation evaluator and completion assembler for live order,
//! signerless recovery and private reconstruction. Prepared business effects
//! are never durable confirmation. Coordinator progress is supplied separately
//! and joins the exact original receipt in one actual store invocation.
use super::engine::{CommittedOrderedOperation, ExecutionWarrant, LegOutcome, MergedWrites};
use super::staging::{HandlerPreparation, PreparedHandlerWrite};
use super::*;
use runtime::DurableObjectHeadRead;

/// An independently evaluated original operation, including refusal-deciding
/// observations. Fields and construction stay private to the owning evaluator;
/// decoded source outcomes or an empty reservation cannot manufacture it.
pub(super) struct PreparedOriginalCompletion {
    outcome: OrderedOutcome,
    business: DurableInvocationTransaction,
    reads: BTreeMap<Vec<u8>, StateRevision>,
}

/// Actual store confirmation of an original completion. Neither the capture
/// adapter nor an unsigned source companion can construct this value.
pub(super) struct ConfirmedOriginalCompletion {
    outcome: OrderedOutcome,
}

/// The complete bounded invocation is still only a proposal. It contains the
/// original receipt explicitly and cannot expose an output until confirmation.
pub(super) struct AssembledOriginalCompletion {
    outcome: OrderedOutcome,
    transaction: DurableInvocationTransaction,
}

impl AssembledOriginalCompletion {
    pub(super) fn confirm<S: StructuredDurableDomainStateStore>(
        self,
        store: &S,
        context: &DurableOperationContext,
    ) -> Result<ConfirmedOriginalCompletion, OrderedEconomicsError> {
        match store.commit_invocation(context, self.transaction) {
            DurableCommitOutcome::Committed => Ok(ConfirmedOriginalCompletion {
                outcome: self.outcome,
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
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        coordinator: MergedWrites,
        prerequisite_heads: &[DurableObjectHeadRead],
    ) -> Result<ConfirmedOriginalCompletion, OrderedEconomicsError> {
        self.assemble(domain, coordinator, prerequisite_heads)?
            .confirm(store, context)
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
        for (key, revision) in self.reads {
            coordinator.read(key, revision)?;
        }
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
        })
    }
}

/// Poisoned preparation takes precedence over the handler's error. Adapter
/// interception is not a dispatched backend operation, so even a propagated
/// sentinel must be reported as the local invariant that actually failed.
fn finish_handler_attempt<S: StructuredDurableDomainStateStore>(
    staging: &StagingStore<'_, S>,
    result: LegOutcome,
) -> Result<(HandlerPreparation, LegOutcome), OrderedEconomicsError> {
    let prepared: HandlerPreparation = staging.finish()?;
    match result {
        LegOutcome::Stop(error) => Err(error),
        result => Ok((prepared, result)),
    }
}

/// Evaluates once, from proof-bound original bytes and the owning execution
/// warrant. Original receipt reconciliation must already have run. A typed
/// healthy refusal produces no business effects; unknown prerequisites stop.
pub(super) fn prepare_original_completion<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    operation: &CommittedOrderedOperation<'_>,
    warrant: &ExecutionWarrant<'_>,
) -> Result<PreparedOriginalCompletion, OrderedEconomicsError> {
    let candidate: &OrderedCandidate = operation.candidate();
    let admission: &OrderedLegAdmission<'_> = warrant.admission(candidate.request_id)?;
    let staging: StagingStore<'_, S> = StagingStore::new(store);
    let result: LegOutcome = match super::policy::authenticate_ordered_operation(env, candidate) {
        Ok(authenticated) => {
            if authenticated.digest() != operation.digest() {
                return Err(OrderedEconomicsError::Prerequisite(
                    "authenticated original differs from committed operation",
                ));
            }
            super::engine::execute_candidate(
                &staging,
                context,
                env,
                &authenticated,
                Some(admission),
                operation.height(),
            )
        }
        // Preserve the historical storage-independent refusal contract. This
        // failure does not issue authenticated evidence; causal admission has
        // already required successful authentication before reaching replay.
        Err(error) => super::engine::disposition(candidate.request_id, error),
    };
    let (prepared, result): (HandlerPreparation, LegOutcome) =
        finish_handler_attempt(&staging, result)?;
    let digest: Digest32 = operation.digest();
    let domain: AtomicityDomainId = env.policy.domain();
    let (output, business): (NodeOutput, DurableInvocationTransaction) = match result {
        LegOutcome::Accepted(output) => {
            let business: DurableInvocationTransaction = match prepared.write {
                Some(PreparedHandlerWrite::Invocation(invocation)) => *invocation,
                Some(PreparedHandlerWrite::State(state)) => DurableInvocationTransaction::new(
                    domain,
                    Some(DurableStateTransaction::from(state)),
                    DurableObjectChanges::empty(),
                    super::engine::build_receipt(candidate.request_id, digest, &output)?,
                    None,
                )?,
                None => {
                    return Err(OrderedEconomicsError::Prerequisite(
                        "ordered accepted candidate produced no prepared transaction",
                    ));
                }
            };
            (output, business)
        }
        LegOutcome::AcceptedRetainedEvidence(output) | LegOutcome::Refused(output) => {
            if prepared.write.is_some() {
                return Err(OrderedEconomicsError::Prerequisite(
                    "ordered no-effect completion unexpectedly prepared a business write",
                ));
            }
            let business: DurableInvocationTransaction = DurableInvocationTransaction::new(
                domain,
                None,
                DurableObjectChanges::empty(),
                super::engine::build_receipt(candidate.request_id, digest, &output)?,
                None,
            )?;
            (output, business)
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
        reads: prepared.reads,
    })
}

#[cfg(test)]
mod tests;
