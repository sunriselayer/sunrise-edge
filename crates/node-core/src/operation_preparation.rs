//! Owning business proposals, never authenticated or confirmed completions.
//!
//! Admission stays with each business owner. A direct wrapper commits the
//! proposal to a real store; ordered completion consumes its same exact parts
//! and merges protocol progress before the one actual commit. Nothing here
//! grants signing authority or acknowledges an intercepted write.

use crate::{NodeCoreError, NodeDedupRecord, NodeOutput, durable_reconciliation};
use runtime::{
    DurableInvocationTransaction, DurableOperationContext, DurableRequestReceipt,
    StructuredDurableDomainStateStore,
};

/// Exact retained output is distinct from a newly evaluated original proposal.
pub(crate) enum InvocationPreparation {
    Retained(NodeOutput),
    Prepared(PreparedBusinessInvocation),
}

/// An owning original transaction and output which have not been persisted.
/// Private fields prevent accidental independent replacement of the receipt
/// and output. Construction validates shape, not authentication or admission.
pub(crate) struct PreparedBusinessInvocation {
    transaction: DurableInvocationTransaction,
    output: NodeOutput,
}

impl PreparedBusinessInvocation {
    pub(crate) fn new(
        transaction: DurableInvocationTransaction,
        output: NodeOutput,
    ) -> Result<Self, NodeCoreError> {
        let receipt: &DurableRequestReceipt = transaction.receipt();
        let record: NodeDedupRecord = NodeDedupRecord::decode(receipt.canonical_bytes())?;
        if record.request_id().as_bytes() != receipt.request_id().as_bytes()
            || record.event_digest() != receipt.event_digest()
            || record.responses() != output.responses()
            || record.encode()? != receipt.canonical_bytes()
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "prepared business receipt differs from owning output",
            ));
        }
        Ok(Self {
            transaction,
            output,
        })
    }

    pub(crate) fn into_parts(self) -> (DurableInvocationTransaction, NodeOutput) {
        (self.transaction, self.output)
    }

    /// Uses the existing direct-handler reconciliation policy after an actual
    /// store call. Rejection and ambiguity never turn into prepared success.
    pub(crate) fn commit<S: StructuredDurableDomainStateStore>(
        self,
        store: &S,
        operation: &DurableOperationContext,
    ) -> Result<NodeOutput, NodeCoreError> {
        durable_reconciliation::committed_output(
            store.commit_invocation(operation, self.transaction),
            self.output,
        )
    }
}

impl InvocationPreparation {
    pub(crate) fn commit<S: StructuredDurableDomainStateStore>(
        self,
        store: &S,
        operation: &DurableOperationContext,
    ) -> Result<NodeOutput, NodeCoreError> {
        match self {
            Self::Retained(output) => Ok(output),
            Self::Prepared(prepared) => prepared.commit(store, operation),
        }
    }
}
