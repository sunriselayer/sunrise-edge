//! Bounded presence-only probe over the `durable_outbox_*` tables. Shares
//! the engine's ordinary namespace/schema/writer/deadline read transaction.
//! Every query is a closed literal, never a caller-supplied string.

use super::*;
use runtime::outbox_guard::{StructuredOutboxExclusionGuard, StructuredOutboxInventory};

fn any_row(session: &mut dyn SqlSession, sql: &str) -> Result<bool, PreCommitFailure> {
    Ok(session.exec(sql, &[])?.one()?.is_some())
}

/// Visible to the sibling `portable` module so the snapshot outbox-empty
/// check reuses this exact presence query instead of a second one.
pub(super) fn probe(
    session: &mut dyn SqlSession,
) -> Result<StructuredOutboxInventory, PreCommitFailure> {
    let delivery_present: bool = any_row(session, "SELECT 1 FROM durable_outbox_delivery LIMIT 1")?;
    let pending_delivery_present: bool = any_row(
        session,
        "SELECT 1 FROM durable_outbox_delivery WHERE completed <> 1 LIMIT 1",
    )?;
    let message_present: bool = any_row(
        session,
        "SELECT 1 FROM durable_outbox_delivery WHERE message_count <> 0 OR next_message_index <> 0 LIMIT 1",
    )? || any_row(
        session,
        "SELECT 1 FROM durable_outbox_messages LIMIT 1",
    )?;
    let attempt_present: bool = any_row(session, "SELECT 1 FROM durable_outbox_attempts LIMIT 1")?;
    Ok(StructuredOutboxInventory::new(
        delivery_present,
        message_present,
        delivery_present,
        pending_delivery_present,
        attempt_present,
    ))
}

impl<B: SqlBackend> StructuredOutboxExclusionGuard for SqlDurableEngine<B> {
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata: NamespaceMetadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            let value: StructuredOutboxInventory = probe(session)?;
            check_deadline_before_commit(session, context)?;
            Ok(value)
        })
        .map_err(PreCommitFailure::into_read_error)
    }
}
