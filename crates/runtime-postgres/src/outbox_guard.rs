//! Namespace-scoped presence-only probe over the `sunrise_edge.outbox_*`
//! tables. Shares the store's ordinary namespace/schema/writer/deadline
//! read transaction.

use super::*;
use runtime::outbox_guard::{StructuredOutboxExclusionGuard, StructuredOutboxInventory};

const NAMESPACE_PREFIX: &str =
    "chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3";

fn any_row(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    sql: &str,
) -> Result<bool, PreCommitFailure> {
    transaction
        .query_opt(
            sql,
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .map(|row| row.is_some())
        .map_err(|error| PreCommitFailure::from_database(&error))
}

fn probe(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
) -> Result<StructuredOutboxInventory, PreCommitFailure> {
    let batch_sql: String =
        format!("SELECT 1 FROM sunrise_edge.outbox_batches WHERE {NAMESPACE_PREFIX} LIMIT 1");
    let message_sql: String =
        format!("SELECT 1 FROM sunrise_edge.outbox_messages WHERE {NAMESPACE_PREFIX} LIMIT 1");
    let delivery_sql: String =
        format!("SELECT 1 FROM sunrise_edge.outbox_delivery WHERE {NAMESPACE_PREFIX} LIMIT 1");
    let attempt_sql: String = format!(
        "SELECT 1 FROM sunrise_edge.outbox_delivery_attempts WHERE {NAMESPACE_PREFIX} LIMIT 1"
    );
    let batch_present: bool = any_row(transaction, namespace, &batch_sql)?;
    let nonempty_batch_sql: String = format!(
        "SELECT 1 FROM sunrise_edge.outbox_batches WHERE {NAMESPACE_PREFIX} AND message_count <> 0 LIMIT 1"
    );
    let message_present: bool = any_row(transaction, namespace, &message_sql)?
        || any_row(transaction, namespace, &nonempty_batch_sql)?;
    let nonzero_cursor_sql: String = format!(
        "SELECT 1 FROM sunrise_edge.outbox_delivery WHERE {NAMESPACE_PREFIX} AND next_message_index <> 0 LIMIT 1"
    );
    let message_present: bool =
        message_present || any_row(transaction, namespace, &nonzero_cursor_sql)?;
    let delivery_present: bool = any_row(transaction, namespace, &delivery_sql)?;
    let attempt_present: bool = any_row(transaction, namespace, &attempt_sql)?;
    let pending_delivery_present: bool = any_pending_delivery(transaction, namespace)?;
    Ok(StructuredOutboxInventory::new(
        batch_present,
        message_present,
        delivery_present,
        pending_delivery_present,
        attempt_present,
    ))
}

impl<M> StructuredOutboxExclusionGuard for PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                runtime::RuntimeError::AtomicityDomainMismatch,
            ));
        }
        let mut client = self
            .acquire(context)
            .map_err(PreCommitFailure::into_read_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(true)
            .start()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        set_local_timeouts(&mut transaction, context).map_err(PreCommitFailure::into_read_error)?;
        let metadata =
            load_namespace_metadata(&mut transaction, &self.namespace, MetadataLockMode::None)
                .map_err(PreCommitFailure::into_read_error)?;
        validate_operation_authority(metadata, context)
            .map_err(PreCommitFailure::into_read_error)?;
        let value: StructuredOutboxInventory =
            probe(&mut transaction, &self.namespace).map_err(PreCommitFailure::into_read_error)?;
        transaction
            .rollback()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        remaining_deadline(context).map_err(PreCommitFailure::into_read_error)?;
        Ok(value)
    }
}

fn any_pending_delivery(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
) -> Result<bool, PreCommitFailure> {
    let sql: String = format!(
        "SELECT 1 FROM sunrise_edge.outbox_delivery WHERE {NAMESPACE_PREFIX} AND state_id <> $4 LIMIT 1"
    );
    transaction
        .query_opt(
            &sql,
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &OUTBOX_DELIVERY_COMPLETED,
            ],
        )
        .map(|row| row.is_some())
        .map_err(|error| PreCommitFailure::from_database(&error))
}
