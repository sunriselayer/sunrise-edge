//! Read-only query dispatch, encoded with the existing
//! `node-wire` HTTP query-result types.
//!
//! This module never invents its own query wire bytes: every result is
//! the same typed `node_core::query` value the native HTTP adapter
//! computes, translated through `node-wire`'s existing
//! `HttpObjectQueryResult`/`HttpReceiptQueryResult`/
//! `HttpNextNonceQueryResult` canonical encoders -- the exact same bytes
//! `crates/native-http` returns for the same query. Fast-path prepare/
//! apply/recovery and genesis installation are called directly from
//! `lib.rs` against `node_core::fast_path`/`node_core::genesis`: a
//! re-export here would only rename that surface, not add anything.

use node_core::{
    NodeCoreError, RequestId, query_object, query_request_receipt, query_sender_next_nonce,
};
use node_wire::{
    HttpNextNonceQueryResult, HttpObjectQueryResult, QueryResultError, http_receipt_query_result,
};
use objects::{Address, ObjectId};
use protocol_types::{ChainId, Epoch, ProtocolVersion};
use runtime::{AtomicityDomainId, DurableOperationContext, StructuredDurableDomainStateStore};

/// Unified error for the query-dispatch functions below: either the
/// underlying `node_core` query failed, or the already-verified typed
/// result failed to re-encode through `node-wire` (for example an
/// object/receipt whose fields violate a `node-wire`-side bound node-core
/// itself does not enforce).
#[derive(Debug)]
pub enum QueryDispatchError {
    /// The `node_core` query itself failed.
    Node(NodeCoreError),
    /// The `node-wire` HTTP result type rejected the query's own fields.
    Wire(QueryResultError),
}

impl From<NodeCoreError> for QueryDispatchError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}

impl From<QueryResultError> for QueryDispatchError {
    fn from(error: QueryResultError) -> Self {
        Self::Wire(error)
    }
}

/// Queries one durable object and encodes it as the canonical
/// `HttpObjectQueryResult` node-wire type.
pub fn dispatch_query_object<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    object_id: ObjectId,
) -> Result<Vec<u8>, QueryDispatchError>
where
    S: StructuredDurableDomainStateStore,
{
    let result = query_object(store, context, domain, chain_id, object_id)?;
    Ok(HttpObjectQueryResult::from(result).encode()?)
}

/// Queries one durable receipt and encodes it as the canonical
/// `HttpReceiptQueryResult` node-wire type.
pub fn dispatch_query_request_receipt<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_id: RequestId,
) -> Result<Vec<u8>, QueryDispatchError>
where
    S: StructuredDurableDomainStateStore,
{
    let result = query_request_receipt(store, context, domain, request_id)?;
    Ok(http_receipt_query_result(result)
        .map_err(NodeCoreError::from)?
        .encode()?)
}

/// Queries the persisted next nonce for `sender` and encodes it as the
/// canonical `HttpNextNonceQueryResult` node-wire type.
pub fn dispatch_query_sender_next_nonce<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    sender: [u8; 32],
) -> Result<Vec<u8>, QueryDispatchError>
where
    S: StructuredDurableDomainStateStore,
{
    let next_nonce = query_sender_next_nonce(
        store,
        context,
        domain,
        chain_id,
        protocol_version,
        epoch,
        sender,
    )?;
    Ok(HttpNextNonceQueryResult::new(Address::new(sender), epoch, next_nonce).encode()?)
}
