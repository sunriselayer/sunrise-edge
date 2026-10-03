//! DR-0189 compact public successor entry points for FastVote, availability
//! publication and authenticated receipts. Each takes a freshly resolved
//! [`LiveWarrant`] and the exact store that issued it, and delegates to the
//! one existing owning handler under the private successor gate: issuer and
//! member binding, cut-floor generation, deciding CAS folding and the
//! protected successor commit port. The ordered successor entries live
//! beside their engine in [`crate::ordered_economics`].

use super::*;
use crate::fast_path::FastPathError;
use crate::fast_path::publication::PublicationRetentionError;
use crate::{NodeOutput, ReceiptQueryResult, RequestId};
use consensus::{AvailabilityVote, ConsensusSigner, FastVote};
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{PaidContractEngine, PaidFeePolicy};
use hashing::HashSuiteResolver;
use runtime::{BlobStore, StructuredDurableDomainStateStore};

/// Trusted local execution composition of one successor FastVote request.
/// Every value is a claim the owning admission checks against the installed
/// verified e+1 rows; none of it grants authority.
pub struct SuccessorFastVoteComposition<'a, E: PaidContractEngine + ?Sized> {
    /// Blob store backing large object bodies.
    pub blob_store: &'a dyn BlobStore,
    /// Locally pinned active resolver.
    pub resolver: &'a HashSuiteResolver,
    /// Locally pinned historical resolvers.
    pub history: &'a [HashSuiteResolver],
    /// Expected e+1 execution policy (must equal the installed row).
    pub base_policy: &'a LocalExecutionPolicy,
    /// Expected e+1 paid fee policy (must equal the installed row).
    pub fee_policy: &'a PaidFeePolicy,
    /// Existing deterministic paid contract engine.
    pub engine: &'a E,
}

fn require_successor_scope(
    warrant: &LiveWarrant<'_>,
    resolver: &HashSuiteResolver,
) -> Result<(), NodeCoreError> {
    let context: &PublicationContext = warrant.policy_inputs().context();
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(NodeCoreError::PersistenceInvariant(
            "successor resolver is not the verified successor scope",
        ));
    }
    Ok(())
}

fn require_fastvote_scope<E: PaidContractEngine + ?Sized>(
    warrant: &LiveWarrant<'_>,
    composition: &SuccessorFastVoteComposition<'_, E>,
) -> Result<(), NodeCoreError> {
    require_successor_scope(warrant, composition.resolver)?;
    let context: &PublicationContext = warrant.policy_inputs().context();
    if composition.base_policy.context() != context || composition.fee_policy.context != *context {
        return Err(NodeCoreError::PersistenceInvariant(
            "successor FastVote policy is not the verified e+1 scope",
        ));
    }
    Ok(())
}

/// Successor FastVote preparation: the existing prepare handler at the
/// verified e+1 scope. A retained vote is re-exposed only under this fresh
/// warrant; a fresh vote is signed only by the fresh namespace member.
pub fn prepare_successor<S, E, C>(
    warrant: &LiveWarrant<'_>,
    store: &S,
    composition: &SuccessorFastVoteComposition<'_, E>,
    signer: &C,
    signed_bytes: &[u8],
    created_checkpoint: u64,
) -> Result<FastVote, FastPathError>
where
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
    C: ConsensusSigner,
{
    require_fastvote_scope(warrant, composition)?;
    crate::fast_path::prepare_gated(
        ServingGate::Successor(warrant),
        store,
        composition.blob_store,
        warrant.context(),
        warrant.policy_inputs().domain(),
        composition.resolver,
        composition.history,
        warrant.policy_inputs().context(),
        composition.base_policy,
        composition.fee_policy,
        composition.engine,
        signer,
        signed_bytes,
        created_checkpoint,
    )
}

/// Successor FastVote certificate apply: the existing apply handler at the
/// verified e+1 scope, including availability publication before apply and
/// signerless recovery when a recovery checkpoint is supplied.
pub fn apply_successor<S, E>(
    warrant: &LiveWarrant<'_>,
    store: &S,
    composition: &SuccessorFastVoteComposition<'_, E>,
    signed_bytes: &[u8],
    certificate_bytes: &[u8],
    availability_certificate_bytes: Option<&[u8]>,
    recovery_created_checkpoint: Option<u64>,
) -> Result<NodeOutput, FastPathError>
where
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
{
    require_fastvote_scope(warrant, composition)?;
    crate::fast_path::apply_internal(
        ServingGate::Successor(warrant),
        store,
        composition.blob_store,
        warrant.context(),
        warrant.policy_inputs().domain(),
        composition.resolver,
        composition.history,
        warrant.policy_inputs().context(),
        composition.base_policy,
        composition.fee_policy,
        composition.engine,
        signed_bytes,
        certificate_bytes,
        recovery_created_checkpoint,
        availability_certificate_bytes,
    )
}

/// Successor availability ACK retention for one certified publication.
pub fn retain_publication_successor<S, C>(
    warrant: &LiveWarrant<'_>,
    store: &S,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    bundle_bytes: &[u8],
    signer: &C,
) -> Result<AvailabilityVote, PublicationRetentionError>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    require_successor_scope(warrant, resolver)?;
    crate::fast_path::publication::retain_publication_gated(
        ServingGate::Successor(warrant),
        store,
        warrant.context(),
        warrant.policy_inputs().domain(),
        resolver,
        history,
        warrant.policy_inputs().context(),
        bundle_bytes,
        signer,
    )
}

/// Authenticated exposure of one exact original receipt, including the
/// original Seal receipt and every imported or successor business receipt,
/// under the fresh warrant issuer.
pub fn query_request_receipt_successor<S: StructuredDurableDomainStateStore>(
    warrant: &LiveWarrant<'_>,
    store: &S,
    request_id: RequestId,
) -> Result<ReceiptQueryResult, NodeCoreError> {
    let domain: AtomicityDomainId = warrant.policy_inputs().domain();
    ServingGate::Successor(warrant).require_live(store, warrant.context(), domain)?;
    crate::query_request_receipt(store, warrant.context(), domain, request_id)
}
