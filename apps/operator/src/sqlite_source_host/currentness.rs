//! Read-only original-bond source observation against the live host store.
//! There is deliberately no transport or approval/signing route in this slice.

use crate::sqlite_genesis_checks::{
    OriginalHostPins, read_original_host_state, read_stable_advisory_with_token,
    verify_original_signer,
};
use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use node_core::genesis::VerifiedGenesisRoot;
use node_core::{
    ObjectQueryResult,
    ordered_economics::{
        OrderedEconomicsEnvironment, OrderedEconomicsPolicy, OrderedHistoryIdentity,
        query_ordered_history_summary,
    },
    query_committed_epoch_state, query_object,
};
use objects::{Object, ObjectRef, decode_object, encode_object};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, ValidatorId};
use runtime::portable::PortableSnapshotToken;
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore};
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// A local observation at one stable SQLite token. It is neither a chain
/// proof nor a mutation fence, and can become stale immediately after return.
pub struct OriginalBondCurrentnessObservation {
    pub token: PortableSnapshotToken,
    pub epoch: Epoch,
    pub validator_set_digest: Digest32,
    pub ordered_tip: OrderedHistoryIdentity,
    pub coin: ObjectRef,
}

/// Pinned, read-only reader for one original host's already-claimed writer
/// fence and *same* store Arc. Construction neither opens nor advances state.
/// A future authenticated local listener may invoke `observe`; currently no
/// request path does, so this type grants no live signing authority.
pub struct OriginalBondCurrentnessReader {
    store: Arc<SqliteDurableStore>,
    blobs: Arc<SqliteBlobStore>,
    root: VerifiedGenesisRoot,
    policy: OrderedEconomicsPolicy,
    leg_policy: LocalExecutionPolicy,
    engine: LocalWasmExecutionEngine,
    domain: AtomicityDomainId,
    validator: ValidatorId,
    validator_public_key: [u8; 32],
    fence: WriterFenceGeneration,
    timeout_millis: u64,
    next_correlation: AtomicU64,
}

impl OriginalBondCurrentnessReader {
    /// Binds the reader to an original host's preexisting, claimed store.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<SqliteDurableStore>,
        blobs: Arc<SqliteBlobStore>,
        root: VerifiedGenesisRoot,
        domain: AtomicityDomainId,
        validator: ValidatorId,
        validator_public_key: [u8; 32],
        fence: WriterFenceGeneration,
        timeout: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        let timeout_millis: u64 = u64::try_from(timeout.as_millis())?;
        if timeout_millis == 0
            || timeout_millis > super::MAX_HOST_TIMEOUT_SECONDS * 1000
            || root.genesis_context().epoch() != Epoch::new(0)
            || store.writer_fence()? != fence
        {
            return Err("original bond currentness reader pins are invalid".into());
        }
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, domain)?;
        let leg_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(root.genesis_context().clone());
        Ok(Self {
            store,
            blobs,
            root,
            policy,
            leg_policy,
            engine: LocalWasmExecutionEngine::new(),
            domain,
            validator,
            validator_public_key,
            fence,
            timeout_millis,
            next_correlation: AtomicU64::new(1),
        })
    }

    /// Rechecks one independently prepared original-bond Coin preimage. The
    /// caller must already have validated its operation-specific Coin meaning;
    /// this method requires the exact canonical body and reference to be the
    /// current inline object under a stable local token.
    pub fn observe(
        &self,
        reviewed: &ObjectRef,
        reviewed_bytes: &[u8],
    ) -> Result<OriginalBondCurrentnessObservation, Box<dyn Error>> {
        if reviewed_bytes.is_empty()
            || reviewed_bytes.len() > node_core::MAX_AUTHENTICATED_OBJECT_BODY_BYTES
        {
            return Err("original bond reviewed Coin size refused".into());
        }
        let decoded: Object = decode_object(reviewed_bytes)?;
        if encode_object(&decoded)? != reviewed_bytes
            || decoded.id != reviewed.id
            || decoded.version != reviewed.version
        {
            return Err("original bond reviewed Coin preimage mismatch".into());
        }
        let sequence: u64 = self
            .next_correlation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "original bond observation identity exhausted")?;
        let now: u64 = SystemClock.now_unix_millis()?;
        let deadline: u64 = now
            .checked_add(self.timeout_millis)
            .ok_or("original bond observation deadline overflow")?;
        let mut correlation: [u8; 16] = [0; 16];
        correlation[..8].copy_from_slice(&self.fence.get().to_be_bytes());
        correlation[8..].copy_from_slice(&sequence.to_be_bytes());
        let context: DurableOperationContext = DurableOperationContext::new(
            self.fence,
            StorageDeadline::new(deadline).ok_or("invalid observation deadline")?,
            StorageCorrelationId::new(correlation).ok_or("invalid observation identity")?,
        );
        let pins: OriginalHostPins<'_> = OriginalHostPins {
            domain: self.domain,
            expected_context: self.root.genesis_context(),
            root: &self.root,
            resolver: self.root.genesis_resolver(),
        };
        let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: &self.policy,
            history: &[],
            leg_policy: &self.leg_policy,
            engine: &self.engine,
            blobs: self.blobs.as_ref(),
            seal: None,
        };
        let ((epoch, validator_set_digest, ordered_tip), token) =
            read_stable_advisory_with_token(self.store.as_ref(), &context, self.domain, || {
                let (_fee, record) =
                    read_original_host_state(self.store.as_ref(), &context, &pins)?;
                verify_original_signer(
                    &record,
                    &self.root,
                    self.validator,
                    &self.validator_public_key,
                )?;
                let live = query_committed_epoch_state(
                    self.store.as_ref(),
                    &context,
                    self.domain,
                    self.root.genesis_context().chain_id(),
                )?;
                let trusted_digest: Digest32 = self
                    .root
                    .genesis_committee()
                    .digest(self.root.genesis_resolver())?;
                if live.current_epoch != Epoch::new(0)
                    || live.current_validator_set_digest != trusted_digest
                {
                    return Err("original bond committed epoch/set changed".into());
                }
                let summary =
                    query_ordered_history_summary(self.store.as_ref(), &context, &environment)?;
                let query = query_object(
                    self.store.as_ref(),
                    &context,
                    self.domain,
                    self.root.genesis_context().chain_id(),
                    reviewed.id,
                )?;
                require_exact_inline(
                    query,
                    reviewed,
                    reviewed_bytes,
                    self.root.genesis_context().chain_id(),
                    self.root.genesis_context().protocol_version(),
                )?;
                Ok((
                    live.current_epoch,
                    live.current_validator_set_digest,
                    summary.identity,
                ))
            })?;
        if token.writer_fence() != self.fence {
            return Err("original bond observed writer fence changed".into());
        }
        Ok(OriginalBondCurrentnessObservation {
            token,
            epoch,
            validator_set_digest,
            ordered_tip,
            coin: reviewed.clone(),
        })
    }
}

fn require_exact_inline(
    query: ObjectQueryResult,
    reviewed: &ObjectRef,
    reviewed_bytes: &[u8],
    chain: &protocol_types::ChainId,
    protocol_version: protocol_types::ProtocolVersion,
) -> Result<(), Box<dyn Error>> {
    match query {
        ObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            creating_chain_id,
            protocol_version: created_version,
            canonical_object_bytes,
            ..
        } if object_id == reviewed.id
            && object_version.get() == reviewed.version
            && digest == reviewed.digest
            && &creating_chain_id == chain
            && created_version == protocol_version
            && canonical_object_bytes == reviewed_bytes =>
        {
            Ok(())
        }
        _ => Err("original bond Coin is absent, not inline, or differs from review".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashAlgorithmId, ProtocolVersion};
    use runtime::{DurableObjectVersion, ObjectHeadRevision};

    #[test]
    fn local_coin_result_refuses_noncurrent_and_changed_preimages() {
        let chain = ChainId::new("bond-observation").unwrap();
        let version = ProtocolVersion::new(1);
        let id = objects::ObjectId::new([7; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [8; 32]);
        let reviewed = ObjectRef {
            id,
            version: 1,
            digest,
        };
        let body = b"reviewed-coin";
        let current = || ObjectQueryResult::CurrentInline {
            object_id: id,
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            creating_chain_id: chain.clone(),
            protocol_version: version,
            canonical_object_bytes: body.to_vec(),
        };
        assert!(require_exact_inline(current(), &reviewed, body, &chain, version).is_ok());
        for result in [
            ObjectQueryResult::Absent { object_id: id },
            ObjectQueryResult::Tombstoned {
                object_id: id,
                head_revision: ObjectHeadRevision::FIRST,
                last_object_version: DurableObjectVersion::FIRST,
            },
            ObjectQueryResult::CurrentBlobReference {
                object_id: id,
                head_revision: ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                blob_digest: digest,
            },
        ] {
            assert!(require_exact_inline(result, &reviewed, body, &chain, version).is_err());
        }
        assert!(require_exact_inline(current(), &reviewed, b"changed", &chain, version).is_err());
        let wrong_version = ObjectRef {
            version: 2,
            ..reviewed.clone()
        };
        assert!(require_exact_inline(current(), &wrong_version, body, &chain, version).is_err());
        let wrong_digest = ObjectRef {
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]),
            ..reviewed.clone()
        };
        assert!(require_exact_inline(current(), &wrong_digest, body, &chain, version).is_err());
        let foreign = ChainId::new("foreign").unwrap();
        assert!(require_exact_inline(current(), &reviewed, body, &foreign, version).is_err());
        assert!(
            require_exact_inline(current(), &reviewed, body, &chain, ProtocolVersion::new(2))
                .is_err()
        );
    }
}
