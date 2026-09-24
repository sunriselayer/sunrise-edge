//! Read-only, caller-driven inventory of chain-scoped FastVote settlement
//! rows. A page is not a global snapshot: operators must sweep a quiescent
//! store and restart at the prefix after concurrent writes.

use super::*;
use canonical_encoding::encode_chain_id;
use runtime::{DurableStateKeyScanner, StateKeyPage, StateKeyScan};
use std::num::NonZeroUsize;

/// One bounded page of independently verified certified settlement rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeEscrowInventoryPage {
    /// Number of exact settlement keys verified on this page, including
    /// uncharged certificates.
    pub verified_rows: u64,
    /// Number of retained claims proved across those rows.
    pub verified_claims: u64,
    /// Number of signed split payout objects proved across those rows.
    pub verified_payouts: u64,
    /// Pass this exclusive key to the next page, or `None` when this sweep
    /// reached the current end of the prefix.
    pub continuation_cursor: Option<Vec<u8>>,
}

/// Verifies one bounded page of every settlement key in the requested chain.
/// The scanner exposes tombstones, and every exact key is point-read by
/// `verify_fee_claim_history`; a missing/tombstoned or malformed key fails
/// closed. This is a maintenance operation, never a consensus transition.
#[allow(clippy::too_many_arguments)]
pub fn verify_fee_escrow_inventory_page<S: DurableStateKeyScanner>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    chain: &ChainId,
    after: Option<Vec<u8>>,
    limit: NonZeroUsize,
) -> Result<FeeEscrowInventoryPage, FeeClaimError> {
    let mut prefix: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    prefix.extend_from_slice(b"settlement/");
    prefix.extend(encode_chain_id(chain)?);
    let scan: StateKeyScan = StateKeyScan::new(prefix.clone(), after, limit)?;
    let page: StateKeyPage = store.scan_durable_keys(context, domain, &scan)?;
    let mut result: FeeEscrowInventoryPage = FeeEscrowInventoryPage {
        verified_rows: 0,
        verified_claims: 0,
        verified_payouts: 0,
        continuation_cursor: page
            .continuation_cursor()
            .map(|cursor: &[u8]| cursor.to_vec()),
    };
    for key in page.keys() {
        let request_id: [u8; 32] = key
            .strip_prefix(prefix.as_slice())
            .ok_or(FeeClaimError::Invalid("fee escrow inventory key prefix"))?
            .try_into()
            .map_err(|_| FeeClaimError::Invalid("fee escrow inventory key shape"))?;
        let exact_key: Vec<u8> = local_instance_state::fastpath_settlement_key(chain, &request_id)?;
        if key != &exact_key {
            return Err(FeeClaimError::Invalid("fee escrow inventory key mismatch"));
        }
        let verified: FeeClaimVerificationReport = verify_fee_claim_history(
            store,
            blob_store,
            context,
            domain,
            resolver,
            history,
            chain,
            &request_id,
        )?;
        result.verified_rows = result
            .verified_rows
            .checked_add(1)
            .ok_or(FeeClaimError::Invalid("fee escrow inventory row count"))?;
        result.verified_claims = result
            .verified_claims
            .checked_add(verified.verified_claims)
            .ok_or(FeeClaimError::Invalid("fee escrow inventory claim count"))?;
        result.verified_payouts = result
            .verified_payouts
            .checked_add(verified.verified_payouts)
            .ok_or(FeeClaimError::Invalid("fee escrow inventory payout count"))?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::tests::{chain, context, domain, resolver};
    use runtime::{
        AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
        DurableDomainStateStore, MemoryBlobStore, MemoryDurableStateStore, StateMutation,
        StateMutationEntry, StateReadAssertion, WriterFenceGeneration,
    };

    fn store() -> MemoryDurableStateStore {
        MemoryDurableStateStore::new_bound(domain(), WriterFenceGeneration::new(1).unwrap())
    }

    fn write_key(store: &MemoryDurableStateStore, key: Vec<u8>, mutation: StateMutation) {
        let observed = store
            .get_versioned_durable(&context(1), domain(), &key)
            .unwrap();
        let transaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context(1), transaction),
            DurableCommitOutcome::Committed
        );
    }

    fn scan(store: &MemoryDurableStateStore) -> Result<FeeEscrowInventoryPage, FeeClaimError> {
        verify_fee_escrow_inventory_page(
            store,
            &MemoryBlobStore::default(),
            &context(1),
            domain(),
            &resolver(),
            &[],
            &chain(),
            None,
            NonZeroUsize::new(1).unwrap(),
        )
    }

    #[test]
    fn empty_inventory_page_is_not_a_global_history_proof() {
        let result: FeeEscrowInventoryPage = scan(&store()).unwrap();
        assert_eq!(result.verified_rows, 0);
        assert_eq!(result.continuation_cursor, None);
    }

    #[test]
    fn malformed_settlement_key_and_tombstone_fail_closed() {
        let malformed_store: MemoryDurableStateStore = store();
        let exact_key: Vec<u8> =
            local_instance_state::fastpath_settlement_key(&chain(), &[0x71; 32]).unwrap();
        let mut malformed_key: Vec<u8> = exact_key.clone();
        malformed_key.push(0x01);
        write_key(&malformed_store, malformed_key, StateMutation::Put(vec![1]));
        assert!(matches!(
            scan(&malformed_store),
            Err(FeeClaimError::Invalid("fee escrow inventory key shape"))
        ));

        let tombstoned_store: MemoryDurableStateStore = store();
        write_key(
            &tombstoned_store,
            exact_key.clone(),
            StateMutation::Put(vec![1]),
        );
        write_key(&tombstoned_store, exact_key, StateMutation::Delete);
        assert!(matches!(
            scan(&tombstoned_store),
            Err(FeeClaimError::Invalid("fee claim settlement missing"))
        ));
    }
}
