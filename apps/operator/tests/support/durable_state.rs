//! Direct test-only fixture writes and independent snapshots, never HTTP routes.
#![allow(dead_code)]
use protocol_types::{AtomicityDomainId, ChainId};
use runtime::*;
use runtime_sqlite::SqliteDurableStore;
use std::num::NonZeroUsize;

pub fn replace<S: DurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: Vec<u8>,
    bytes: Vec<u8>,
) {
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key).unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(context, transaction),
        DurableCommitOutcome::Committed
    );
}

pub fn set_epoch(
    store: &SqliteDurableStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    record: &node_core::local_instance_state::FastPathEpochRecord,
) {
    replace(
        store,
        context,
        domain,
        node_core::local_instance_state::fastpath_epoch_record_key(chain).unwrap(),
        node_core::local_instance_state::encode_fastpath_epoch_record(record).unwrap(),
    );
}

pub fn snapshot(
    store: &SqliteDurableStore,
    context: &DurableOperationContext,
    fixture: &super::genesis_fixture::FastVoteGenesisFixture,
) -> String {
    // Include every generic state row (including locks, prepared, certificate,
    // sender nonce and tombstones), plus every genesis business object's actual
    // typed head/version and the final receipt through production query APIs.
    let mut values: Vec<(Vec<u8>, VersionedStateValue)> = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let scan: StateKeyScan =
            StateKeyScan::new(b"se/".to_vec(), after, NonZeroUsize::new(128).unwrap()).unwrap();
        let page: StateKeyPage = store
            .scan_durable_keys(context, fixture.domain, &scan)
            .unwrap();
        for key in page.keys() {
            values.push((
                key.clone(),
                store
                    .get_versioned_durable(context, fixture.domain, key)
                    .unwrap(),
            ));
        }
        after = page.continuation_cursor().map(<[u8]>::to_vec);
        if after.is_none() {
            break;
        }
    }
    let manifest: node_core::GenesisManifest =
        node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let objects: Vec<node_core::ObjectQueryResult> = manifest
        .objects
        .iter()
        .map(|entry| {
            node_core::query_object(
                store,
                context,
                fixture.domain,
                &fixture.chain_id,
                entry.object.id,
            )
            .unwrap()
        })
        .collect();
    let receipt: node_core::ReceiptQueryResult = node_core::query_request_receipt(
        store,
        context,
        fixture.domain,
        node_core::RequestId::new(fixture.request_id).unwrap(),
    )
    .unwrap();
    format!("{values:?}\n{objects:?}\n{receipt:?}")
}
