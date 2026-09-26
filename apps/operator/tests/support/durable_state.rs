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

/// Every durable key this domain has ever written under the shared `se/`
/// key space (nonce locks, prepared/certificate/witness/settlement records,
/// sender nonces, publication and object-authority records, instance
/// records, tombstones -- anything `local_instance_state`/`publication`
/// derive a key for), plus every caller-selected object's independently
/// re-verified head/version and canonical query bytes, every caller-selected
/// request's canonical receipt, and every caller-selected package origin's
/// independently re-verified canonical publication record. Used to prove
/// exact convergence across replicas and exact no-op idempotent replay
/// without hand-deriving each individual key -- a change here is caught the
/// same way an unexpected new key or a bit flip in an existing one would be.
#[allow(clippy::too_many_arguments)]
pub fn convergence_snapshot<S: StructuredDurableDomainStateStore + DurableStateKeyScanner>(
    store: &S,
    context: &DurableOperationContext,
    fixture: &super::genesis_fixture::FastVoteGenesisFixture,
    ids: &std::collections::BTreeSet<objects::ObjectId>,
    requests: &[[u8; 32]],
    publications: &[abi::package_types::PackageOrigin],
) -> String {
    let mut values: Vec<(Vec<u8>, VersionedStateValue)> = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let scan: StateKeyScan =
            StateKeyScan::new(b"se/".to_vec(), after, NonZeroUsize::new(256).unwrap()).unwrap();
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
    let objects: Vec<node_core::ObjectQueryResult> = ids
        .iter()
        .map(|id: &objects::ObjectId| {
            node_core::query_object(store, context, fixture.domain, &fixture.chain_id, *id).unwrap()
        })
        .collect();
    let receipts: Vec<node_core::ReceiptQueryResult> = requests
        .iter()
        .map(|request: &[u8; 32]| {
            node_core::query_request_receipt(
                store,
                context,
                fixture.domain,
                node_core::RequestId::new(*request).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let published: Vec<Option<node_core::publication::PublicationQueryResult>> = publications
        .iter()
        .map(|origin: &abi::package_types::PackageOrigin| {
            node_core::publication::query_publication(
                store,
                context,
                fixture.domain,
                &fixture.resolver,
                origin,
            )
            .unwrap()
        })
        .collect();
    let nonce: u64 = node_core::query_sender_next_nonce(
        store,
        context,
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        fixture.sender,
    )
    .unwrap();
    format!("{values:?}\n{objects:?}\n{receipts:?}\n{published:?}\nsender_nonce={nonce}\n")
}
