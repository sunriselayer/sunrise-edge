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

const REPLICA_LOCAL_PREFIXES: [&[u8]; 3] = [
    b"se/instances/v1/fastpath/prepared/",
    b"se/instances/v1/fastpath/lock/",
    b"se/instances/v1/fastpath/nonce-lock/",
];

fn scan_se_entries<S: StructuredDurableDomainStateStore + DurableStateKeyScanner>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    exclude: impl Fn(&[u8]) -> bool,
) -> Vec<(Vec<u8>, VersionedStateValue)> {
    let mut values: Vec<(Vec<u8>, VersionedStateValue)> = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let scan: StateKeyScan =
            StateKeyScan::new(b"se/".to_vec(), after, NonZeroUsize::new(256).unwrap()).unwrap();
        let page: StateKeyPage = store.scan_durable_keys(context, domain, &scan).unwrap();
        for key in page.keys() {
            if exclude(key) {
                continue;
            }
            values.push((
                key.clone(),
                store.get_versioned_durable(context, domain, key).unwrap(),
            ));
        }
        after = page.continuation_cursor().map(<[u8]>::to_vec);
        if after.is_none() {
            break;
        }
    }
    values
}

fn object_head_version_evidence<S: StructuredDurableDomainStateStore + DurableStateKeyScanner>(
    store: &S,
    context: &DurableOperationContext,
    fixture: &super::genesis_fixture::FastVoteGenesisFixture,
    ids: &std::collections::BTreeSet<objects::ObjectId>,
) -> String {
    let mut snapshot = String::new();
    for id in ids {
        let head: DurableObjectHead = store.get_object_head(context, fixture.domain, *id).unwrap();
        let verified: node_core::ObjectQueryResult =
            node_core::query_object(store, context, fixture.domain, &fixture.chain_id, *id)
                .unwrap();
        snapshot.push_str(&format!(
            "object={id:?} head={head:?} verified={verified:?}\n"
        ));
        if let Some(last) = head.object_version() {
            for version in 1..=last.get() {
                let value: Option<DurableObjectVersionRecord> = store
                    .get_object_version(
                        context,
                        fixture.domain,
                        *id,
                        DurableObjectVersion::new(version).unwrap(),
                    )
                    .unwrap();
                snapshot.push_str(&format!("version={version} value={value:?}\n"));
            }
        }
    }
    snapshot
}

fn request_publication_nonce_evidence<
    S: StructuredDurableDomainStateStore + DurableStateKeyScanner,
>(
    store: &S,
    context: &DurableOperationContext,
    fixture: &super::genesis_fixture::FastVoteGenesisFixture,
    requests: &[[u8; 32]],
    publications: &[abi::package_types::PackageOrigin],
) -> String {
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
    format!("{receipts:?}\n{published:?}\nsender_nonce={nonce}\n")
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
///
/// This reads back the FULL key set from the SAME store the caller already
/// has open, so it is only meaningful for same-store no-reapplication
/// snapshots (e.g. before/after a no-op retry). For CROSS-REPLICA
/// comparison use [`protocol_convergence_snapshot`] instead.
#[allow(clippy::too_many_arguments)]
pub fn convergence_snapshot<S: StructuredDurableDomainStateStore + DurableStateKeyScanner>(
    store: &S,
    context: &DurableOperationContext,
    fixture: &super::genesis_fixture::FastVoteGenesisFixture,
    ids: &std::collections::BTreeSet<objects::ObjectId>,
    requests: &[[u8; 32]],
    publications: &[abi::package_types::PackageOrigin],
) -> String {
    let values = scan_se_entries(store, context, fixture.domain, |_key: &[u8]| false);
    let objects_evidence = object_head_version_evidence(store, context, fixture, ids);
    let shared_evidence =
        request_publication_nonce_evidence(store, context, fixture, requests, publications);
    format!("{values:?}\n{objects_evidence}{shared_evidence}")
}

/// Same inputs as [`convergence_snapshot`], but built for comparing across
/// *different* replicas rather than the same store before/after a no-op
/// replay. It deliberately excludes three key prefixes that are legitimately
/// replica-local and are never expected to converge:
///
/// - `se/instances/v1/fastpath/prepared/...` -- the in-flight two-phase
///   prepare marker only the replica that is actively driving a request
///   holds. An online validator that never raced the prepare, or a replica
///   that only observes the request via missed-prepare catch-up, legitimately
///   never writes (or already pruned) this record even though it converges
///   on the same final receipt.
/// - `se/instances/v1/fastpath/lock/...` and `.../nonce-lock/...` -- purely
///   local mutual-exclusion locks a process takes out on its own connection
///   while it prepares/commits; they serialize local writers only and carry
///   no cross-replica protocol meaning.
///
/// Every other key -- publication, instance, authority, nonce, certificate,
/// commitment-witness, settlement records, and any unexpected new key -- is
/// still compared by exact value and revision, exactly like
/// `convergence_snapshot`.
#[allow(clippy::too_many_arguments)]
pub fn protocol_convergence_snapshot<
    S: StructuredDurableDomainStateStore + DurableStateKeyScanner,
>(
    store: &S,
    context: &DurableOperationContext,
    fixture: &super::genesis_fixture::FastVoteGenesisFixture,
    ids: &std::collections::BTreeSet<objects::ObjectId>,
    requests: &[[u8; 32]],
    publications: &[abi::package_types::PackageOrigin],
) -> String {
    let values = scan_se_entries(store, context, fixture.domain, |key: &[u8]| {
        REPLICA_LOCAL_PREFIXES
            .iter()
            .any(|prefix: &&[u8]| key.starts_with(prefix))
    });
    let objects_evidence = object_head_version_evidence(store, context, fixture, ids);
    let shared_evidence =
        request_publication_nonce_evidence(store, context, fixture, requests, publications);
    format!("{values:?}\n{objects_evidence}{shared_evidence}")
}
