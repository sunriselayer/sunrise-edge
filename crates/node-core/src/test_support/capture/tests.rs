//! Storage-port negative controls only. These raw records exercise capture;
//! they provide no genesis, business authority or blob-backed execution proof.

use super::*;
use crate::{NodeDedupRecord, RequestId};
use objects::ObjectId;
use protocol_types::{ChainId, HashAlgorithmId, ProtocolVersion};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, BlobStore,
    DurableCommitOutcome, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersion, DurableObjectVersionRecord,
    DurableRequestId, DurableRequestReceipt, MemoryBlobStore, MemoryDurableStateStore,
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId,
    StorageDeadline, StructuredDurableDomainStateStore, WriterFenceGeneration,
};

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([0x81; 32]).unwrap()
}

fn context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(100).unwrap(),
        StorageCorrelationId::new([0x82; 16]).unwrap(),
    )
}

fn store() -> MemoryDurableStateStore {
    MemoryDurableStateStore::new_bound(domain(), WriterFenceGeneration::new(1).unwrap())
}

fn blob_digest() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [0x83; 32])
}

fn install_storage_rows(store: &MemoryDurableStateStore) {
    let request: RequestId = RequestId::new([0x84; 32]).unwrap();
    let event: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x85; 32]);
    let canonical: Vec<u8> = NodeDedupRecord::new(request, event, Vec::new())
        .unwrap()
        .encode()
        .unwrap();
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(*request.as_bytes()).unwrap(),
        event,
        canonical,
    )
    .unwrap();
    let id: ObjectId = ObjectId::new([0x86; 32]);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::FIRST,
        blob_digest(),
        1,
        DurableObjectProvenance::new(
            ChainId::new("capture-storage-port").unwrap(),
            ProtocolVersion::new(1),
        ),
        12,
        blob_digest(),
    );
    let objects: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(id, DurableObjectHead::Absent)],
        vec![DurableObjectMutationEntry::new(
            id,
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::default(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let transaction: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain(), None, objects, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

fn comparison_rejects(actual: &SourceBusinessSnapshot, expected: &SourceBusinessSnapshot) {
    assert!(
        std::panic::catch_unwind(|| assert_same_records_and_blobs(actual, expected)).is_err(),
        "the exact comparison must reject this storage difference"
    );
}

#[test]
fn exact_capture_rejects_missing_receipt_head_and_extra_state_rows() {
    let source: MemoryDurableStateStore = store();
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    blobs.put_blob(blob_digest(), vec![0x87; 2053]).unwrap();
    install_storage_rows(&source);
    let complete: SourceBusinessSnapshot = captured_source(&source, &blobs, &context(), domain());
    // Deliberately omit one captured row at a time. Keep every other record,
    // body and the local token exact so no unrelated difference masks it.
    // Shape validation cannot itself prove collection enumeration complete.
    let mut without_receipt: SourceBusinessSnapshot = complete.clone();
    without_receipt
        .records
        .retain(|record| !matches!(record.descriptor.key(), DurableRecordKey::Receipt(_)));
    let mut without_head: SourceBusinessSnapshot = complete.clone();
    without_head
        .records
        .retain(|record| !matches!(record.descriptor.key(), DurableRecordKey::ObjectHead(_)));
    assert_eq!(without_receipt.records.len() + 1, complete.records.len());
    assert_eq!(without_head.records.len() + 1, complete.records.len());
    without_receipt.validate().unwrap();
    without_head.validate().unwrap();
    comparison_rejects(&without_receipt, &complete);
    comparison_rejects(&without_head, &complete);

    let extra_key: Vec<u8> = b"capture-extra-state".to_vec();
    let extra_bytes: Vec<u8> = vec![0x88; 2053];
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(extra_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(extra_key.clone(), StateMutation::Put(extra_bytes.clone()))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        source.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
    let with_extra: SourceBusinessSnapshot = captured_source(&source, &blobs, &context(), domain());
    assert_eq!(with_extra.records.len(), complete.records.len() + 1);
    assert!(with_extra.records.iter().any(|record| {
        record.descriptor.key() == &DurableRecordKey::State(extra_key.clone())
            && record.value.as_deref() == Some(extra_bytes.as_slice())
    }));
    comparison_rejects(&with_extra, &complete);
}

#[test]
fn exact_capture_reads_referenced_blob_bytes_and_rejects_a_changed_body() {
    let source: MemoryDurableStateStore = store();
    install_storage_rows(&source);
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let changed_blobs: MemoryBlobStore = MemoryBlobStore::default();
    let bytes: Vec<u8> = vec![0x89; 2053];
    let changed_bytes: Vec<u8> = vec![0x8a; 2053];
    blobs.put_blob(blob_digest(), bytes.clone()).unwrap();
    // A separate real blob port models corrupted referenced content. The
    // immutable primary correctly refuses a same-digest overwrite attempt.
    assert!(
        blobs
            .put_blob(blob_digest(), changed_bytes.clone())
            .is_err()
    );
    changed_blobs
        .put_blob(blob_digest(), changed_bytes.clone())
        .unwrap();
    let complete: SourceBusinessSnapshot = captured_source(&source, &blobs, &context(), domain());
    let changed: SourceBusinessSnapshot =
        captured_source(&source, &changed_blobs, &context(), domain());
    assert_eq!(complete.records, changed.records);
    assert_eq!(complete.referenced_blobs.len(), 1);
    assert_eq!(complete.referenced_blobs.get(&blob_digest()), Some(&bytes));
    assert_eq!(
        changed.referenced_blobs.get(&blob_digest()),
        Some(&changed_bytes)
    );
    comparison_rejects(&changed, &complete);
    assert_eq!(
        captured_source(&source, &blobs, &context(), domain()),
        complete
    );
}
