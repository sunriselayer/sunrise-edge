//! Successful blob + structured COMMIT, unconfirmed return, then total owner death.
//! Not interrupted COMMIT, power loss, cross-file atomicity or custody evidence.

mod guest_fault;

use super::*;
use crate::native_connection::{NativeConnection, NativeError};
use crate::{SQLITE_BLOB_SCHEMA_IDENTITY, SqliteBlobStore};
use runtime::portable::{
    DurableCollection, DurablePayloadDescriptor, DurableRecordChunk, DurableRecordMetadata,
    PortableBlobChunkOutcome, PortableBlobChunkRequest, PortableBlobDescriptor,
    PortableBlobRepository,
};
use runtime::{
    BlobStore, DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID, ObjectHeadRevision, OutgoingBarrier,
};
use runtime_sql_durable::SqlValue;
use rusqlite::{Transaction, types::ValueRef};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    num::NonZeroUsize,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
};

const CHILD_SELECTOR: &str = "structured::ownership_tests::blob_crash::after_commit_owner_child";
const ROOT_ENV: &str = "SUNRISE_SQLITE_BLOB_CRASH_ROOT";
const PHASE_ENV: &str = "SUNRISE_SQLITE_BLOB_CRASH_PHASE";
const PHASE: &str = "after-positive-blob-commit";
const MAX_BODY: usize = 96 * 1024;
const MAX_IMAGE_BYTES: usize = 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const STATE_ROWS: usize = 16;
const BLOB_ROWS: usize = 3;
const MAX_KEYS: usize = 9;
const MAX_PAGES: usize = 16;

const TABLES: [(&str, &str, usize); 12] = [
    (
        "durable_metadata",
        "SELECT id, schema_identity, chain_id, validator_id, domain, writer_fence, mutation_sequence, source_instance_id, namespace_origin, import_binding FROM durable_metadata ORDER BY id",
        10,
    ),
    (
        "durable_import_progress",
        "SELECT id, phase, progress FROM durable_import_progress ORDER BY id",
        3,
    ),
    (
        "durable_outgoing_barrier",
        "SELECT id, barrier FROM durable_outgoing_barrier ORDER BY id",
        2,
    ),
    (
        "durable_successor_serving",
        "SELECT id, serving FROM durable_successor_serving ORDER BY id",
        2,
    ),
    (
        "durable_state",
        "SELECT key, revision, value FROM durable_state ORDER BY key",
        3,
    ),
    (
        "durable_conditional_readiness",
        "SELECT slot, status, record FROM durable_conditional_readiness ORDER BY slot",
        3,
    ),
    (
        "durable_object_heads",
        "SELECT object_id, status, head_revision, object_version, digest_algorithm, digest_bytes, owner_projection, routing_projection FROM durable_object_heads ORDER BY object_id",
        8,
    ),
    (
        "durable_object_versions",
        "SELECT object_id, object_version, digest_algorithm, digest_bytes, schema_version, type_id, created_chain_id, created_protocol_version, created_checkpoint, inline_canonical_bytes, blob_digest_algorithm, blob_digest_bytes FROM durable_object_versions ORDER BY object_id, object_version",
        12,
    ),
    (
        "durable_receipts",
        "SELECT request_id, event_digest_algorithm, event_digest_bytes, canonical_bytes FROM durable_receipts ORDER BY request_id",
        4,
    ),
    (
        "durable_outbox_messages",
        "SELECT request_id, message_index, payload_digest_algorithm, payload_digest_bytes, canonical_payload FROM durable_outbox_messages ORDER BY request_id, message_index",
        5,
    ),
    (
        "durable_outbox_delivery",
        "SELECT request_id, message_count, next_message_index, completed, available_at_unix_millis, active_lease_id, lease_expires_at_unix_millis, attempt_count FROM durable_outbox_delivery ORDER BY request_id",
        8,
    ),
    (
        "durable_outbox_attempts",
        "SELECT lease_id, request_id, message_index, lease_expires_at_unix_millis, status FROM durable_outbox_attempts ORDER BY lease_id",
        5,
    ),
];
const BLOB_TABLES: [(&str, &str, usize); 2] = [
    (
        "blob_metadata",
        "SELECT id, schema_identity FROM blob_metadata ORDER BY id",
        2,
    ),
    (
        "blobs",
        "SELECT digest_algorithm, digest_bytes, content FROM blobs ORDER BY digest_algorithm, digest_bytes",
        3,
    ),
];
type Row = Vec<SqlValue>;
type Tables = BTreeMap<&'static str, Vec<Row>>;
type PortableRows = BTreeMap<DurableRecordKey, (DurableRecordDescriptor, Option<Vec<u8>>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawImage {
    state: Tables,
    blobs: Tables,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicImage {
    token: PortableSnapshotToken,
    pages: BTreeMap<DurableCollection, Vec<DurableRecordPage>>,
    rows: PortableRows,
    bodies: BTreeMap<Digest32, Vec<u8>>,
}

struct KnownObject {
    object: Object,
    bytes: Vec<u8>,
    digest: Digest32,
    checkpoint: u64,
}
fn known_object(target: bool) -> KnownObject {
    // Independent literals/public codecs, never recovered output or invocation mutations.
    let object: Object = Object {
        id: ObjectId::new([if target { 61 } else { 161 }; 32]),
        version: 1,
        owner: Owner::Address(Address::new([if target { 62 } else { 162 }; 32])),
        type_hash: digest(if target { 63 } else { 163 }),
        schema_version: 1,
        data: vec![if target { 64 } else { 164 }; 70 * 1024],
    };
    let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
    assert!(bytes.len() > CHUNK && bytes.len() <= MAX_BODY);
    assert_eq!(objects::decode_object(&bytes).unwrap(), object);
    let object_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            ProtocolVersion::new(1),
            namespace().chain_id(),
            &bytes,
        )
        .unwrap();
    KnownObject {
        object,
        bytes,
        digest: object_digest,
        checkpoint: if target { 7 } else { 17 },
    }
}
fn version(known: &KnownObject) -> DurableObjectVersionRecord {
    DurableObjectVersionRecord::from_blob_reference(
        known.object.id,
        DurableObjectVersion::new(1).unwrap(),
        known.digest,
        1,
        DurableObjectProvenance::new(namespace().chain_id().clone(), ProtocolVersion::new(1)),
        known.checkpoint,
        known.digest,
    )
}
fn head(known: &KnownObject) -> DurableObjectHead {
    DurableObjectHead::Current {
        head_revision: ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::new(1).unwrap(),
        digest: known.digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(known.object.owner.clone())
            .unwrap(),
        routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
    }
}
fn receipt(target: bool) -> DurableRequestReceipt {
    DurableRequestReceipt::new(
        OutboxRequestId::new([if target { 81 } else { 181 }; 32]).unwrap(),
        digest(if target { 82 } else { 182 }),
        if target { vec![83, 84] } else { vec![183, 184] },
    )
    .unwrap()
}
fn input(target: bool) -> DurableInvocationTransaction {
    let known: KnownObject = known_object(target);
    let mut mutations: Vec<StateMutationEntry> = vec![
        StateMutationEntry::new(
            if target {
                b"state".to_vec()
            } else {
                b"unrelated".to_vec()
            },
            StateMutation::Put(vec![if target { 71 } else { 171 }]),
        )
        .unwrap(),
    ];
    let mut reads: Vec<StateReadAssertion> = vec![
        StateReadAssertion::new(
            if target {
                b"state".to_vec()
            } else {
                b"unrelated".to_vec()
            },
            StateRevision::INITIAL,
        )
        .unwrap(),
    ];
    if target {
        reads.push(StateReadAssertion::new(nonce_key(), StateRevision::INITIAL).unwrap());
        mutations.push(
            StateMutationEntry::new(nonce_key(), StateMutation::Put(nonce_record_bytes())).unwrap(),
        );
    }
    let state: DurableStateTransaction = DurableStateTransaction::new(
        namespace().domain(),
        AtomicStateReadSet::new(reads).unwrap(),
        mutations,
    )
    .unwrap();
    let objects: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            known.object.id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            known.object.id,
            DurableObjectMutation::Create {
                version: version(&known),
                owner_projection: DurableObjectOwnerProjection::from_owner(known.object.owner)
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
            },
        )],
    )
    .unwrap();
    let received: DurableRequestReceipt = receipt(target);
    let outbox: DurableOutboxBatch = DurableOutboxBatch::new(
        received.request_id(),
        received.event_digest(),
        vec![
            DurableOutboxMessage::new(
                digest(if target { 85 } else { 185 }),
                vec![if target { 86 } else { 186 }],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    DurableInvocationTransaction::new(
        namespace().domain(),
        Some(state),
        objects,
        received,
        Some(outbox),
    )
    .unwrap()
}

fn charge(bytes: &mut usize, count: usize) {
    *bytes = bytes.checked_add(count).unwrap();
    assert!(*bytes <= MAX_IMAGE_BYTES, "complete SQL image byte bound");
}
fn bounded_rows(
    transaction: &Transaction<'_>,
    query: &str,
    columns: usize,
    total_rows: &mut usize,
    row_limit: usize,
    total_bytes: &mut usize,
    cell_limit: usize,
) -> Vec<Row> {
    assert!((1..=12).contains(&columns));
    let mut statement: rusqlite::Statement<'_> = transaction.prepare(query).unwrap();
    assert_eq!(statement.column_count(), columns);
    let mut cursor: rusqlite::Rows<'_> = statement.query([]).unwrap();
    let mut rows: Vec<Row> = Vec::new();
    while let Some(row) = cursor.next().unwrap() {
        // Admission precedes row Vec growth and every ValueRef allocation/copy.
        assert!(*total_rows < row_limit, "unexpected populated SQL row");
        *total_rows = total_rows.checked_add(1).unwrap();
        let mut values: Row = Vec::with_capacity(columns);
        for index in 0..columns {
            let value: ValueRef<'_> = row.get_ref(index).unwrap();
            let length: usize = match value {
                ValueRef::Null => 0,
                ValueRef::Integer(_) => 8,
                ValueRef::Blob(bytes) | ValueRef::Text(bytes) => bytes.len(),
                ValueRef::Real(_) => panic!("unexpected SQL REAL"),
            };
            assert!(length <= cell_limit, "oversized SQL value before copy");
            charge(total_bytes, length);
            values.push(match value {
                ValueRef::Null => SqlValue::Null,
                ValueRef::Integer(value) => SqlValue::Integer(value),
                ValueRef::Blob(bytes) => SqlValue::Blob(bytes.to_vec()),
                ValueRef::Text(bytes) => {
                    SqlValue::Text(std::str::from_utf8(bytes).unwrap().to_owned())
                }
                ValueRef::Real(_) => unreachable!(),
            });
        }
        rows.push(values);
    }
    rows
}
fn tables(
    connection: &Connection,
    expected: &[(&'static str, &str, usize)],
    row_limit: usize,
    total_bytes: &mut usize,
) -> Tables {
    let transaction: Transaction<'_> = connection.unchecked_transaction().unwrap();
    let mut name_count: usize = 0;
    let names: Vec<Row> = bounded_rows(
        &transaction,
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        1,
        &mut name_count,
        expected.len(),
        total_bytes,
        64,
    );
    let actual: Vec<&str> = names
        .iter()
        .map(|row: &Row| row[0].as_text().unwrap())
        .collect();
    let mut known: Vec<&str> = expected
        .iter()
        .map(|entry: &(&str, &str, usize)| entry.0)
        .collect();
    known.sort();
    assert_eq!(actual, known, "complete closed table-name inventory");
    let mut result: Tables = BTreeMap::new();
    let mut populated: usize = 0;
    for &(name, query, columns) in expected {
        let rows: Vec<Row> = bounded_rows(
            &transaction,
            query,
            columns,
            &mut populated,
            row_limit,
            total_bytes,
            MAX_BODY,
        );
        assert!(result.len() < expected.len());
        assert!(result.insert(name, rows).is_none());
    }
    // Explicit read rollback, never an unconfirmed/ignored transaction Drop.
    transaction.rollback().unwrap();
    assert!(connection.is_autocommit());
    result
}
fn raw_image(state_path: &Path, blob_path: &Path) -> RawImage {
    let mut bytes: usize = 0;
    let mut state: NativeConnection = NativeConnection::open_existing(state_path, false).unwrap();
    let structured: Tables = state
        .inspect(|connection| {
            Ok::<Tables, NativeError>(tables(connection, &TABLES, STATE_ROWS, &mut bytes))
        })
        .unwrap();
    let mut blobs: NativeConnection = NativeConnection::open_existing(blob_path, false).unwrap();
    let blob_rows: Tables = blobs
        .inspect(|connection| {
            Ok::<Tables, NativeError>(tables(connection, &BLOB_TABLES, BLOB_ROWS, &mut bytes))
        })
        .unwrap();
    // Both extra SQLite-owned connections/attachment holders die here.
    RawImage {
        state: structured,
        blobs: blob_rows,
    }
}

fn expected_portable(target_present: bool) -> PortableRows {
    let mut expected: PortableRows = BTreeMap::new();
    for target in [false, true] {
        if target && !target_present {
            continue;
        }
        let known: KnownObject = known_object(target);
        let received: DurableRequestReceipt = receipt(target);
        let mut entries: Vec<(DurableRecordKey, DurableRecordMetadata, Option<Vec<u8>>)> = vec![
            (
                DurableRecordKey::State(if target {
                    b"state".to_vec()
                } else {
                    b"unrelated".to_vec()
                }),
                DurableRecordMetadata::State {
                    revision: StateRevision::new(1),
                    value_length: Some(1),
                },
                Some(vec![if target { 71 } else { 171 }]),
            ),
            (
                DurableRecordKey::Receipt(received.request_id()),
                DurableRecordMetadata::Receipt {
                    event_digest: received.event_digest(),
                    length: NonZeroUsize::new(2).unwrap(),
                },
                Some(received.canonical_bytes().to_vec()),
            ),
            (
                DurableRecordKey::ObjectHead(known.object.id),
                DurableRecordMetadata::ObjectHead(head(&known)),
                None,
            ),
            (
                DurableRecordKey::ObjectVersion(
                    known.object.id,
                    DurableObjectVersion::new(1).unwrap(),
                ),
                DurableRecordMetadata::ObjectVersion {
                    digest: known.digest,
                    schema_version: 1,
                    provenance: DurableObjectProvenance::new(
                        namespace().chain_id().clone(),
                        ProtocolVersion::new(1),
                    ),
                    created_checkpoint: known.checkpoint,
                    payload: DurablePayloadDescriptor::BlobReference(known.digest),
                },
                None,
            ),
        ];
        if target {
            let nonce: Vec<u8> = nonce_record_bytes();
            entries.push((
                DurableRecordKey::State(nonce_key()),
                DurableRecordMetadata::State {
                    revision: StateRevision::new(1),
                    value_length: Some(nonce.len()),
                },
                Some(nonce),
            ));
        }
        for (key, metadata, payload) in entries {
            assert!(expected.len() < MAX_KEYS);
            let descriptor: DurableRecordDescriptor =
                DurableRecordDescriptor::new(key.clone(), metadata).unwrap();
            assert!(expected.insert(key, (descriptor, payload)).is_none());
        }
    }
    assert_eq!(expected.len(), if target_present { 9 } else { 4 });
    expected
}
fn blob_body(owner: &SqliteBlobStore, known: &KnownObject) -> Vec<u8> {
    let descriptor: PortableBlobDescriptor = owner
        .read_portable_blob_descriptor(&known.digest)
        .unwrap()
        .unwrap();
    assert_eq!(descriptor.digest(), known.digest);
    assert_eq!(descriptor.length(), known.bytes.len());
    assert!(descriptor.length() > CHUNK && descriptor.length() <= MAX_BODY);
    let actual: Vec<u8> = owner.get_blob(&known.digest).unwrap().unwrap();
    assert!(
        actual == known.bytes,
        "complete public body differs from independent literal"
    );
    assert_eq!(objects::decode_object(&actual).unwrap(), known.object);
    assert!(objects::encode_object(&objects::decode_object(&actual).unwrap()).unwrap() == actual);
    let hash: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            ProtocolVersion::new(1),
            namespace().chain_id(),
            &actual,
        )
        .unwrap();
    assert_eq!(hash, known.digest);
    let mut assembled: Vec<u8> = Vec::with_capacity(descriptor.length());
    let mut offset: usize = 0;
    for index in 0..2 {
        let request: PortableBlobChunkRequest =
            PortableBlobChunkRequest::new(descriptor, offset, NonZeroUsize::new(CHUNK).unwrap())
                .unwrap();
        let PortableBlobChunkOutcome::Chunk(chunk) =
            owner.read_portable_blob_chunk(&request).unwrap()
        else {
            panic!("known immutable blob range was corrupt");
        };
        assert_eq!(chunk.request(), &request);
        assert!(!chunk.bytes().is_empty());
        let end: usize = offset.checked_add(chunk.bytes().len()).unwrap();
        assert_eq!(request.range(), offset..end);
        assert!(end <= MAX_BODY && end <= descriptor.length());
        assert_eq!(chunk.is_last(), index == 1);
        assembled.extend_from_slice(chunk.bytes());
        offset = end;
    }
    assert_eq!(offset, descriptor.length());
    assert!(assembled == known.bytes);
    actual
}
fn public_image(
    store: &SqliteDurableStore,
    writer: &SqliteBlobStore,
    reader: Option<&SqliteBlobStore>,
    generation: u64,
    target_present: bool,
) -> PublicImage {
    let ctx: DurableOperationContext = context(generation);
    let domain: AtomicityDomainId = namespace().domain();
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&ctx, domain).unwrap();
    let expected: PortableRows = expected_portable(target_present);
    let mut rows: PortableRows = BTreeMap::new();
    let mut pages: BTreeMap<DurableCollection, Vec<DurableRecordPage>> = BTreeMap::new();
    let mut page_count: usize = 0;
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let keys: Vec<DurableRecordKey> = expected
            .keys()
            .filter(|key: &&DurableRecordKey| key.collection() == collection)
            .cloned()
            .collect();
        let mut after: Option<DurableRecordKey> = None;
        let mut saved: Vec<DurableRecordPage> = Vec::new();
        loop {
            assert!(page_count < MAX_PAGES);
            page_count += 1;
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(1).unwrap())
                    .unwrap();
            let page: DurableRecordPage = store
                .scan_portable_keys_at(&ctx, domain, &token, &scan)
                .unwrap();
            let candidates: Vec<DurableRecordKey> = keys
                .iter()
                .filter(|key: &&DurableRecordKey| {
                    after
                        .as_ref()
                        .is_none_or(|cursor: &DurableRecordKey| *key > cursor)
                })
                .take(2)
                .cloned()
                .collect();
            assert_eq!(
                page,
                DurableRecordPage::from_ordered_candidates(&scan, candidates).unwrap()
            );
            for key in page.keys() {
                assert!(rows.len() < MAX_KEYS);
                let (known, body): &(DurableRecordDescriptor, Option<Vec<u8>>) =
                    expected.get(key).unwrap();
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor_at(&ctx, domain, &token, key)
                    .unwrap()
                    .unwrap();
                assert_eq!(&descriptor, known); // Unknown keys/references and Inline fallback refuse.
                let payload: Option<Vec<u8>> = if let Some(length) = descriptor.payload_length() {
                    assert!(length > 0 && length <= MAX_BODY);
                    assert_eq!(body.as_ref().unwrap().len(), length);
                    let mut bytes: Vec<u8> = Vec::with_capacity(length);
                    let mut offset: usize = 0;
                    for _ in 0..2 {
                        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
                            descriptor.clone(),
                            offset,
                            NonZeroUsize::new(CHUNK).unwrap(),
                        )
                        .unwrap();
                        let DurableRecordChunkOutcome::Chunk(chunk): DurableRecordChunkOutcome =
                            store
                                .read_portable_chunk_at(&ctx, domain, &token, &request)
                                .unwrap()
                        else {
                            panic!("snapshot-bound payload changed");
                        };
                        let chunk: Box<DurableRecordChunk> = chunk;
                        assert_eq!(chunk.request(), &request);
                        assert!(!chunk.bytes().is_empty());
                        let end: usize = offset.checked_add(chunk.bytes().len()).unwrap();
                        assert_eq!(request.range(), offset..end);
                        assert!(end <= length);
                        bytes.extend_from_slice(chunk.bytes());
                        offset = end;
                        if chunk.is_last() {
                            break;
                        }
                    }
                    assert_eq!(offset, length);
                    Some(bytes)
                } else {
                    None
                };
                assert_eq!(&payload, body);
                assert!(rows.insert(key.clone(), (descriptor, payload)).is_none());
            }
            after = page.continuation().cloned();
            saved.push(page);
            if after.is_none() {
                break;
            }
        }
        assert!(pages.len() < 4 && pages.insert(collection, saved).is_none());
    }
    assert_eq!(rows, expected);
    assert_eq!(store.begin_portable_snapshot(&ctx, domain).unwrap(), token);
    let mut bodies: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
    for target in [false, true] {
        let known: KnownObject = known_object(target);
        if target && !target_present {
            assert_eq!(writer.get_blob(&known.digest).unwrap(), None);
            assert_eq!(
                writer.read_portable_blob_descriptor(&known.digest).unwrap(),
                None
            );
            continue;
        }
        let body: Vec<u8> = blob_body(writer, &known);
        if let Some(reader) = reader {
            assert!(blob_body(reader, &known) == body);
        }
        assert!(bodies.len() < 2 && bodies.insert(known.digest, body).is_none());
        assert_eq!(
            store
                .get_object_head(&ctx, domain, known.object.id)
                .unwrap(),
            head(&known)
        );
        assert_eq!(
            store
                .get_object_version(
                    &ctx,
                    domain,
                    known.object.id,
                    DurableObjectVersion::new(1).unwrap()
                )
                .unwrap(),
            Some(version(&known))
        );
        assert_eq!(
            store
                .get_request_receipt(&ctx, domain, receipt(target).request_id())
                .unwrap(),
            Some(receipt(target))
        );
        let state: VersionedStateValue = store
            .get_versioned_durable(&ctx, domain, if target { b"state" } else { b"unrelated" })
            .unwrap();
        assert_eq!(state.revision(), StateRevision::new(1));
        assert_eq!(
            state.value(),
            Some([if target { 71 } else { 171 }].as_slice())
        );
    }
    let nonce: VersionedStateValue = store
        .get_versioned_durable(&ctx, domain, &nonce_key())
        .unwrap();
    let expected_nonce: Vec<u8> = nonce_record_bytes();
    assert_eq!(
        nonce.revision(),
        if target_present {
            StateRevision::new(1)
        } else {
            StateRevision::INITIAL
        }
    );
    assert_eq!(
        nonce.value(),
        if target_present {
            Some(expected_nonce.as_slice())
        } else {
            None
        }
    );
    if !target_present {
        assert_eq!(
            store
                .get_object_head(&ctx, domain, ObjectId::new([61; 32]))
                .unwrap(),
            DurableObjectHead::Absent
        );
        assert_eq!(
            store
                .get_object_version(
                    &ctx,
                    domain,
                    ObjectId::new([61; 32]),
                    DurableObjectVersion::new(1).unwrap()
                )
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .get_request_receipt(&ctx, domain, receipt(true).request_id())
                .unwrap(),
            None
        );
        let absent: VersionedStateValue =
            store.get_versioned_durable(&ctx, domain, b"state").unwrap();
        assert_eq!(absent.revision(), StateRevision::INITIAL);
        assert_eq!(absent.value(), None);
    }
    assert!(
        store
            .get_namespace_lifecycle(&ctx, domain)
            .unwrap()
            .is_ordinary()
    );
    assert_eq!(
        store.get_outgoing_barrier(&ctx, domain).unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store.get_successor_serving(&ctx, domain).unwrap(),
        runtime::successor_serving::SuccessorServingSlot::Inactive
    );
    assert_eq!(store.begin_portable_snapshot(&ctx, domain).unwrap(), token);
    PublicImage {
        token,
        pages,
        rows,
        bodies,
    }
}

fn blob(value: &[u8]) -> SqlValue {
    SqlValue::Blob(value.to_vec())
}
fn number(value: u64) -> SqlValue {
    blob(&value.to_be_bytes())
}
fn expected_material(target: bool) -> Tables {
    let known: KnownObject = known_object(target);
    let received: DurableRequestReceipt = receipt(target);
    let algorithm: SqlValue = SqlValue::Integer(i64::from(HashAlgorithmId::Sha2_256.as_u16()));
    let mut result: Tables = BTreeMap::new();
    let mut state: Vec<Row> = vec![vec![
        blob(if target { b"state" } else { b"unrelated" }),
        number(1),
        blob(&[if target { 71 } else { 171 }]),
    ]];
    if target {
        state.push(vec![
            blob(&nonce_key()),
            number(1),
            blob(&nonce_record_bytes()),
        ]);
    }
    state.sort_by(|left: &Row, right: &Row| {
        left[0].as_blob().unwrap().cmp(right[0].as_blob().unwrap())
    });
    result.insert("durable_state", state);
    result.insert(
        "durable_object_heads",
        vec![vec![
            blob(known.object.id.as_bytes()),
            SqlValue::Integer(1),
            number(1),
            number(1),
            algorithm.clone(),
            blob(&known.digest.bytes()),
            blob(&objects::encode_owner(&known.object.owner).unwrap()),
            SqlValue::Null,
        ]],
    );
    result.insert(
        "durable_object_versions",
        vec![vec![
            blob(known.object.id.as_bytes()),
            number(1),
            algorithm.clone(),
            blob(&known.digest.bytes()),
            SqlValue::Integer(1),
            SqlValue::Integer(i64::from(DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID)),
            SqlValue::Text("native-ownership".into()),
            SqlValue::Integer(1),
            number(known.checkpoint),
            SqlValue::Null,
            algorithm.clone(),
            blob(&known.digest.bytes()),
        ]],
    );
    result.insert(
        "durable_receipts",
        vec![vec![
            blob(received.request_id().as_bytes()),
            algorithm.clone(),
            blob(&received.event_digest().bytes()),
            blob(received.canonical_bytes()),
        ]],
    );
    result.insert(
        "durable_outbox_messages",
        vec![vec![
            blob(received.request_id().as_bytes()),
            SqlValue::Integer(0),
            algorithm,
            blob(&[if target { 85 } else { 185 }; 32]),
            blob(&[if target { 86 } else { 186 }]),
        ]],
    );
    result.insert(
        "durable_outbox_delivery",
        vec![vec![
            blob(received.request_id().as_bytes()),
            SqlValue::Integer(1),
            SqlValue::Integer(0),
            SqlValue::Integer(0),
            number(0),
            SqlValue::Null,
            SqlValue::Null,
            number(0),
        ]],
    );
    result
}
fn assert_initial_raw(image: &RawImage) {
    assert_eq!(image.state.len(), 12);
    let material: Tables = expected_material(false);
    for (table, expected) in material {
        assert!(
            image.state[table] == expected,
            "independent initial material: {table}"
        );
    }
    for table in [
        "durable_import_progress",
        "durable_conditional_readiness",
        "durable_outbox_attempts",
    ] {
        assert!(image.state[table].is_empty());
    }
    let metadata: &Vec<Row> = &image.state["durable_metadata"];
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].len(), 10);
    assert_eq!(metadata[0][0], SqlValue::Integer(1));
    assert_eq!(
        metadata[0][1],
        blob(crate::SQLITE_STRUCTURED_SCHEMA_IDENTITY)
    );
    assert_eq!(metadata[0][2], SqlValue::Text("native-ownership".into()));
    assert_eq!(metadata[0][3], blob(&[31; 32]));
    assert_eq!(metadata[0][4], blob(&[32; 32]));
    assert_eq!(metadata[0][5], number(1));
    assert_eq!(metadata[0][6], number(1));
    assert_eq!(metadata[0][7].as_blob().unwrap().len(), 16); // Captured random source identity, not guessed.
    assert_eq!(metadata[0][8], SqlValue::Integer(1));
    assert_eq!(metadata[0][9], SqlValue::Null);
    assert_eq!(
        image.state["durable_outgoing_barrier"],
        vec![vec![
            SqlValue::Integer(1),
            blob(
                &runtime::outgoing_seal::encode_outgoing_barrier(&OutgoingBarrier::Unsealed)
                    .unwrap()
            )
        ]]
    );
    assert_eq!(
        image.state["durable_successor_serving"],
        vec![vec![
            SqlValue::Integer(1),
            blob(
                &runtime::successor_serving::encode_successor_serving_slot(
                    &runtime::successor_serving::SuccessorServingSlot::Inactive
                )
                .unwrap()
            )
        ]]
    );
    assert_eq!(
        image.blobs["blob_metadata"],
        vec![vec![
            SqlValue::Integer(1),
            blob(SQLITE_BLOB_SCHEMA_IDENTITY)
        ]]
    );
    let unrelated: KnownObject = known_object(false);
    assert!(
        image.blobs["blobs"]
            == vec![vec![
                SqlValue::Integer(i64::from(unrelated.digest.algorithm().as_u16())),
                blob(&unrelated.digest.bytes()),
                blob(&unrelated.bytes)
            ]]
    );
}
fn expected_after_commit(before: &RawImage) -> RawImage {
    let mut expected: RawImage = before.clone();
    for (table, additions) in expected_material(true) {
        let rows: &mut Vec<Row> = expected.state.get_mut(table).unwrap();
        assert!(rows.len().checked_add(additions.len()).unwrap() <= STATE_ROWS);
        rows.extend(additions);
        rows.sort_by(|left: &Row, right: &Row| {
            left[0].as_blob().unwrap().cmp(right[0].as_blob().unwrap())
        });
    }
    expected.state.get_mut("durable_metadata").unwrap()[0][6] = number(2);
    let target: KnownObject = known_object(true);
    let rows: &mut Vec<Row> = expected.blobs.get_mut("blobs").unwrap();
    assert_eq!(rows.len(), 1);
    rows.push(vec![
        SqlValue::Integer(i64::from(target.digest.algorithm().as_u16())),
        blob(&target.digest.bytes()),
        blob(&target.bytes),
    ]);
    rows.sort_by(|left: &Row, right: &Row| {
        left[1].as_blob().unwrap().cmp(right[1].as_blob().unwrap())
    });
    assert_eq!(
        expected.state.values().map(Vec::len).sum::<usize>(),
        STATE_ROWS
    );
    assert_eq!(
        expected.blobs.values().map(Vec::len).sum::<usize>(),
        BLOB_ROWS
    );
    expected
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MainIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}
fn main_identity(path: &Path, owner_uid: u32) -> MainIdentity {
    let metadata: fs::Metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), owner_uid);
    MainIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
    }
}
fn check_root(root: &Path) -> u32 {
    assert!(root.is_absolute());
    assert!(
        root.components()
            .all(|component: std::path::Component<'_>| matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
    );
    assert!(
        root.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("sunrise-native-ownership-")
    );
    let metadata: fs::Metadata = fs::symlink_metadata(root).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    metadata.uid()
}
fn marker_body(pid: u32) -> Vec<u8> {
    let bytes: Vec<u8> = format!("{PHASE} pid={pid}\n").into_bytes();
    assert!(bytes.len() <= 128);
    bytes
}

#[test]
fn after_commit_owner_child() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    assert_eq!(std::env::var(PHASE_ENV).unwrap(), PHASE);
    let root: PathBuf = PathBuf::from(root);
    let uid: u32 = check_root(&root);
    let state_path: PathBuf = root.join("state.db");
    let blob_path: PathBuf = root.join("blobs.db");
    assert_ne!(
        main_identity(&state_path, uid),
        main_identity(&blob_path, uid)
    );
    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_path, namespace()).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&blob_path).unwrap();
    let target: KnownObject = known_object(true);
    assert_eq!(blobs.get_blob(&target.digest).unwrap(), None);
    assert_eq!(
        store
            .get_request_receipt(
                &context(1),
                namespace().domain(),
                receipt(true).request_id()
            )
            .unwrap(),
        None
    );
    // One real successful target blob publication, with both owners alive.
    blobs.put_blob(target.digest, target.bytes.clone()).unwrap();
    assert!(blob_body(&blobs, &target) == target.bytes);
    let marker: PathBuf = root.join("after-commit.marker");
    let staged: PathBuf = root.join("after-commit.pending");
    assert!(
        fs::symlink_metadata(&marker)
            .is_err_and(|error: std::io::Error| error.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(
        fs::symlink_metadata(&staged)
            .is_err_and(|error: std::io::Error| error.kind() == std::io::ErrorKind::NotFound)
    );
    store
        .engine
        .backend()
        .on_commit(CommitBoundary::AfterCommit, move || {
            // Backend invokes this only AFTER successful transaction.commit(), before
            // its final identity check/return. No query/checkpoint/close in this hook.
            let bytes: Vec<u8> = marker_body(std::process::id());
            let mut file: File = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&staged)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.flush().unwrap();
            drop(file);
            fs::rename(&staged, &marker).unwrap();
            loop {
                std::thread::park();
            }
        });
    let _outcome: DurableCommitOutcome = store.commit_invocation(&context(1), input(true));
    panic!("AfterCommit child returned without owned SIGKILL");
}

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Failure cleanup only, never credited as the successful fault oracle.
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn kill_after_commit(root: &Path, uid: u32) {
    let mut child: OwnedChild = OwnedChild(Some(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_SELECTOR, "--nocapture", "--test-threads=1"])
            .env(ROOT_ENV, root)
            .env(PHASE_ENV, PHASE)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    let pid: u32 = child.0.as_ref().unwrap().id();
    let expected: Vec<u8> = marker_body(pid);
    let marker: PathBuf = root.join("after-commit.marker");
    let end: Instant = Instant::now().checked_add(Duration::from_secs(15)).unwrap();
    loop {
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "sole child exited before fault rendezvous"
        );
        assert!(
            Instant::now() < end,
            "AfterCommit marker rendezvous expired"
        );
        match fs::symlink_metadata(&marker) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => panic!("marker metadata failed: {error}"),
            Ok(named) => {
                assert!(named.is_file() && !named.file_type().is_symlink());
                assert_eq!(named.nlink(), 1);
                assert_eq!(named.uid(), uid);
                assert_eq!(named.mode() & 0o7777, 0o600);
                assert!(named.len() <= 128);
                // Parent opens ONLY this marker while the child lives; never DB/sidecar.
                let mut file: File = File::open(&marker).unwrap();
                let held: fs::Metadata = file.metadata().unwrap();
                assert!(held.is_file());
                assert_eq!(held.nlink(), 1);
                assert_eq!(held.uid(), uid);
                assert_eq!(held.mode() & 0o7777, 0o600);
                assert_eq!(
                    (held.dev(), held.ino(), held.len()),
                    (named.dev(), named.ino(), named.len())
                );
                let mut observed: Vec<u8> = Vec::with_capacity(129);
                Read::by_ref(&mut file)
                    .take(129)
                    .read_to_end(&mut observed)
                    .unwrap();
                assert!(
                    observed.len() <= 128 && observed == expected,
                    "wrong phase/PID marker"
                );
                let after: fs::Metadata = file.metadata().unwrap();
                let named_after: fs::Metadata = fs::symlink_metadata(&marker).unwrap();
                assert!(named_after.is_file() && !named_after.file_type().is_symlink());
                assert_eq!(
                    (
                        after.dev(),
                        after.ino(),
                        after.len(),
                        after.uid(),
                        after.nlink(),
                        after.mode()
                    ),
                    (
                        held.dev(),
                        held.ino(),
                        held.len(),
                        held.uid(),
                        held.nlink(),
                        held.mode()
                    )
                );
                assert_eq!(
                    (
                        named_after.dev(),
                        named_after.ino(),
                        named_after.len(),
                        named_after.uid(),
                        named_after.nlink(),
                        named_after.mode()
                    ),
                    (
                        held.dev(),
                        held.ino(),
                        held.len(),
                        held.uid(),
                        held.nlink(),
                        held.mode()
                    )
                );
                break;
            }
        }
    }
    assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none());
    let exact: &mut Child = child.0.as_mut().unwrap();
    exact.kill().unwrap();
    let status: std::process::ExitStatus = exact.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    assert_eq!(status.code(), None);
    drop(child.0.take().unwrap()); // Disarm only after the verified reap.
    // Only after actual wait/reap returns may the parent reopen either database.
}

#[test]
fn positive_blob_after_commit_total_owner_death_preserves_complete_publication() {
    let directory: Directory = Directory::new();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    let root: &Path = &directory.0;
    let uid: u32 = check_root(root);
    let state_path: PathBuf = root.join("state.db");
    let blob_path: PathBuf = root.join("blobs.db");
    let (before_raw, before_public, state_identity, blob_identity): (
        RawImage,
        PublicImage,
        MainIdentity,
        MainIdentity,
    ) = {
        let store: SqliteDurableStore =
            SqliteDurableStore::create_new(&state_path, namespace(), fence(1)).unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::create_new_fresh(&blob_path).unwrap();
        let unrelated: KnownObject = known_object(false);
        blobs
            .put_blob(unrelated.digest, unrelated.bytes.clone())
            .unwrap();
        assert_eq!(
            store.commit_invocation(&context(1), input(false)),
            DurableCommitOutcome::Committed
        );
        store.sync_created().unwrap();
        blobs.sync_created().unwrap();
        let raw: RawImage = raw_image(&state_path, &blob_path);
        assert_initial_raw(&raw);
        let public: PublicImage = public_image(&store, &blobs, None, 1, false);
        assert_eq!(public.token.mutation_sequence(), 1);
        let state_main: MainIdentity = main_identity(&state_path, uid);
        let blob_main: MainIdentity = main_identity(&blob_path, uid);
        assert_ne!(state_main, blob_main);
        (raw, public, state_main, blob_main)
        // ALL parent store/blob/engine/connection/statement/transaction/ImportFile
        // and ancestor/main/WAL/SHM holders drop at this scope boundary. Only
        // scalar identities, known bytes and captured images/tokens survive.
    };
    kill_after_commit(root, uid);
    assert_eq!(main_identity(&state_path, uid), state_identity);
    assert_eq!(main_identity(&blob_path, uid), blob_identity);
    let expected: RawImage = expected_after_commit(&before_raw);
    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_path, namespace()).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&blob_path).unwrap();
    let reader: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_path).unwrap();
    assert!(
        raw_image(&state_path, &blob_path) == expected,
        "complete committed SQL/blob closure after total owner death"
    );
    let recovered: PublicImage = public_image(&store, &blobs, Some(&reader), 1, true);
    let token: PortableSnapshotToken = PortableSnapshotToken::new(
        before_public.token.namespace().to_vec(),
        namespace().domain(),
        fence(1),
        2,
    )
    .unwrap();
    assert_eq!(recovered.token, token);
    assert_eq!(
        store.commit_invocation(&context(1), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert!(raw_image(&state_path, &blob_path) == expected);
    assert_eq!(
        public_image(&store, &blobs, Some(&reader), 1, true),
        recovered
    );
    assert_eq!(
        store.advance_writer_fence(fence(1), fence(2)).unwrap(),
        fence(2)
    );
    let mut fenced: RawImage = expected.clone();
    fenced.state.get_mut("durable_metadata").unwrap()[0][5] = number(2);
    assert!(
        raw_image(&state_path, &blob_path) == fenced,
        "only metadata writer fence changes"
    );
    drop(reader);
    drop(blobs);
    drop(store); // Discard old optional sidecar owners before last-close.
    assert_eq!(main_identity(&state_path, uid), state_identity);
    assert_eq!(main_identity(&blob_path, uid), blob_identity);
    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_path, namespace()).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&blob_path).unwrap();
    let reader: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_path).unwrap();
    assert_eq!(store.writer_fence().unwrap(), fence(2));
    let fenced_public: PublicImage = public_image(&store, &blobs, Some(&reader), 2, true);
    assert_eq!(
        fenced_public.token,
        PortableSnapshotToken::new(
            token.namespace().to_vec(),
            namespace().domain(),
            fence(2),
            2
        )
        .unwrap()
    );
    assert!(raw_image(&state_path, &blob_path) == fenced);
    // Fresh valid deadlines ensure stale fence precedence, not deadline refusal.
    assert_eq!(
        store.commit_invocation(&context(1), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence(2)
        })
    );
    assert!(raw_image(&state_path, &blob_path) == fenced);
    assert_eq!(
        public_image(&store, &blobs, Some(&reader), 2, true),
        fenced_public
    );
    assert_eq!(
        store.commit_invocation(&context(2), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert!(raw_image(&state_path, &blob_path) == fenced);
    assert_eq!(
        public_image(&store, &blobs, Some(&reader), 2, true),
        fenced_public
    );
}
