//! Fixed small integrity-frame vectors are claims, not authenticated plans.
//! Genuine factory/install/replay tests reuse the signed causal fixture.
use super::*;
use canonical_encoding::decode_canonical_frame;
use objects::ObjectId;
use protocol_types::{
    ChainId, Epoch, ExecutionGeneration, HashAlgorithmId, HashSuite, HashSuiteSchedule,
    ProtocolVersion,
};
use runtime::{AtomicityDomainId, DurableObjectProvenance, DurableObjectVersion};

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("cut-vector").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(2),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        ProtocolVersion::new(1),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn binding() -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: context().chain_id().clone(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(2),
        },
        domain: AtomicityDomainId::new([0x11; 32]).unwrap(),
        genesis_digest: digest(0x22),
        validator_set_digest: digest(0x22),
        cut_digest: digest(0x22),
        package_digest: digest(0x22),
        plan_digest: digest(0x22),
        row_count: 3,
        blob_count: 2,
        generation_floor: ExecutionGeneration::new(7),
    }
}
fn progress() -> ImportProgress {
    ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: digest(0x22),
    }
}
fn body_digest() -> Digest32 {
    let bytes: [u8; 32] = [
        0x32, 0x70, 0x6e, 0x73, 0x47, 0x88, 0x1d, 0x30, 0x90, 0x3f, 0x43, 0x93, 0x67, 0x78, 0x9f,
        0xe8, 0xae, 0xec, 0x25, 0x1c, 0x23, 0x25, 0x85, 0x23, 0x19, 0x11, 0xfa, 0xa0, 0xfa, 0x8a,
        0x59, 0x16,
    ];
    Digest32::new(HashAlgorithmId::Sha2_256, bytes)
}
fn state_metadata() -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64C3, 1);
    expected.field_u16(1, 1).unwrap();
    expected.field_u16(2, 1).unwrap();
    expected.finish().unwrap()
}
fn descriptor_vector() -> Vec<u8> {
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64C2, 1);
    expected.field_bytes(1, vec![1, b'k']).unwrap();
    expected.field_bytes(2, state_metadata()).unwrap();
    expected.field_u64(3, 3).unwrap();
    expected
        .field_bytes(4, encode_digest32(&body_digest()).unwrap())
        .unwrap();
    expected.finish().unwrap()
}

fn assert_node_pin(bytes: &[u8], expected: &str) {
    let actual: Digest32 = hash(&resolver(), &context(), bytes).unwrap();
    let hexadecimal: String = actual
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hexadecimal, expected,
        "independently reconstructed Node script pin"
    );
}

#[test]
fn inactive_import_independent_node_hash_pins() {
    // scripts/business-import-vectors.mjs computes these independently from
    // documented field tables. No script or Node runtime is used by this test.
    assert_node_pin(
        &state_metadata(),
        "f7b8e086242a0bb20b5580fc3a78e7a840c906a039ef2bad5b4a64077e0e123c",
    );
    assert_node_pin(
        &row_descriptor(
            &resolver(),
            &context(),
            &ImportRow::State {
                key: b"k".to_vec(),
                value: Some(b"abc".to_vec()),
            },
        )
        .unwrap(),
        "cd725f4fe3c78459b78dcc2561a8e4f2981758943aeaff1bb50c8f2aac8d6255",
    );
    assert_node_pin(
        &head_metadata(&ImportObjectHead::Tombstoned {
            last_object_version: DurableObjectVersion::new(19).unwrap(),
        })
        .unwrap(),
        "7de36c0232da3fc995c7cb3e11b42568dd16c93130bf03a667a28b7e834b22e9",
    );
    assert_node_pin(
        &plan_seed(&binding()).unwrap(),
        "149603f218bf0835543b2e03df500066ac24b67b844bf8dcfbdeae7fed3ab246",
    );
    assert_node_pin(
        &inventory_fold(digest(0x22), 1, &descriptor_vector()).unwrap(),
        "b88fa4d102cfeba1922cbf305c45aa3c5d329c89cb6ddafbca7a7a6f84b379f0",
    );
    assert_node_pin(
        &batch_frame(digest(0x22), &progress(), 3, digest(0x22)).unwrap(),
        "1183ce66efe0a25bddd578732b9ff6b6e9654cf3350c94da291f8f80daedf8df",
    );
    assert_node_pin(
        &progress_seed(digest(0x22)).unwrap(),
        "e12eb0cfd2b630fd4caf6113572d9b8bb95ee59da2ac2212949e7dbe007a0d98",
    );
    assert_node_pin(
        &progress_fold(digest(0x22), digest(0x33), 3).unwrap(),
        "8a683a313e86be89789075494eca750abcfa809747af5a46876716e062166c2f",
    );
}

#[test]
fn inactive_import_descriptor_metadata_head_fixed_vectors() {
    let row: ImportRow = ImportRow::State {
        key: b"k".to_vec(),
        value: Some(b"abc".to_vec()),
    };
    let actual: Vec<u8> = row_descriptor(&resolver(), &context(), &row).unwrap();
    assert_eq!(actual, descriptor_vector());
    let decoded = decode_canonical_frame(&actual).unwrap();
    assert_eq!(decoded.type_id(), 0x64C2);
    assert_eq!(decoded.version(), 1);
    assert_eq!(decoded.required_field(2).unwrap(), state_metadata());
    assert!(decoded.require_type(0x64C3).is_err());
    assert!(decoded.require_version(2).is_err());
    assert!(decoded.require_only_fields(&[1, 2, 3]).is_err());
    for end in [0, 1, actual.len() - 1] {
        assert!(decode_canonical_frame(&actual[..end]).is_err());
    }
    let head: ImportObjectHead = ImportObjectHead::Tombstoned {
        last_object_version: DurableObjectVersion::new(19).unwrap(),
    };
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64C4, 1);
    expected.field_u16(1, 2).unwrap();
    expected.field_u64(2, 19).unwrap();
    expected.field_bytes(3, Vec::new()).unwrap();
    expected.field_u16(4, 0).unwrap();
    expected.field_bytes(5, Vec::new()).unwrap();
    expected.field_u16(6, 0).unwrap();
    expected.field_bytes(7, Vec::new()).unwrap();
    assert_eq!(head_metadata(&head).unwrap(), expected.finish().unwrap());
}

#[test]
fn inactive_import_seed_fold_batch_progress_fixed_vectors_are_non_circular() {
    let pin: ImportBinding = binding();
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64C5, 1);
    expected
        .field_bytes(1, encode_publication_context(&context()).unwrap())
        .unwrap();
    expected.field_bytes(2, vec![0x11; 32]).unwrap();
    for id in 3..=6 {
        expected
            .field_bytes(id, encode_digest32(&digest(0x22)).unwrap())
            .unwrap();
    }
    expected.field_u64(7, 7).unwrap();
    expected.field_u64(8, 3).unwrap();
    expected.field_u64(9, 2).unwrap();
    assert_eq!(plan_seed(&pin).unwrap(), expected.finish().unwrap());
    let mut changed: ImportBinding = pin.clone();
    changed.plan_digest = digest(0x33);
    assert_eq!(plan_seed(&changed).unwrap(), plan_seed(&pin).unwrap());
    changed.generation_floor = ExecutionGeneration::new(8);
    assert_ne!(plan_seed(&changed).unwrap(), plan_seed(&pin).unwrap());
    let descriptor: Vec<u8> = descriptor_vector();
    let mut fold: CanonicalStruct = CanonicalStruct::new(0x64C6, 1);
    fold.field_bytes(1, encode_digest32(&digest(0x22)).unwrap())
        .unwrap();
    fold.field_u16(2, 1).unwrap();
    fold.field_bytes(3, descriptor.clone()).unwrap();
    assert_eq!(
        inventory_fold(digest(0x22), 1, &descriptor).unwrap(),
        fold.finish().unwrap()
    );
    // Independent fixed runtime C1 layout inside C7, not its owner encoder.
    let mut before: CanonicalStruct = CanonicalStruct::new(0x64C1, 1);
    before.field_u64(1, 0).unwrap();
    before.field_bytes(2, Vec::new()).unwrap();
    before
        .field_bytes(3, encode_digest32(&digest(0x22)).unwrap())
        .unwrap();
    let mut batch: CanonicalStruct = CanonicalStruct::new(0x64C7, 1);
    batch
        .field_bytes(1, encode_digest32(&digest(0x22)).unwrap())
        .unwrap();
    batch.field_bytes(2, before.finish().unwrap()).unwrap();
    batch.field_u64(3, 3).unwrap();
    batch
        .field_bytes(4, encode_digest32(&digest(0x22)).unwrap())
        .unwrap();
    assert_eq!(
        batch_frame(digest(0x22), &progress(), 3, digest(0x22)).unwrap(),
        batch.finish().unwrap()
    );
    let mut end: CanonicalStruct = CanonicalStruct::new(0x64C8, 1);
    end.field_bytes(1, encode_digest32(&digest(0x22)).unwrap())
        .unwrap();
    end.field_bytes(2, encode_digest32(&digest(0x33)).unwrap())
        .unwrap();
    end.field_u64(3, 3).unwrap();
    assert_eq!(
        progress_fold(digest(0x22), digest(0x33), 3).unwrap(),
        end.finish().unwrap()
    );
    assert_ne!(
        progress_seed(digest(0x22)).unwrap(),
        progress_fold(digest(0x22), digest(0x22), 0).unwrap()
    );
}

fn blob_version(object: u8, body: u8) -> ImportRow {
    ImportRow::ObjectVersion(DurableObjectVersionRecord::from_blob_reference(
        ObjectId::new([object; 32]),
        DurableObjectVersion::new(1).unwrap(),
        digest(object),
        1,
        DurableObjectProvenance::new(context().chain_id().clone(), ProtocolVersion::new(1)),
        0,
        digest(body),
    ))
}

#[test]
fn inactive_import_batch_new_work_counts_distinct_required_bodies() {
    // Storage-only capacity claims: not a publicly constructible verified plan.
    let rows: Vec<ImportRow> = vec![blob_version(1, 0x51), blob_version(2, 0x52)];
    let mut pin: ImportBinding = binding();
    pin.row_count = 2;
    let mut bodies: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
    for id in [0x51, 0x52] {
        bodies.insert(digest(id), vec![id; MAX_IMPORT_BATCH_BYTES / 2]);
    }
    let parts: Vec<ImportBatch> = batches(
        &resolver(),
        &context(),
        &pin,
        &progress(),
        &rows,
        &[vec![1], vec![2]],
        &bodies,
    )
    .unwrap();
    assert_eq!(
        parts.len(),
        2,
        "two legal 32MiB bodies cannot be eagerly published with one row batch"
    );
    assert_eq!(
        required_blobs(parts[0].rows()),
        BTreeSet::from([digest(0x51)])
    );
    assert_eq!(
        required_blobs(parts[1].rows()),
        BTreeSet::from([digest(0x52)])
    );
    let shared: Vec<ImportRow> = vec![blob_version(1, 0x51), blob_version(2, 0x51)];
    assert_eq!(
        batches(
            &resolver(),
            &context(),
            &pin,
            &progress(),
            &shared,
            &[vec![1], vec![2]],
            &bodies
        )
        .unwrap()
        .len(),
        1,
        "same owning immutable body is counted only once per bounded batch"
    );
    assert!(
        batches(
            &resolver(),
            &context(),
            &pin,
            &progress(),
            &rows,
            &[vec![1], vec![2]],
            &BTreeMap::new()
        )
        .is_err()
    );
}

struct BoundedDestination<'a> {
    inner: &'a runtime_sqlite::SqliteBlobStore,
    chunks: std::cell::Cell<usize>,
}
impl BlobStore for BoundedDestination<'_> {
    fn get_blob(&self, _: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        panic!("unbounded get_blob must never read a resumed destination");
    }
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.inner.put_blob(digest, bytes)
    }
}
impl PortableBlobRepository for BoundedDestination<'_> {
    fn read_portable_blob_descriptor(
        &self,
        digest: &Digest32,
    ) -> Result<Option<runtime::portable::PortableBlobDescriptor>, RuntimeError> {
        self.inner.read_portable_blob_descriptor(digest)
    }
    fn read_portable_blob_chunk(
        &self,
        request: &PortableBlobChunkRequest,
    ) -> Result<PortableBlobChunkOutcome, RuntimeError> {
        self.chunks.set(self.chunks.get().checked_add(1).unwrap());
        self.inner.read_portable_blob_chunk(request)
    }
}

#[test]
fn inactive_import_resumed_native_blob_refuses_oversize_before_any_chunk() {
    // Exact storage integrity only; these claims do not construct a cut/plan.
    let nanos: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "sunrise-inactive-body-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("body.db");
    let native = runtime_sqlite::SqliteBlobStore::open(&path).unwrap();
    let bounded: BoundedDestination<'_> = BoundedDestination {
        inner: &native,
        chunks: std::cell::Cell::new(0),
    };
    let key: Digest32 = digest(0x55);
    assert!(!verify_destination_blob(&bounded, key, b"abc").unwrap());
    native.put_blob(key, b"abc".to_vec()).unwrap();
    assert!(verify_destination_blob(&bounded, key, b"abc").unwrap());
    assert_eq!(bounded.chunks.replace(0), 1);
    let sql: rusqlite::Connection = rusqlite::Connection::open(&path).unwrap();
    let oversize: i64 = i64::try_from(MAX_IMPORT_BATCH_BYTES.checked_add(1).unwrap()).unwrap();
    sql.execute(
        "UPDATE blobs SET content = zeroblob(?1) WHERE digest_algorithm = ?2 AND digest_bytes = ?3",
        rusqlite::params![
            oversize,
            i64::from(key.algorithm().as_u16()),
            key.bytes().as_slice()
        ],
    )
    .unwrap();
    assert!(matches!(
        verify_destination_blob(&bounded, key, b"abc"),
        Err(BusinessImportError::Invalid(
            "destination immutable body descriptor conflicts"
        ))
    ));
    assert_eq!(
        bounded.chunks.get(),
        0,
        "arbitrary persisted length is refused before extracting bytes"
    );
    sql.execute(
        "UPDATE blobs SET content = ?1 WHERE digest_algorithm = ?2 AND digest_bytes = ?3",
        rusqlite::params![
            b"abd".as_slice(),
            i64::from(key.algorithm().as_u16()),
            key.bytes().as_slice()
        ],
    )
    .unwrap();
    assert!(verify_destination_blob(&bounded, key, b"abc").is_err());
    assert_eq!(
        bounded.chunks.get(),
        1,
        "equal-length corrupt bytes are refused by exact bounded comparison"
    );
    drop(sql);
    drop(native);
    std::fs::remove_dir_all(directory).unwrap();
}
