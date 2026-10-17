//! Ignored driver for the explicit Linux/QEMU/ext4 virtual fault profile.
//! The owner supplies real guest loss and block faults; this module injects none.

mod anchored;

use super::*;

const PROFILE: &str = "native-sqlite-qemu-v1";
const ROOT: &str = "/data";
const GUEST_ROWS: usize = 19;

#[derive(Clone)]
struct Proof {
    nonce: String,
    case: String,
    mode: String,
    source: Option<[u8; 16]>,
}

fn bounded_file(path: &str, limit: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)
        .unwrap()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(u64::try_from(bytes.len()).unwrap() <= limit);
    bytes
}

fn unhex(text: &str) -> [u8; 16] {
    assert_eq!(text.len(), 32);
    assert!(
        text.bytes()
            .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let mut bytes: [u8; 16] = [0; 16];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

fn command_proof(command: &str) -> Proof {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for word in command.split_ascii_whitespace() {
        if let Some((name, value)) = word.split_once('=')
            && name.starts_with("sunrise_")
        {
            assert!(
                fields.insert(name, value).is_none(),
                "duplicate guest argument"
            );
        }
    }
    assert_eq!(fields.get("sunrise_profile"), Some(&PROFILE));
    let nonce: String = fields["sunrise_nonce"].to_owned();
    let _nonce_bytes: [u8; 16] = unhex(&nonce);
    let case: String = fields["sunrise_case"].to_owned();
    assert!(["ack", "preack", "write", "flush"].contains(&case.as_str()));
    let mode: String = fields["sunrise_mode"].to_owned();
    assert!(["fault", "recover"].contains(&mode.as_str()));
    let source: Option<[u8; 16]> = fields.get("sunrise_source").map(|text| unhex(text));
    assert_eq!(source.is_some(), mode == "recover");
    assert_eq!(fields.len(), if source.is_some() { 5 } else { 4 });
    Proof {
        nonce,
        case,
        mode,
        source,
    }
}

fn guest_proof() -> Option<Proof> {
    // Ordinary --ignored invocations are inert. Only the dedicated init and an
    // exact matching kernel command line can enter any writable test path.
    if std::env::var("SUNRISE_SQLITE_GUEST_PROFILE")
        .ok()
        .as_deref()
        != Some(PROFILE)
    {
        return None;
    }
    let command: String = String::from_utf8(bounded_file("/proc/cmdline", 4096)).unwrap();
    let proof: Proof = command_proof(&command);
    assert_eq!(
        String::from_utf8(bounded_file("/proc/sys/kernel/osrelease", 128))
            .unwrap()
            .trim(),
        "7.2.9-200.fc44.x86_64"
    );
    assert_eq!(
        String::from_utf8(bounded_file("/sys/block/vda/serial", 128))
            .unwrap()
            .trim(),
        format!("se-{}", &proof.nonce[..16])
    );
    let mounts: String =
        String::from_utf8(bounded_file("/proc/self/mountinfo", 16 * 1024)).unwrap();
    let entries: Vec<&str> = mounts
        .lines()
        .filter(|line| {
            let columns: Vec<&str> = line.split_ascii_whitespace().collect();
            columns.get(4) == Some(&ROOT)
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let (left, right): (&str, &str) = entries[0].split_once(" - ").unwrap();
    let left: Vec<&str> = left.split_ascii_whitespace().collect();
    let right: Vec<&str> = right.split_ascii_whitespace().collect();
    assert_eq!(&right[..2], ["ext4", "/dev/vda1"]);
    assert!(left[5].split(',').any(|flag: &str| flag == "rw"));
    assert_eq!(fs::symlink_metadata(ROOT).unwrap().uid(), 0);
    Some(proof)
}

#[test]
fn guest_command_line_accepts_owner_frames_and_refuses_extra_or_duplicate_fields() {
    // Actual owner launch shape: four sunrise fields in the fault boot and
    // one additional source pin in the cold recovery boot. Other kernel args
    // are intentionally retained rather than represented as guest fields.
    const FAULT: &str = "console=ttyS0 rdinit=/init panic=-1 loglevel=4 sunrise_profile=native-sqlite-qemu-v1 sunrise_nonce=0123456789abcdef0123456789abcdef sunrise_case=flush sunrise_mode=fault";
    let fault: Proof = command_proof(FAULT);
    assert_eq!(fault.nonce, "0123456789abcdef0123456789abcdef");
    assert_eq!(fault.case, "flush");
    assert_eq!(fault.mode, "fault");
    assert_eq!(fault.source, None);
    let recovery: String = FAULT.replace("sunrise_mode=fault", "sunrise_mode=recover")
        + " sunrise_source=10101010101010101010101010101010";
    let recovery: Proof = command_proof(&recovery);
    assert_eq!(recovery.mode, "recover");
    assert_eq!(recovery.source, Some([0x10; 16]));
    for invalid in [
        format!("{FAULT} sunrise_nonce=0123456789abcdef0123456789abcdef"),
        format!("{FAULT} sunrise_unknown=refuse"),
        format!("{FAULT} sunrise_source=10101010101010101010101010101010"),
        FAULT.replace("sunrise_mode=fault", "sunrise_mode=recover"),
    ] {
        assert!(std::panic::catch_unwind(|| command_proof(&invalid)).is_err());
    }
}

fn accepted_commit_error(case: &str, code: i32) -> bool {
    // Ext4 may buffer a virtual block WRITE error until SQLite's WAL fsync.
    // The separately armed flush-only case still requires the exact fsync code.
    matches!(
        (case, code),
        (
            "write",
            rusqlite::ffi::SQLITE_IOERR_WRITE | rusqlite::ffi::SQLITE_IOERR_FSYNC
        ) | ("flush", rusqlite::ffi::SQLITE_IOERR_FSYNC)
    )
}

#[test]
fn real_commit_error_classification_keeps_writeback_and_flush_boundaries_distinct() {
    assert!(accepted_commit_error(
        "write",
        rusqlite::ffi::SQLITE_IOERR_WRITE
    ));
    assert!(accepted_commit_error(
        "write",
        rusqlite::ffi::SQLITE_IOERR_FSYNC
    ));
    assert!(accepted_commit_error(
        "flush",
        rusqlite::ffi::SQLITE_IOERR_FSYNC
    ));
    assert!(!accepted_commit_error(
        "flush",
        rusqlite::ffi::SQLITE_IOERR_WRITE
    ));
    for code in [
        0,
        rusqlite::ffi::SQLITE_IOERR,
        rusqlite::ffi::SQLITE_FULL,
        9999,
    ] {
        assert!(!accepted_commit_error("write", code));
        assert!(!accepted_commit_error("flush", code));
    }
    assert!(!accepted_commit_error(
        "ack",
        rusqlite::ffi::SQLITE_IOERR_FSYNC
    ));
}

fn frame(proof: &Proof, event: &str, detail: &str) {
    println!(
        "\nSUNRISE-GUEST v1 nonce={} case={} mode={} event={event} {detail}",
        proof.nonce, proof.case, proof.mode
    );
    std::io::stdout().flush().unwrap();
}

fn release(proof: &Proof) {
    let mut line: Vec<u8> = Vec::with_capacity(64);
    let mut input: std::io::StdinLock<'static> = std::io::stdin().lock();
    for _ in 0..64 {
        let mut byte: [u8; 1] = [0];
        input.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            assert_eq!(line, format!("release {}", proof.nonce).as_bytes());
            return;
        }
        line.push(byte[0]);
    }
    panic!("oversized guest release frame");
}

fn baseline(source: [u8; 16]) -> RawImage {
    // Every field is independent literal/codec material except the random ID
    // retained by the owner before the fault, never learned from recovery.
    let mut state: Tables = TABLES
        .iter()
        .map(|&(name, _, _)| (name, Vec::new()))
        .collect();
    state.extend(expected_material(false));
    state.insert(
        "durable_metadata",
        vec![vec![
            SqlValue::Integer(1),
            blob(crate::SQLITE_STRUCTURED_SCHEMA_IDENTITY),
            SqlValue::Text("native-ownership".into()),
            blob(&[31; 32]),
            blob(&[32; 32]),
            number(1),
            number(1),
            blob(&source),
            SqlValue::Integer(1),
            SqlValue::Null,
        ]],
    );
    state.insert(
        "durable_outgoing_barrier",
        vec![vec![
            SqlValue::Integer(1),
            blob(
                &runtime::outgoing_seal::encode_outgoing_barrier(&OutgoingBarrier::Unsealed)
                    .unwrap(),
            ),
        ]],
    );
    state.insert(
        "durable_successor_serving",
        vec![vec![
            SqlValue::Integer(1),
            blob(
                &runtime::successor_serving::encode_successor_serving_slot(
                    &runtime::successor_serving::SuccessorServingSlot::Inactive,
                )
                .unwrap(),
            ),
        ]],
    );
    let known: KnownObject = known_object(false);
    let blobs: Tables = BTreeMap::from([
        (
            "blob_metadata",
            vec![vec![
                SqlValue::Integer(1),
                blob(SQLITE_BLOB_SCHEMA_IDENTITY),
            ]],
        ),
        (
            "blobs",
            vec![vec![
                SqlValue::Integer(i64::from(known.digest.algorithm().as_u16())),
                blob(&known.digest.bytes()),
                blob(&known.bytes),
            ]],
        ),
    ]);
    let image: RawImage = RawImage { state, blobs };
    assert_initial_raw(&image);
    image
}

fn guest_raw(state: &Path, blobs: &Path) -> RawImage {
    let mut bytes: usize = 0;
    let mut read =
        |path: &Path, inventory: &[(&'static str, &str, usize)], limit: usize| -> Tables {
            let mut owner: NativeConnection = NativeConnection::open_existing(path, false).unwrap();
            owner
                .inspect(|connection| {
                    // Closed physical column inventory as well as explicit row images.
                    for &(name, query, columns) in inventory {
                        let projection: &str = query
                            .strip_prefix("SELECT ")
                            .unwrap()
                            .split_once(" FROM ")
                            .unwrap()
                            .0;
                        let expected: Vec<&str> = projection.split(", ").collect();
                        assert_eq!(expected.len(), columns);
                        let mut statement: rusqlite::Statement<'_> = connection
                            .prepare(&format!("PRAGMA table_info({name})"))
                            .unwrap();
                        let mut cursor: rusqlite::Rows<'_> = statement.query([]).unwrap();
                        let mut index: usize = 0;
                        while let Some(row) = cursor.next().unwrap() {
                            assert!(index < columns);
                            let ValueRef::Text(column) = row.get_ref(1).unwrap() else {
                                panic!("column name");
                            };
                            assert_eq!(column, expected[index].as_bytes());
                            index += 1;
                        }
                        assert_eq!(index, columns);
                    }
                    Ok::<Tables, NativeError>(tables(connection, inventory, limit, &mut bytes))
                })
                .unwrap()
        };
    RawImage {
        state: read(state, &TABLES, GUEST_ROWS),
        blobs: read(blobs, &BLOB_TABLES, BLOB_ROWS),
    }
}

fn fresh_receipt() -> DurableRequestReceipt {
    DurableRequestReceipt::new(
        OutboxRequestId::new([91; 32]).unwrap(),
        digest(92),
        vec![93, 94],
    )
    .unwrap()
}

fn fresh_input() -> DurableInvocationTransaction {
    let received: DurableRequestReceipt = fresh_receipt();
    DurableInvocationTransaction::new(
        namespace().domain(),
        Some(
            DurableStateTransaction::new(
                namespace().domain(),
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(b"state".to_vec(), StateRevision::new(1)).unwrap(),
                ])
                .unwrap(),
                vec![
                    StateMutationEntry::new(b"state".to_vec(), StateMutation::Put(vec![72]))
                        .unwrap(),
                ],
            )
            .unwrap(),
        ),
        DurableObjectChanges::empty(),
        received.clone(),
        Some(
            DurableOutboxBatch::new(
                received.request_id(),
                received.event_digest(),
                vec![DurableOutboxMessage::new(digest(95), vec![96]).unwrap()],
            )
            .unwrap(),
        ),
    )
    .unwrap()
}

fn after_fresh(mut image: RawImage) -> RawImage {
    let state: &mut Row = image
        .state
        .get_mut("durable_state")
        .unwrap()
        .iter_mut()
        .find(|row| row[0] == blob(b"state"))
        .unwrap();
    assert_eq!(&state[1..], [number(1), blob(&[71])]);
    state[1] = number(2);
    state[2] = blob(&[72]);
    image.state.get_mut("durable_metadata").unwrap()[0][6] = number(3);
    image.state.get_mut("durable_receipts").unwrap().push(vec![
        blob(&[91; 32]),
        SqlValue::Integer(i64::from(HashAlgorithmId::Sha2_256.as_u16())),
        blob(&[92; 32]),
        blob(&[93, 94]),
    ]);
    image
        .state
        .get_mut("durable_outbox_messages")
        .unwrap()
        .push(vec![
            blob(&[91; 32]),
            SqlValue::Integer(0),
            SqlValue::Integer(i64::from(HashAlgorithmId::Sha2_256.as_u16())),
            blob(&[95; 32]),
            blob(&[96]),
        ]);
    image
        .state
        .get_mut("durable_outbox_delivery")
        .unwrap()
        .push(vec![
            blob(&[91; 32]),
            SqlValue::Integer(1),
            SqlValue::Integer(0),
            SqlValue::Integer(0),
            number(0),
            SqlValue::Null,
            SqlValue::Null,
            number(0),
        ]);
    for name in [
        "durable_receipts",
        "durable_outbox_messages",
        "durable_outbox_delivery",
    ] {
        image
            .state
            .get_mut(name)
            .unwrap()
            .sort_by(|left, right| left[0].as_blob().unwrap().cmp(right[0].as_blob().unwrap()));
    }
    assert_eq!(
        image.state.values().map(Vec::len).sum::<usize>(),
        GUEST_ROWS
    );
    image
}

fn guest_public(
    store: &SqliteDurableStore,
    blobs: &SqliteBlobStore,
    source: [u8; 16],
    generation: u64,
    target: bool,
    fresh: bool,
) -> PublicImage {
    let ctx: DurableOperationContext = context(generation);
    let domain: AtomicityDomainId = namespace().domain();
    let mut expected: PortableRows = expected_portable(target);
    if fresh {
        assert!(target);
        let key: DurableRecordKey = DurableRecordKey::State(b"state".to_vec());
        expected.insert(
            key.clone(),
            (
                DurableRecordDescriptor::new(
                    key,
                    DurableRecordMetadata::State {
                        revision: StateRevision::new(2),
                        value_length: Some(1),
                    },
                )
                .unwrap(),
                Some(vec![72]),
            ),
        );
        let received: DurableRequestReceipt = fresh_receipt();
        let key: DurableRecordKey = DurableRecordKey::Receipt(received.request_id());
        assert!(
            expected
                .insert(
                    key.clone(),
                    (
                        DurableRecordDescriptor::new(
                            key,
                            DurableRecordMetadata::Receipt {
                                event_digest: received.event_digest(),
                                length: NonZeroUsize::new(2).unwrap(),
                            }
                        )
                        .unwrap(),
                        Some(vec![93, 94])
                    )
                )
                .is_none()
        );
    }
    let sequence: u64 = if fresh {
        3
    } else if target {
        2
    } else {
        1
    };
    let mut namespace_bytes: Vec<u8> = b"sql/\x10native-ownership".to_vec();
    // Chain length is 16 bytes; validator/domain/source are independent pins.
    assert_eq!(namespace().chain_id().as_str().len(), 16);
    namespace_bytes.extend_from_slice(&[31; 32]);
    namespace_bytes.extend_from_slice(&[32; 32]);
    namespace_bytes.extend_from_slice(&source);
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&ctx, domain).unwrap();
    assert_eq!(
        token,
        PortableSnapshotToken::new(namespace_bytes, domain, fence(generation), sequence).unwrap()
    );
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
            .filter(|key| key.collection() == collection)
            .cloned()
            .collect();
        let mut after: Option<DurableRecordKey> = None;
        let mut saved: Vec<DurableRecordPage> = Vec::new();
        loop {
            assert!(page_count < 20);
            page_count += 1;
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(1).unwrap())
                    .unwrap();
            let page: DurableRecordPage = store
                .scan_portable_keys_at(&ctx, domain, &token, &scan)
                .unwrap();
            let candidates: Vec<DurableRecordKey> = keys
                .iter()
                .filter(|key| after.as_ref().is_none_or(|cursor| *key > cursor))
                .take(2)
                .cloned()
                .collect();
            assert_eq!(
                page,
                DurableRecordPage::from_ordered_candidates(&scan, candidates).unwrap()
            );
            for key in page.keys() {
                assert!(rows.len() < 10);
                let (descriptor, payload): &(DurableRecordDescriptor, Option<Vec<u8>>) =
                    &expected[key];
                assert_eq!(
                    store
                        .read_portable_descriptor_at(&ctx, domain, &token, key)
                        .unwrap()
                        .as_ref(),
                    Some(descriptor)
                );
                let actual: Option<Vec<u8>> = descriptor.payload_length().map(|length| {
                    assert!((1..=CHUNK).contains(&length));
                    let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
                        descriptor.clone(),
                        0,
                        NonZeroUsize::new(CHUNK).unwrap(),
                    )
                    .unwrap();
                    let DurableRecordChunkOutcome::Chunk(chunk) = store
                        .read_portable_chunk_at(&ctx, domain, &token, &request)
                        .unwrap()
                    else {
                        panic!("portable payload");
                    };
                    assert_eq!(chunk.request(), &request);
                    assert!(chunk.is_last());
                    assert_eq!(chunk.bytes().len(), length);
                    chunk.bytes().to_vec()
                });
                assert_eq!(&actual, payload);
                assert!(
                    rows.insert(key.clone(), (descriptor.clone(), actual))
                        .is_none()
                );
            }
            after = page.continuation().cloned();
            saved.push(page);
            if after.is_none() {
                break;
            }
        }
        assert!(pages.insert(collection, saved).is_none());
    }
    assert_eq!(rows, expected);
    // Both immutable bodies were acknowledged BEFORE every selected fault.
    // An orphan target body is allowed only with a completely absent write set.
    let bodies: BTreeMap<Digest32, Vec<u8>> = [false, true]
        .into_iter()
        .map(|target| {
            let known: KnownObject = known_object(target);
            (known.digest, blob_body(blobs, &known))
        })
        .collect();
    assert_eq!(store.begin_portable_snapshot(&ctx, domain).unwrap(), token);
    PublicImage {
        token,
        pages,
        rows,
        bodies,
    }
}

fn fault(proof: &Proof, state_path: &Path, blob_path: &Path) {
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(state_path, namespace(), fence(1)).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::create_new_fresh(blob_path).unwrap();
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
    let initial: RawImage = raw_image(state_path, blob_path);
    assert_initial_raw(&initial);
    let source: [u8; 16] = initial.state["durable_metadata"][0][7]
        .as_blob()
        .unwrap()
        .try_into()
        .unwrap();
    assert!(initial == baseline(source));
    let _initial_public: PublicImage = public_image(&store, &blobs, None, 1, false);
    let target: KnownObject = known_object(true);
    blobs.put_blob(target.digest, target.bytes.clone()).unwrap();
    assert!(blob_body(&blobs, &target) == target.bytes);
    frame(proof, "baseline", &format!("source={}", hex(&source)));
    if proof.case != "ack" {
        let owned: Proof = proof.clone();
        let boundary: CommitBoundary = if proof.case == "preack" {
            CommitBoundary::AfterCommit
        } else {
            CommitBoundary::BeforeDispatch
        };
        store.engine.backend().on_commit(boundary, move || {
            frame(
                &owned,
                if owned.case == "preack" {
                    "committed-before-ack"
                } else {
                    "before-commit"
                },
                "",
            );
            release(&owned);
            assert_ne!(
                owned.case, "preack",
                "pre-ACK owner must be lost without release"
            );
            Ok(())
        });
    }
    let outcome: DurableCommitOutcome = store.commit_invocation(&context(1), input(true));
    if proof.case == "ack" {
        assert_eq!(outcome, DurableCommitOutcome::Committed);
        assert!(guest_raw(state_path, blob_path) == expected_after_commit(&baseline(source)));
        let _complete: PublicImage = public_image(&store, &blobs, None, 1, true);
        frame(proof, "acknowledged", "");
    } else {
        assert!(["write", "flush"].contains(&proof.case.as_str()));
        assert!(matches!(outcome, DurableCommitOutcome::Indeterminate(_)));
        let code: i32 = store.engine.backend().observed_commit_error().unwrap();
        frame(proof, "commit-error", &format!("extended={code}"));
        assert!(
            accepted_commit_error(&proof.case, code),
            "unexpected real COMMIT extended error {code} for {}",
            proof.case
        );
    }
    // Owners stay live. Only the outer owner's actual QEMU kill may end this.
    release(proof);
    panic!("fault owner returned without virtual power loss");
}

fn recover(proof: &Proof, state_path: &Path, blob_path: &Path) {
    let source: [u8; 16] = proof.source.unwrap();
    let all: RawImage = expected_after_commit(&baseline(source));
    let mut none: RawImage = baseline(source);
    none.blobs = all.blobs.clone(); // The previously acknowledged immutable body survives either outcome.
    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(state_path, namespace()).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(blob_path).unwrap();
    // Receipt FIRST, before choosing any retry or querying the rest of state.
    let received: Option<DurableRequestReceipt> = store
        .get_request_receipt(
            &context(1),
            namespace().domain(),
            receipt(true).request_id(),
        )
        .unwrap();
    assert!(received.is_none() || received == Some(receipt(true)));
    let committed: bool = received.is_some();
    if ["ack", "preack"].contains(&proof.case.as_str()) {
        assert!(committed);
    }
    let before: RawImage = if committed { all.clone() } else { none };
    assert!(
        guest_raw(state_path, blob_path) == before,
        "complete cold none-or-all write set"
    );
    let public: PublicImage = guest_public(&store, &blobs, source, 1, committed, false);
    assert_eq!(
        store.advance_writer_fence(fence(1), fence(2)).unwrap(),
        fence(2)
    );
    let mut fenced: RawImage = before;
    fenced.state.get_mut("durable_metadata").unwrap()[0][5] = number(2);
    assert!(guest_raw(state_path, blob_path) == fenced);
    assert_eq!(
        store.commit_invocation(&context(1), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence(2)
        })
    );
    assert!(guest_raw(state_path, blob_path) == fenced);
    let replay: DurableCommitOutcome = store.commit_invocation(&context(2), input(true));
    assert_eq!(
        replay,
        if committed {
            DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
        } else {
            DurableCommitOutcome::Committed
        }
    );
    let mut reconciled: RawImage = all;
    reconciled.state.get_mut("durable_metadata").unwrap()[0][5] = number(2);
    assert!(guest_raw(state_path, blob_path) == reconciled);
    let stable: PublicImage = guest_public(&store, &blobs, source, 2, true, false);
    assert_eq!(stable.bodies, public.bodies);
    assert_eq!(
        store.commit_invocation(&context(2), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert!(guest_raw(state_path, blob_path) == reconciled);
    assert_eq!(guest_public(&store, &blobs, source, 2, true, false), stable);
    // A fresh real state/receipt/outbox commit at the new fence proves service
    // rather than only a successful administrative fence increment.
    assert_eq!(
        store.commit_invocation(&context(1), fresh_input()),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence(2)
        })
    );
    assert!(guest_raw(state_path, blob_path) == reconciled);
    assert_eq!(
        store.commit_invocation(&context(2), fresh_input()),
        DurableCommitOutcome::Committed
    );
    let expected: RawImage = after_fresh(reconciled);
    assert!(guest_raw(state_path, blob_path) == expected);
    let fresh_public: PublicImage = guest_public(&store, &blobs, source, 2, true, true);
    assert_eq!(
        store
            .get_request_receipt(
                &context(2),
                namespace().domain(),
                fresh_receipt().request_id()
            )
            .unwrap(),
        Some(fresh_receipt())
    );
    assert_eq!(
        store.commit_invocation(&context(2), fresh_input()),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert!(guest_raw(state_path, blob_path) == expected);
    assert_eq!(
        guest_public(&store, &blobs, source, 2, true, true),
        fresh_public
    );
    drop(blobs);
    drop(store);
    frame(
        proof,
        "recovered",
        &format!(
            "initial={} tables=12+2 collections=4 bodies=2 sequence=3 fence=2",
            if committed { "all" } else { "none" }
        ),
    );
}

#[test]
#[ignore = "requires the explicit native-sqlite-qemu-v1 guest owner"]
fn virtual_fault_guest() {
    let Some(proof) = guest_proof() else {
        return;
    };
    let root: PathBuf = Path::new(ROOT).join(format!("sunrise-native-ownership-{}", proof.nonce));
    if proof.mode == "fault" {
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let _uid: u32 = check_root(&root);
    let state: PathBuf = root.join("state.db");
    let blobs: PathBuf = root.join("blobs.db");
    if proof.mode == "fault" {
        fault(&proof, &state, &blobs);
    } else {
        recover(&proof, &state, &blobs);
    }
}
