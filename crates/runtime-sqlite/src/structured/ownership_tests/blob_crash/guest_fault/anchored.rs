//! Additive actual-guest profile for the independent authority COMMIT phases.
//! No fault is injected here: the private owner supplies virtual power/device EIO.
use super::*;
use crate::anchor::AnchorCommitPhase;
use crate::{AnchorCheckpoint, enroll_independent_anchor, inspect_independent_anchor_inputs};
use sha2::{Digest, Sha256};

const PROFILE: &str = "native-sqlite-qemu-anchored-v1";
const AUTHORITY: &str = "/authority";
const CASES: [&str; 9] = [
    "ack",
    "prepared",
    "pre-finalize",
    "source-write",
    "source-flush",
    "prepare-write",
    "prepare-flush",
    "finalize-write",
    "finalize-flush",
];
const ANCHOR_TABLES: [(&str, &str, usize); 2] = [
    (
        "anchor_head",
        "SELECT id, device, inode, lease_device, lease_inode, sequence, state_root, body_root, pending_state_root, pending_body_root, pending_sequence FROM anchor_head ORDER BY id",
        11,
    ),
    (
        "anchor_bodies",
        "SELECT pending, algorithm, digest, length, content_hash FROM anchor_bodies ORDER BY pending, algorithm, digest",
        5,
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    lease_device: u64,
    lease_inode: u64,
}
impl Identity {
    fn observe(anchor: &Path) -> Self {
        let meta: fs::Metadata = fs::symlink_metadata(anchor).unwrap();
        let mut name: std::ffi::OsString = anchor.as_os_str().to_owned();
        name.push(".lease");
        let lease: fs::Metadata = fs::symlink_metadata(PathBuf::from(name)).unwrap();
        assert!(meta.is_file() && !meta.file_type().is_symlink());
        assert!(lease.is_file() && !lease.file_type().is_symlink());
        assert_eq!(lease.len(), 0);
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            lease_device: lease.dev(),
            lease_inode: lease.ino(),
        }
    }
    fn text(self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.device, self.inode, self.lease_device, self.lease_inode
        )
    }
    fn parse(text: &str) -> Self {
        let values: Vec<u64> = text
            .split(':')
            .map(|value: &str| {
                assert!(
                    !value.is_empty()
                        && value.len() <= 20
                        && value.bytes().all(|byte: u8| byte.is_ascii_digit())
                );
                value.parse::<u64>().unwrap()
            })
            .collect();
        assert_eq!(values.len(), 4);
        Self {
            device: values[0],
            inode: values[1],
            lease_device: values[2],
            lease_inode: values[3],
        }
    }
}
struct GuestProof {
    common: Proof,
    identity: Option<Identity>,
}
fn parse_command(command: &str) -> GuestProof {
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for word in command.split_ascii_whitespace() {
        if let Some((key, value)) = word.split_once('=')
            && key.starts_with("sunrise_")
        {
            assert!(
                fields.insert(key, value).is_none(),
                "duplicate dedicated guest field"
            );
        }
    }
    assert_eq!(fields.get("sunrise_profile"), Some(&PROFILE));
    let nonce: String = fields["sunrise_nonce"].to_owned();
    let _nonce: [u8; 16] = unhex(&nonce);
    let case: String = fields["sunrise_case"].to_owned();
    assert!(CASES.contains(&case.as_str()));
    let mode: String = fields["sunrise_mode"].to_owned();
    assert!(["fault", "recover"].contains(&mode.as_str()));
    let source: Option<[u8; 16]> = fields.get("sunrise_source").map(|text| unhex(text));
    let identity: Option<Identity> = fields
        .get("sunrise_authority")
        .map(|text| Identity::parse(text));
    assert_eq!(source.is_some(), mode == "recover");
    assert_eq!(identity.is_some(), mode == "recover");
    assert_eq!(fields.len(), if mode == "recover" { 6 } else { 4 });
    GuestProof {
        common: Proof {
            nonce,
            case,
            mode,
            source,
        },
        identity,
    }
}
fn mounted(path: &str, device: &str, serial_file: &str, serial: &str) {
    assert_eq!(
        String::from_utf8(bounded_file(serial_file, 128))
            .unwrap()
            .trim(),
        serial
    );
    let mounts: String =
        String::from_utf8(bounded_file("/proc/self/mountinfo", 16 * 1024)).unwrap();
    let entries: Vec<&str> = mounts
        .lines()
        .filter(|line| line.split_ascii_whitespace().nth(4) == Some(path))
        .collect();
    assert_eq!(entries.len(), 1);
    let (left, right): (&str, &str) = entries[0].split_once(" - ").unwrap();
    let right: Vec<&str> = right.split_ascii_whitespace().collect();
    assert_eq!(&right[..2], ["ext4", device]);
    assert!(
        left.split_ascii_whitespace()
            .nth(5)
            .unwrap()
            .split(',')
            .any(|flag: &str| flag == "rw")
    );
    assert_eq!(fs::symlink_metadata(path).unwrap().uid(), 0);
}
fn guest_proof() -> Option<GuestProof> {
    if std::env::var("SUNRISE_SQLITE_GUEST_PROFILE")
        .ok()
        .as_deref()
        != Some(PROFILE)
    {
        return None;
    }
    let proof: GuestProof =
        parse_command(&String::from_utf8(bounded_file("/proc/cmdline", 4096)).unwrap());
    assert_eq!(
        String::from_utf8(bounded_file("/proc/sys/kernel/osrelease", 128))
            .unwrap()
            .trim(),
        "7.2.9-200.fc44.x86_64"
    );
    mounted(
        ROOT,
        "/dev/vda1",
        "/sys/block/vda/serial",
        &format!("se-s-{}", &proof.common.nonce[..16]),
    );
    mounted(
        AUTHORITY,
        "/dev/vdb1",
        "/sys/block/vdb/serial",
        &format!("se-a-{}", &proof.common.nonce[..16]),
    );
    assert_ne!(
        fs::metadata(ROOT).unwrap().dev(),
        fs::metadata(AUTHORITY).unwrap().dev()
    );
    Some(proof)
}
#[test]
fn anchored_guest_parser_requires_exact_owner_frames_and_cold_identity() {
    let fault: String = format!(
        "console=ttyS0 sunrise_profile={PROFILE} sunrise_nonce=0123456789abcdef0123456789abcdef sunrise_case=prepare-flush sunrise_mode=fault"
    );
    assert_eq!(parse_command(&fault).common.case, "prepare-flush");
    let cold: String = fault.replace("sunrise_mode=fault", "sunrise_mode=recover")
        + " sunrise_source=10101010101010101010101010101010 sunrise_authority=1:2:3:4";
    assert_eq!(
        parse_command(&cold).identity.unwrap(),
        Identity {
            device: 1,
            inode: 2,
            lease_device: 3,
            lease_inode: 4
        }
    );
    for invalid in [
        fault.clone() + " sunrise_unknown=x",
        fault.clone() + " sunrise_nonce=0123456789abcdef0123456789abcdef",
        fault.replace("sunrise_mode=fault", "sunrise_mode=recover"),
        cold.replace("sunrise_authority=1:2:3:4", "sunrise_authority=1:2:3"),
        cold.replace(PROFILE, "native-sqlite-qemu-v1"),
    ] {
        assert!(std::panic::catch_unwind(|| parse_command(&invalid)).is_err());
    }
}
fn event(proof: &Proof, name: &str, detail: &str) {
    println!(
        "\nSUNRISE-ANCHOR-GUEST v1 nonce={} case={} mode={} event={name} {detail}",
        proof.nonce, proof.case, proof.mode
    );
    std::io::stdout().flush().unwrap();
}
fn anchored_baseline(source: [u8; 16]) -> RawImage {
    let mut image: RawImage = baseline(source);
    image.state.get_mut("durable_metadata").unwrap()[0][1] =
        blob(runtime_sql_durable::schema::SQL_ANCHORED_SCHEMA_IDENTITY);
    image
}
fn candidates(source: [u8; 16]) -> (RawImage, RawImage) {
    let initial: RawImage = anchored_baseline(source);
    let all: RawImage = expected_after_commit(&initial);
    let mut none: RawImage = initial;
    none.blobs = all.blobs.clone();
    (none, all)
}

// Independent fixture encoder over the complete expected literal rows. It never
// calls the production root implementation or learns a root from recovery.
fn expected_root(image: &RawImage) -> [u8; 32] {
    fn field(hash: &mut Sha256, tag: u8, bytes: &[u8]) {
        hash.update([tag]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash: Sha256 = Sha256::new();
    hash.update(b"SE-LOCAL-ANCHORED-ROWS\0\x01");
    assert_eq!(image.state.len(), 12);
    for &(name, _, width) in &TABLES {
        field(&mut hash, 1, name.as_bytes());
        let rows: &Vec<Row> = &image.state[name];
        assert!(rows.len() <= GUEST_ROWS);
        for row in rows {
            assert_eq!(row.len(), width);
            hash.update([2]);
            hash.update((width as u64).to_be_bytes());
            for value in row {
                match value {
                    SqlValue::Null => field(&mut hash, 0, &[]),
                    SqlValue::Integer(value) => field(&mut hash, 1, &value.to_be_bytes()),
                    SqlValue::Text(value) => field(&mut hash, 2, value.as_bytes()),
                    SqlValue::Blob(value) => field(&mut hash, 3, value),
                }
            }
        }
        hash.update([3]);
        hash.update((rows.len() as u64).to_be_bytes());
    }
    hash.finalize().into()
}
fn body_rows(both: bool, pending: bool) -> Vec<Row> {
    let mut rows: Vec<Row> = [false, true]
        .into_iter()
        .filter(|target| both || !*target)
        .map(|target: bool| {
            let known: KnownObject = known_object(target);
            let content_hash: [u8; 32] = Sha256::digest(&known.bytes).into();
            vec![
                SqlValue::Integer(i64::from(pending)),
                SqlValue::Integer(i64::from(known.digest.algorithm().as_u16())),
                blob(&known.digest.bytes()),
                number(known.bytes.len() as u64),
                blob(&content_hash),
            ]
        })
        .collect();
    rows.sort_by(|a: &Row, b: &Row| a[2].as_blob().unwrap().cmp(b[2].as_blob().unwrap()));
    rows
}
fn body_root(both: bool) -> [u8; 32] {
    let rows: Vec<Row> = body_rows(both, false);
    let mut hash: Sha256 = Sha256::new();
    hash.update(b"SE-LOCAL-IMMUTABLE-BODIES\0\x01");
    hash.update((rows.len() as u64).to_be_bytes());
    for row in rows {
        hash.update(row[1].as_integer().unwrap().to_be_bytes());
        for cell in &row[2..] {
            hash.update(cell.as_blob().unwrap());
        }
    }
    hash.finalize().into()
}
fn expected_authority(
    identity: Identity,
    image: &RawImage,
    sequence: u64,
    both: bool,
    pending: Option<&RawImage>,
) -> Tables {
    let mut head: Row = vec![
        SqlValue::Integer(1),
        number(identity.device),
        number(identity.inode),
        number(identity.lease_device),
        number(identity.lease_inode),
        number(sequence),
        blob(&expected_root(image)),
        blob(&body_root(both)),
        SqlValue::Null,
        SqlValue::Null,
        SqlValue::Null,
    ];
    let mut bodies: Vec<Row> = body_rows(both, false);
    if let Some(candidate) = pending {
        head[8] = blob(&expected_root(candidate));
        head[9] = blob(&body_root(true));
        head[10] = number(sequence.checked_add(1).unwrap());
        bodies.extend(body_rows(true, true));
    }
    BTreeMap::from([("anchor_head", vec![head]), ("anchor_bodies", bodies)])
}
fn authority_rows(path: &Path) -> Tables {
    let mut bytes: usize = 0;
    let mut owner: NativeConnection = NativeConnection::open_existing(path, false).unwrap();
    owner
        .inspect(|connection| {
            for &(name, query, width) in &ANCHOR_TABLES {
                let selected: &str = query
                    .strip_prefix("SELECT ")
                    .unwrap()
                    .split_once(" FROM ")
                    .unwrap()
                    .0;
                let expected: Vec<&str> = selected.split(", ").collect();
                assert_eq!(expected.len(), width);
                let mut statement: rusqlite::Statement<'_> = connection
                    .prepare(&format!("PRAGMA table_info({name})"))
                    .unwrap();
                let mut cursor: rusqlite::Rows<'_> = statement.query([]).unwrap();
                let mut index: usize = 0;
                while let Some(row) = cursor.next().unwrap() {
                    assert!(
                        index < width,
                        "closed authority column inventory before allocation"
                    );
                    let ValueRef::Text(name) = row.get_ref(1).unwrap() else {
                        panic!("column name");
                    };
                    assert_eq!(name, expected[index].as_bytes());
                    index += 1;
                }
                assert_eq!(index, width);
            }
            Ok::<Tables, NativeError>(tables(connection, &ANCHOR_TABLES, 8, &mut bytes))
        })
        .unwrap()
}
fn inspect_source_receipt_first(state: &Path) -> (SqliteDurableStore, bool) {
    // Forensic read-only capability; it grants no independent freshness or writes.
    let store: SqliteDurableStore =
        SqliteDurableStore::open_historical(state, namespace()).unwrap();
    let received: Option<DurableRequestReceipt> = store
        .get_request_receipt(
            &context(1),
            namespace().domain(),
            receipt(true).request_id(),
        )
        .unwrap();
    assert!(received.is_none() || received == Some(receipt(true)));
    (store, received.is_some())
}
fn fault(proof: &Proof, state: &Path, blobs_path: &Path, anchor: &Path) {
    let ordinary: SqliteDurableStore =
        SqliteDurableStore::create_new(state, namespace(), fence(1)).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::create_new_fresh(blobs_path).unwrap();
    let unrelated: KnownObject = known_object(false);
    blobs
        .put_blob(unrelated.digest, unrelated.bytes.clone())
        .unwrap();
    assert_eq!(
        ordinary.commit_invocation(&context(1), input(false)),
        DurableCommitOutcome::Committed
    );
    ordinary.sync_created().unwrap();
    blobs.sync_created().unwrap();
    let initial: RawImage = raw_image(state, blobs_path);
    assert_initial_raw(&initial);
    let source: [u8; 16] = initial.state["durable_metadata"][0][7]
        .as_blob()
        .unwrap()
        .try_into()
        .unwrap();
    assert!(initial == baseline(source));
    drop(blobs);
    drop(ordinary);
    let observed: AnchorCheckpoint = inspect_independent_anchor_inputs(
        state,
        blobs_path,
        namespace().chain_id(),
        namespace().validator_id(),
        namespace().domain(),
    )
    .unwrap();
    let enrolled: AnchorCheckpoint = enroll_independent_anchor(
        state,
        blobs_path,
        anchor,
        namespace().chain_id(),
        namespace().validator_id(),
        namespace().domain(),
        observed.state_root,
        observed.body_manifest_root,
        true,
    )
    .unwrap();
    let identity: Identity = Identity::observe(anchor);
    let initial: RawImage = anchored_baseline(source);
    assert_eq!(enrolled.sequence, 1);
    assert_eq!(enrolled.state_root, expected_root(&initial));
    assert_eq!(enrolled.body_manifest_root, body_root(false));
    assert_eq!(
        authority_rows(anchor),
        expected_authority(identity, &initial, 1, false, None)
    );
    let store: SqliteDurableStore =
        SqliteDurableStore::open_anchored(state, blobs_path, anchor, namespace()).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(blobs_path).unwrap();
    let target: KnownObject = known_object(true);
    blobs.put_blob(target.digest, target.bytes.clone()).unwrap();
    let (none, all): (RawImage, RawImage) = candidates(source);
    assert!(guest_raw(state, blobs_path) == none);
    let _baseline: PublicImage = guest_public(&store, &blobs, source, 1, false, false);
    event(
        proof,
        "baseline",
        &format!("source={} authority={}", hex(&source), identity.text()),
    );
    match proof.case.as_str() {
        "ack" => {}
        "prepared" | "source-write" | "source-flush" => {
            let owned: Proof = proof.clone();
            store
                .engine
                .backend()
                .on_commit(CommitBoundary::BeforeDispatch, move || {
                    event(
                        &owned,
                        if owned.case == "prepared" {
                            "prepared-before-source"
                        } else {
                            "before-source-commit"
                        },
                        "",
                    );
                    release(&owned);
                    assert_ne!(owned.case, "prepared", "power cut must not release");
                    Ok(())
                });
        }
        "pre-finalize" | "finalize-write" | "finalize-flush" => {
            let owned: Proof = proof.clone();
            store
                .engine
                .backend()
                .on_commit(CommitBoundary::AfterCommit, move || {
                    event(&owned, "source-committed", "");
                    if owned.case == "pre-finalize" {
                        release(&owned);
                        panic!("power cut must not release");
                    }
                    Ok(())
                });
        }
        "prepare-write" | "prepare-flush" => {
            let owned: Proof = proof.clone();
            store
                .engine
                .backend()
                .on_commit(CommitBoundary::BeforeDispatch, move || {
                    event(&owned, "source-dispatched", "");
                    Ok(())
                });
        }
        _ => unreachable!(),
    }
    if proof.case.starts_with("prepare-") || proof.case.starts_with("finalize-") {
        let phase: AnchorCommitPhase = if proof.case.starts_with("prepare-") {
            AnchorCommitPhase::Prepare
        } else {
            AnchorCommitPhase::Finalize
        };
        let owned: Proof = proof.clone();
        store.engine.backend().on_anchor_commit(phase, move || {
            event(
                &owned,
                if phase == AnchorCommitPhase::Prepare {
                    "before-prepare-commit"
                } else {
                    "before-finalize-commit"
                },
                "",
            );
            release(&owned);
        });
    }
    let outcome: DurableCommitOutcome = store.commit_invocation(&context(1), input(true));
    if proof.case == "ack" {
        assert_eq!(outcome, DurableCommitOutcome::Committed);
        assert!(guest_raw(state, blobs_path) == all);
        assert_eq!(
            authority_rows(anchor),
            expected_authority(identity, &all, 2, true, None)
        );
        let _all: PublicImage = guest_public(&store, &blobs, source, 1, true, false);
        event(proof, "acknowledged", "authority=finalized");
    } else {
        let (phase, kind): (&str, &str) = proof.case.split_once('-').unwrap();
        let code: i32 = if phase == "source" {
            assert!(matches!(outcome, DurableCommitOutcome::Indeterminate(_)));
            store.engine.backend().observed_commit_error().unwrap()
        } else {
            let (observed_phase, code): (AnchorCommitPhase, i32) = store
                .engine
                .backend()
                .observed_anchor_commit_error()
                .unwrap();
            assert_eq!(
                observed_phase,
                if phase == "prepare" {
                    AnchorCommitPhase::Prepare
                } else {
                    AnchorCommitPhase::Finalize
                }
            );
            if phase == "prepare" {
                assert_eq!(
                    outcome,
                    DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
                );
            } else {
                assert!(matches!(outcome, DurableCommitOutcome::Indeterminate(_)));
            }
            code
        };
        event(
            proof,
            "commit-error",
            &format!("phase={phase} extended={code}"),
        );
        assert!(accepted_commit_error(kind, code));
    }
    release(proof);
    panic!("fault guest returned without real virtual power loss");
}

fn recover(proof: &Proof, identity: Identity, state: &Path, blobs_path: &Path, anchor: &Path) {
    assert_eq!(
        Identity::observe(anchor),
        identity,
        "same original authority and lease inodes"
    );
    let source: [u8; 16] = proof.source.unwrap();
    let (none, all): (RawImage, RawImage) = candidates(source);
    let (forensic, committed): (SqliteDurableStore, bool) = inspect_source_receipt_first(state);
    let initial: RawImage = if committed { all.clone() } else { none.clone() };
    assert!(
        guest_raw(state, blobs_path) == initial,
        "complete cold source none-or-all"
    );
    let bodies: SqliteBlobStore = SqliteBlobStore::open_existing(blobs_path).unwrap();
    let public: PublicImage = guest_public(&forensic, &bodies, source, 1, committed, false);
    drop(bodies);
    drop(forensic);
    if ["ack", "pre-finalize"].contains(&proof.case.as_str()) || proof.case.starts_with("finalize-")
    {
        assert!(committed);
    }
    if proof.case == "prepared" || proof.case.starts_with("prepare-") {
        assert!(!committed);
    }
    let authority: Tables = authority_rows(anchor);
    let old: Tables = expected_authority(identity, &none, 1, false, None);
    let pending: Tables = expected_authority(identity, &none, 1, false, Some(&all));
    let acknowledged: Tables = expected_authority(identity, &all, 2, true, None);
    match proof.case.as_str() {
        "ack" => assert_eq!(authority, acknowledged),
        "prepared" | "pre-finalize" | "source-write" | "source-flush" => {
            assert_eq!(authority, pending)
        }
        "prepare-write" | "prepare-flush" => assert!(authority == old || authority == pending),
        "finalize-write" | "finalize-flush" => {
            assert!(authority == pending || authority == acknowledged)
        }
        _ => unreachable!(),
    }
    if authority == pending && !committed {
        for _attempt in 0..3 {
            assert!(
                SqliteDurableStore::open_anchored(state, blobs_path, anchor, namespace()).is_err()
            );
            assert!(guest_raw(state, blobs_path) == none);
            assert_eq!(authority_rows(anchor), pending);
            assert_eq!(Identity::observe(anchor), identity);
        }
        event(
            proof,
            "stopped",
            "initial=none tables=12+2 authority=2 collections=4 bodies=2 fence=1 pending=2 repeated=3",
        );
        return;
    }
    let store: SqliteDurableStore =
        SqliteDurableStore::open_anchored(state, blobs_path, anchor, namespace()).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(blobs_path).unwrap();
    assert_eq!(
        authority_rows(anchor),
        if committed { acknowledged } else { old }
    );
    let _before: PublicImage = guest_public(&store, &blobs, source, 1, committed, false);
    assert_eq!(
        store.advance_writer_fence(fence(1), fence(2)).unwrap(),
        fence(2)
    );
    let mut fenced: RawImage = initial;
    fenced.state.get_mut("durable_metadata").unwrap()[0][5] = number(2);
    assert!(guest_raw(state, blobs_path) == fenced);
    assert_eq!(
        authority_rows(anchor),
        expected_authority(identity, &fenced, if committed { 3 } else { 2 }, true, None)
    );
    assert_eq!(
        store.commit_invocation(&context(1), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence(2)
        })
    );
    assert_eq!(
        store.commit_invocation(&context(2), input(true)),
        if committed {
            DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
        } else {
            DurableCommitOutcome::Committed
        }
    );
    let mut reconciled: RawImage = all;
    reconciled.state.get_mut("durable_metadata").unwrap()[0][5] = number(2);
    assert!(guest_raw(state, blobs_path) == reconciled);
    let stable_authority: Tables = expected_authority(identity, &reconciled, 3, true, None);
    assert_eq!(authority_rows(anchor), stable_authority);
    let stable: PublicImage = guest_public(&store, &blobs, source, 2, true, false);
    assert_eq!(stable.bodies, public.bodies);
    assert_eq!(
        store.commit_invocation(&context(2), input(true)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert!(guest_raw(state, blobs_path) == reconciled);
    assert_eq!(authority_rows(anchor), stable_authority);
    assert_eq!(
        store.commit_invocation(&context(1), fresh_input()),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence(2)
        })
    );
    assert_eq!(
        store.commit_invocation(&context(2), fresh_input()),
        DurableCommitOutcome::Committed
    );
    let expected: RawImage = after_fresh(reconciled);
    assert!(guest_raw(state, blobs_path) == expected);
    let fresh_authority: Tables = expected_authority(identity, &expected, 4, true, None);
    assert_eq!(authority_rows(anchor), fresh_authority);
    let fresh: PublicImage = guest_public(&store, &blobs, source, 2, true, true);
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
    assert!(guest_raw(state, blobs_path) == expected);
    assert_eq!(authority_rows(anchor), fresh_authority);
    assert_eq!(guest_public(&store, &blobs, source, 2, true, true), fresh);
    drop(blobs);
    drop(store);
    assert_eq!(Identity::observe(anchor), identity);
    event(
        proof,
        "recovered",
        &format!(
            "initial={} tables=12+2 authority=2 collections=4 bodies=2 sequence=3 fence=2 anchor_sequence=4",
            if committed { "all" } else { "none" }
        ),
    );
}
#[test]
#[ignore = "requires the explicit native-sqlite-qemu-anchored-v1 guest owner"]
fn virtual_anchored_fault_guest() {
    let Some(proof) = guest_proof() else {
        return;
    };
    let root: PathBuf =
        Path::new(ROOT).join(format!("sunrise-native-ownership-{}", proof.common.nonce));
    let authority: PathBuf =
        Path::new(AUTHORITY).join(format!("sunrise-native-ownership-{}", proof.common.nonce));
    if proof.common.mode == "fault" {
        for directory in [&root, &authority] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let _uid: u32 = check_root(&root);
    let _authority_uid: u32 = check_root(&authority);
    let state: PathBuf = root.join("state.db");
    let blobs: PathBuf = root.join("blobs.db");
    let anchor: PathBuf = authority.join("anchor.db");
    if proof.common.mode == "fault" {
        fault(&proof.common, &state, &blobs, &anchor);
    } else {
        recover(
            &proof.common,
            proof.identity.unwrap(),
            &state,
            &blobs,
            &anchor,
        );
    }
}
