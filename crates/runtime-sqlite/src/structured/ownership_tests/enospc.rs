//! Ignored, real ENOSPC controls for a fresh Docker-only /fault allocation.
//! No Docker invocation, host path parameter, production hook or dependency.
//! These controls are UNFORMATTED, UNCOMPILED and UNEXECUTED at authorship.
//! OS ENOSPC and a separate raw SQLITE_FULL probe are not a main-DB error
//! code, power-loss, custody, public launch or full-profile qualification.

use super::*;
use crate::SqliteBlobStore;
use runtime::portable::{
    DurableCollection, DurablePayloadDescriptor, DurableRecordChunk, DurableRecordMetadata,
};
use runtime::{BlobStore, IndeterminateCommitReason, ObjectHeadRevision};
use runtime_sql_durable::{SqlRow, SqlRows, SqlSession, SqlSessionError, SqlValue};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata, OpenOptions},
    io::{self, Read, Write},
    num::NonZeroUsize,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::{Arc, Mutex, MutexGuard, TryLockError, Weak},
};

const FAULT_ROOT: &str = "/fault";
const FAULT_BYTES: u64 = 64 * 1024 * 1024;
const WRITE_BYTES: usize = 4096;
const LARGE_STATE_BYTES: usize = 8 * 1024 * 1024;
const READ_LIMIT: u64 = 65_536;
const CASE_SECONDS: u64 = 60;
const REFERENCED_OBJECT_DATA_BYTES: usize = 65_537;
static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectFixture {
    Inline,
    Referenced,
}

fn unix_millis() -> u64 {
    let elapsed: Duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    u64::try_from(elapsed.as_millis()).unwrap()
}

fn serial_guard() -> MutexGuard<'static, ()> {
    let end: Instant = Instant::now() + Duration::from_secs(CASE_SECONDS);
    loop {
        assert!(
            Instant::now() < end,
            "exclusive fixture acquisition expired"
        );
        match SERIAL.try_lock() {
            Ok(guard) => return guard,
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::Poisoned(_)) => panic!("previous fault case poisoned exclusion"),
        }
    }
}

fn small_text(path: &Path) -> String {
    let input: File = File::open(path).unwrap();
    let mut bytes: String = String::new();
    let mut bounded: io::Take<File> = input.take(READ_LIMIT + 1);
    bounded.read_to_string(&mut bytes).unwrap();
    assert!(
        u64::try_from(bytes.len()).unwrap() <= READ_LIMIT,
        "oversize guard read"
    );
    bytes
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

fn identity(metadata: &Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn named_directory(path: &Path, held: &File, expected: &Identity) {
    let named: Metadata = fs::symlink_metadata(path).unwrap();
    let opened: Metadata = held.metadata().unwrap();
    assert!(named.is_dir() && !named.file_type().is_symlink());
    assert!(opened.is_dir());
    assert_eq!(&identity(&named), expected);
    assert_eq!(&identity(&opened), expected);
}

fn named_file(path: &Path, held: &File, expected: &Identity) {
    let named: Metadata = fs::symlink_metadata(path).unwrap();
    let opened: Metadata = held.metadata().unwrap();
    assert!(named.is_file() && !named.file_type().is_symlink());
    assert_eq!(named.nlink(), 1);
    assert_eq!(opened.nlink(), 1);
    assert_eq!(&identity(&named), expected);
    assert_eq!(&identity(&opened), expected);
}

fn mount_line(target: &str) -> String {
    let text: String = small_text(Path::new("/proc/self/mountinfo"));
    let matches: Vec<&str> = text
        .lines()
        .filter(|line: &&str| {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            fields.get(4).copied() == Some(target)
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "missing or ambiguous literal mount {target}"
    );
    matches[0].to_owned()
}

fn effective_environment() -> String {
    assert_eq!(
        std::env::var("SUNRISE_EDGE_SQLITE_ENOSPC_DOCKER").as_deref(),
        Ok("1")
    );
    let marker: Metadata = fs::symlink_metadata("/.dockerenv").unwrap();
    assert!(marker.is_file() && !marker.file_type().is_symlink());
    let root: String = mount_line("/");
    let root_fields: Vec<&str> = root.split_ascii_whitespace().collect();
    assert!(root_fields[5].split(',').any(|option: &str| option == "ro"));
    let status: String = small_text(Path::new("/proc/self/status"));
    let uid_line: &str = status
        .lines()
        .find(|line: &&str| line.starts_with("Uid:"))
        .unwrap();
    let ids: Vec<&str> = uid_line.split_ascii_whitespace().skip(1).collect();
    assert_eq!(ids.len(), 4);
    assert!(ids.iter().all(|id: &&str| *id != "0" && *id == ids[0]));
    for expected in [
        "CapPrm:\t0000000000000000",
        "CapEff:\t0000000000000000",
        "NoNewPrivs:\t1",
    ] {
        let expected: &str = expected;
        assert!(status.lines().any(|line: &str| line == expected));
    }
    let resources: [(&str, &str); 4] = [
        ("/sys/fs/cgroup/memory.max", "536870912"),
        ("/sys/fs/cgroup/memory.swap.max", "0"),
        ("/sys/fs/cgroup/cpu.max", "100000 100000"),
        ("/sys/fs/cgroup/pids.max", "64"),
    ];
    for entry in resources {
        let (path, expected): (&str, &str) = entry;
        assert_eq!(small_text(Path::new(path)).trim(), expected);
    }
    let mut interfaces: Vec<String> = fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|entry: io::Result<fs::DirEntry>| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    interfaces.sort();
    assert_eq!(interfaces, vec![String::from("lo")]);
    let actual: String = mount_line(FAULT_ROOT);
    let fields: Vec<&str> = actual.split_ascii_whitespace().collect();
    let separator: usize = fields
        .iter()
        .position(|field: &&str| *field == "-")
        .unwrap();
    assert_eq!(fields[separator + 1], "tmpfs");
    assert_eq!(fields[3], "/");
    assert!(fields[5].split(',').any(|option: &str| option == "rw"));
    let options: Vec<&str> = fields[separator + 3]
        .split(',')
        .chain(fields[5].split(','))
        .collect();
    for required in ["noswap", "nosuid", "nodev", "noexec", "size=65536k"] {
        let required: &str = required;
        assert!(
            options.contains(&required),
            "effective /fault lacks {required}"
        );
    }
    // Linux mountinfo reports the effective tmpfs size, not an env-provided
    // intended capacity. Its reported device must also match the held path.
    let device: u64 = fs::symlink_metadata(FAULT_ROOT).unwrap().dev();
    let major: u64 = ((device >> 8) & 0xfff) | ((device >> 32) & 0xfffff000);
    let minor: u64 = (device & 0xff) | ((device >> 12) & 0xffffff00);
    assert_eq!(fields[2], format!("{major}:{minor}"));
    actual
}

struct FaultDirectory {
    root: File,
    root_identity: Identity,
    mount: String,
    owner: Option<File>,
    owner_identity: Identity,
    path: PathBuf,
    directory: File,
    directory_identity: Identity,
    end: Instant,
    context: DurableOperationContext,
    process: String,
}

impl FaultDirectory {
    fn new() -> Arc<Self> {
        let mount: String = effective_environment();
        let root_path: &Path = Path::new(FAULT_ROOT);
        let root: File = File::open(root_path).unwrap();
        let root_metadata: Metadata = fs::symlink_metadata(root_path).unwrap();
        assert!(root_metadata.is_dir() && !root_metadata.file_type().is_symlink());
        assert_eq!(
            fs::read_dir(root_path).unwrap().count(),
            0,
            "fault allocation is not fresh"
        );
        let owner_path: PathBuf = root_path.join(".native-enospc-owner");
        let mut owner: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&owner_path)
            .unwrap();
        let process: String = small_text(Path::new("/proc/self/stat"));
        let now: u64 = unix_millis();
        let namespace_text: String = format!(
            "native-ownership/validator31/domain32/fence1/pid{}/millis{now}\n",
            std::process::id(),
        );
        owner.write_all(namespace_text.as_bytes()).unwrap();
        owner.sync_all().unwrap();
        let path: PathBuf = root_path.join(format!("native-enospc-{}-{now}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let directory: File = File::open(&path).unwrap();
        let deadline: u64 = now
            .checked_add(CASE_SECONDS.checked_mul(1000).unwrap())
            .unwrap();
        let context: DurableOperationContext = DurableOperationContext::new(
            fence(1),
            StorageDeadline::new(deadline).unwrap(),
            StorageCorrelationId::new([41; 16]).unwrap(),
        );
        let result: Arc<Self> = Arc::new(Self {
            root_identity: identity(&root_metadata),
            root,
            mount,
            owner_identity: identity(&owner.metadata().unwrap()),
            owner: Some(owner),
            directory_identity: identity(&directory.metadata().unwrap()),
            directory,
            path,
            end: Instant::now() + Duration::from_secs(CASE_SECONDS),
            context,
            process,
        });
        result.check();
        result
    }

    fn check_identities(&self) {
        named_directory(Path::new(FAULT_ROOT), &self.root, &self.root_identity);
        named_directory(&self.path, &self.directory, &self.directory_identity);
        assert_eq!(self.directory_identity.device, self.root_identity.device);
        named_file(
            &Path::new(FAULT_ROOT).join(".native-enospc-owner"),
            self.owner.as_ref().unwrap(),
            &self.owner_identity,
        );
        assert_eq!(effective_environment(), self.mount);
        // Only PID/starttime are stable: utime, stime and other live stat
        // counters are deliberately not an equality oracle.
        let current: String = small_text(Path::new("/proc/self/stat"));
        let original_tail: &str = self.process.rsplit_once(") ").unwrap().1;
        let current_tail: &str = current.rsplit_once(") ").unwrap().1;
        assert_eq!(
            current.split_once(' ').unwrap().0,
            self.process.split_once(' ').unwrap().0
        );
        assert_eq!(
            current_tail.split_ascii_whitespace().nth(19),
            original_tail.split_ascii_whitespace().nth(19)
        );
    }

    fn check(&self) {
        assert!(
            Instant::now() < self.end,
            "unchanged monotonic case deadline expired"
        );
        assert!(
            !self.context.deadline().is_expired_at(unix_millis()),
            "unchanged storage deadline expired"
        );
        self.check_identities();
    }
}

impl Drop for FaultDirectory {
    fn drop(&mut self) {
        // All Arc-owned hooks/fillers and the local SQLite handles have been
        // dropped before this last directory owner. Never unlink a live WAL.
        let cleanup: std::thread::Result<io::Result<()>> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
                self.check_identities();
                for entry in fs::read_dir(&self.path)? {
                    let entry: fs::DirEntry = entry?;
                    let name: String = entry.file_name().into_string().unwrap();
                    assert!(
                        [
                            "state.db",
                            "state.db-wal",
                            "state.db-shm",
                            "state.db-journal",
                            "probe.db",
                            "probe.db-wal",
                            "probe.db-shm",
                            "probe.db-journal",
                            "blob.db",
                            "blob.db-wal",
                            "blob.db-shm",
                            "blob.db-journal"
                        ]
                        .contains(&name.as_str()),
                        "unexpected owned-directory residue {name}"
                    );
                    let metadata: Metadata = fs::symlink_metadata(entry.path())?;
                    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                    assert_eq!(metadata.nlink(), 1);
                    assert_eq!(metadata.dev(), self.directory_identity.device);
                    fs::remove_file(entry.path())?;
                }
                fs::remove_dir(&self.path)?;
                let owner_path: PathBuf = Path::new(FAULT_ROOT).join(".native-enospc-owner");
                named_file(
                    &owner_path,
                    self.owner.as_ref().unwrap(),
                    &self.owner_identity,
                );
                drop(self.owner.take());
                let metadata: Metadata = fs::symlink_metadata(&owner_path)?;
                assert_eq!(identity(&metadata), self.owner_identity);
                assert!(!metadata.file_type().is_symlink() && metadata.nlink() == 1);
                fs::remove_file(owner_path)?;
                assert_eq!(fs::read_dir(FAULT_ROOT)?.count(), 0);
                Ok(())
            }));
        match cleanup {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup_failure(&format!("owned fault fixture cleanup: {error}")),
            Err(_) => cleanup_failure("owned fault fixture cleanup assertion failed"),
        }
    }
}

struct Filler {
    directory: Arc<FaultDirectory>,
    file: Option<File>,
    path: PathBuf,
    identity: Identity,
    written: u64,
    enospc_observations: usize,
}

impl Filler {
    fn new(directory: Arc<FaultDirectory>) -> Self {
        directory.check();
        let path: PathBuf = directory.path.join("owned-filler");
        let file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        Self {
            identity: identity(&file.metadata().unwrap()),
            directory,
            file: Some(file),
            path,
            written: 0,
            enospc_observations: 0,
        }
    }

    fn fill(&mut self) {
        let bytes: [u8; WRITE_BYTES] = [0xa5; WRITE_BYTES];
        let maximum: usize = usize::try_from(FAULT_BYTES / u64::try_from(WRITE_BYTES).unwrap())
            .unwrap()
            .checked_add(2)
            .unwrap();
        for attempt in 0..maximum {
            let attempt: usize = attempt;
            self.directory.check();
            let file: &mut File = self.file.as_mut().unwrap();
            named_file(&self.path, file, &self.identity);
            let result: io::Result<usize> = file.write(&bytes);
            self.directory.check();
            named_file(&self.path, file, &self.identity);
            match result {
                Ok(count) => {
                    let count: usize = count;
                    assert!(
                        count > 0 && count <= WRITE_BYTES,
                        "non-progress/oversize write"
                    );
                    self.written = self
                        .written
                        .checked_add(u64::try_from(count).unwrap())
                        .unwrap();
                    assert!(self.written <= FAULT_BYTES);
                    assert_eq!(file.metadata().unwrap().len(), self.written);
                    // A short positive write is progress, never ENOSPC evidence.
                    assert!(
                        attempt + 1 < maximum,
                        "ENOSPC not observed within finite writes"
                    );
                }
                Err(error) => {
                    let error: io::Error = error;
                    assert_eq!(error.raw_os_error(), Some(28), "not real filesystem ENOSPC");
                    assert!(self.written > 0);
                    assert!(file.metadata().unwrap().blocks() > 0);
                    self.enospc_observations = self.enospc_observations.checked_add(1).unwrap();
                    return;
                }
            }
        }
        panic!("finite ENOSPC write bound exhausted");
    }

    fn remove(&mut self) {
        self.directory.check();
        let file: File = self.file.take().unwrap();
        named_file(&self.path, &file, &self.identity);
        drop(file);
        let metadata: Metadata = fs::symlink_metadata(&self.path).unwrap();
        assert_eq!(identity(&metadata), self.identity);
        assert!(metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1);
        fs::remove_file(&self.path).unwrap();
        assert!(!self.path.try_exists().unwrap());
        self.directory.check();
    }
}

impl Drop for Filler {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let file: File = file;
            let cleanup: std::thread::Result<()> =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.directory.check_identities();
                    named_file(&self.path, &file, &self.identity);
                    drop(file);
                    let metadata: Metadata = fs::symlink_metadata(&self.path).unwrap();
                    assert_eq!(identity(&metadata), self.identity);
                    assert!(
                        metadata.is_file()
                            && !metadata.file_type().is_symlink()
                            && metadata.nlink() == 1
                    );
                    fs::remove_file(&self.path).unwrap();
                }));
            if cleanup.is_err() {
                cleanup_failure("owned filler cleanup assertion failed");
            }
        }
    }
}

fn cleanup_failure(message: &str) {
    if std::thread::panicking() {
        eprintln!("{message}");
    } else {
        panic!("{message}");
    }
}

const TABLES: [(&str, &str); 12] = [
    (
        "durable_metadata",
        "SELECT id, schema_identity, chain_id, validator_id, domain, writer_fence, mutation_sequence, source_instance_id, namespace_origin, import_binding FROM durable_metadata ORDER BY id",
    ),
    (
        "durable_import_progress",
        "SELECT id, phase, progress FROM durable_import_progress ORDER BY id",
    ),
    (
        "durable_outgoing_barrier",
        "SELECT id, barrier FROM durable_outgoing_barrier ORDER BY id",
    ),
    (
        "durable_successor_serving",
        "SELECT id, serving FROM durable_successor_serving ORDER BY id",
    ),
    (
        "durable_state",
        "SELECT key, revision, value FROM durable_state ORDER BY key",
    ),
    (
        "durable_conditional_readiness",
        "SELECT slot, status, record FROM durable_conditional_readiness ORDER BY slot",
    ),
    (
        "durable_object_heads",
        "SELECT object_id, status, head_revision, object_version, digest_algorithm, digest_bytes, owner_projection, routing_projection FROM durable_object_heads ORDER BY object_id",
    ),
    (
        "durable_object_versions",
        "SELECT object_id, object_version, digest_algorithm, digest_bytes, schema_version, type_id, created_chain_id, created_protocol_version, created_checkpoint, inline_canonical_bytes, blob_digest_algorithm, blob_digest_bytes FROM durable_object_versions ORDER BY object_id, object_version",
    ),
    (
        "durable_receipts",
        "SELECT request_id, event_digest_algorithm, event_digest_bytes, canonical_bytes FROM durable_receipts ORDER BY request_id",
    ),
    (
        "durable_outbox_messages",
        "SELECT request_id, message_index, payload_digest_algorithm, payload_digest_bytes, canonical_payload FROM durable_outbox_messages ORDER BY request_id, message_index",
    ),
    (
        "durable_outbox_delivery",
        "SELECT request_id, message_count, next_message_index, completed, available_at_unix_millis, active_lease_id, lease_expires_at_unix_millis, attempt_count FROM durable_outbox_delivery ORDER BY request_id",
    ),
    (
        "durable_outbox_attempts",
        "SELECT lease_id, request_id, message_index, lease_expires_at_unix_millis, status FROM durable_outbox_attempts ORDER BY lease_id",
    ),
];

type SqlImage = BTreeMap<String, SqlRows>;
type PortableRows = BTreeMap<DurableRecordKey, (DurableRecordDescriptor, Option<Vec<u8>>)>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompleteImage {
    sql: SqlImage,
    token: PortableSnapshotToken,
    pages: BTreeMap<DurableCollection, Vec<DurableRecordPage>>,
    rows: PortableRows,
    references: BTreeMap<DurableRecordKey, Digest32>,
    blobs: BTreeMap<Digest32, Vec<u8>>,
}

fn complete_image(
    store: &SqliteDurableStore,
    directory: &FaultDirectory,
    fixture: ObjectFixture,
    blobs: Option<&BlobFixture>,
) -> CompleteImage {
    directory.check();
    let context: &DurableOperationContext = &directory.context;
    let domain: AtomicityDomainId = namespace().domain();
    let token: PortableSnapshotToken = store.begin_portable_snapshot(context, domain).unwrap();
    let sql: SqlImage = store.engine.backend().transaction(
        TransactionBudget::Deadline(context.deadline().unix_millis()),
        |session: &mut dyn SqlSession, _now: u64| -> Result<TransactionDecision<SqlImage>, SqlSessionError> {
            let tables: SqlRows = session.exec(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name", &[],
            )?;
            let actual: Vec<String> = tables.rows().iter().map(|row: &SqlRow| {
                row.text(0).unwrap().to_owned()
            }).collect();
            let mut expected: Vec<String> = TABLES.iter()
                .map(|entry: &(&str, &str)| entry.0.to_owned()).collect();
            expected.sort();
            assert_eq!(actual, expected, "all twelve tables must be enumerated");
            let mut result: SqlImage = BTreeMap::new();
            for entry in TABLES {
                let (name, query): (&str, &str) = entry;
                let rows: SqlRows = session.exec(query, &[])?;
                assert_eq!(rows.rows_affected(), 0);
                assert!(result.insert(name.to_owned(), rows).is_none());
            }
            Ok(TransactionDecision::Rollback(result))
        },
    ).unwrap();
    let collections: [DurableCollection; 4] = [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ];
    let mut pages: BTreeMap<DurableCollection, Vec<DurableRecordPage>> = BTreeMap::new();
    let mut rows: PortableRows = BTreeMap::new();
    let mut references: BTreeMap<DurableRecordKey, Digest32> = BTreeMap::new();
    assert_eq!(blobs.is_some(), fixture == ObjectFixture::Referenced);
    let blob_bytes: BTreeMap<Digest32, Vec<u8>> = match blobs {
        Some(blobs) => blobs.observe(directory),
        None => BTreeMap::new(),
    };
    let page_limit: NonZeroUsize = NonZeroUsize::new(1).unwrap();
    let chunk_limit: NonZeroUsize = NonZeroUsize::new(64 * 1024).unwrap();
    for collection in collections {
        let collection: DurableCollection = collection;
        let mut after: Option<DurableRecordKey> = None;
        let mut collection_pages: Vec<DurableRecordPage> = Vec::new();
        loop {
            directory.check();
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), page_limit).unwrap();
            let page: DurableRecordPage = store
                .scan_portable_keys_at(context, domain, &token, &scan)
                .unwrap();
            for key in page.keys() {
                let key: DurableRecordKey = key.clone();
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor_at(context, domain, &token, &key)
                    .unwrap()
                    .unwrap();
                assert_eq!(descriptor.key(), &key);
                match descriptor.metadata() {
                    DurableRecordMetadata::ObjectVersion {
                        payload: DurablePayloadDescriptor::BlobReference(blob_digest),
                        ..
                    } => {
                        assert_eq!(
                            fixture,
                            ObjectFixture::Referenced,
                            "inline fixture acquired an unenumerated referenced blob"
                        );
                        let target: bool = match &key {
                            DurableRecordKey::ObjectVersion(object_id, version)
                                if *object_id == ObjectId::new([61; 32])
                                    && *version == DurableObjectVersion::new(1).unwrap() =>
                            {
                                true
                            }
                            DurableRecordKey::ObjectVersion(object_id, version)
                                if *object_id == ObjectId::new([161; 32])
                                    && *version == DurableObjectVersion::new(1).unwrap() =>
                            {
                                false
                            }
                            _ => panic!("unknown referenced version key"),
                        };
                        let (object, canonical, expected_digest): (Object, Vec<u8>, Digest32) =
                            literal_referenced_object(target);
                        let expected_metadata: DurableRecordMetadata =
                            DurableRecordMetadata::ObjectVersion {
                                digest: expected_digest,
                                schema_version: object.schema_version,
                                provenance: DurableObjectProvenance::new(
                                    namespace().chain_id().clone(),
                                    ProtocolVersion::new(1),
                                ),
                                created_checkpoint: if target { 7 } else { 17 },
                                payload: DurablePayloadDescriptor::BlobReference(expected_digest),
                            };
                        assert_eq!(descriptor.metadata(), &expected_metadata);
                        assert_eq!(*blob_digest, expected_digest);
                        assert_eq!(blob_bytes.get(blob_digest), Some(&canonical));
                        assert_eq!(descriptor.payload_length(), None);
                        assert!(references.insert(key.clone(), *blob_digest).is_none());
                    }
                    DurableRecordMetadata::ObjectVersion { .. }
                        if fixture == ObjectFixture::Referenced =>
                    {
                        panic!("positive-reference fixture unexpectedly became inline");
                    }
                    _ => {}
                }
                let payload: Option<Vec<u8>> = match descriptor.payload_length() {
                    None => None,
                    Some(length) => {
                        let length: usize = length;
                        let mut bytes: Vec<u8> = Vec::new();
                        let mut offset: usize = 0;
                        loop {
                            directory.check();
                            let request: DurableRecordChunkRequest =
                                DurableRecordChunkRequest::new(
                                    descriptor.clone(),
                                    offset,
                                    chunk_limit,
                                )
                                .unwrap();
                            let chunk: Box<DurableRecordChunk> = match store
                                .read_portable_chunk_at(context, domain, &token, &request)
                                .unwrap()
                            {
                                DurableRecordChunkOutcome::Chunk(chunk) => chunk,
                                DurableRecordChunkOutcome::Changed => {
                                    panic!("pinned payload changed")
                                }
                            };
                            assert_eq!(chunk.request(), &request);
                            bytes.extend_from_slice(chunk.bytes());
                            offset = request.range().end;
                            if chunk.is_last() {
                                break;
                            }
                        }
                        assert_eq!(bytes.len(), length);
                        Some(bytes)
                    }
                };
                assert!(rows.insert(key, (descriptor, payload)).is_none());
            }
            after = page.continuation().cloned();
            if let Some(cursor) = &after {
                let cursor: &DurableRecordKey = cursor;
                assert_eq!(page.keys().last(), Some(cursor));
                assert_ne!(scan.after(), Some(cursor));
            }
            collection_pages.push(page);
            if after.is_none() {
                break;
            }
        }
        assert!(pages.insert(collection, collection_pages).is_none());
    }
    assert_eq!(
        store.begin_portable_snapshot(context, domain).unwrap(),
        token
    );
    assert_eq!(store.writer_fence().unwrap(), fence(1));
    directory.check();
    CompleteImage {
        sql,
        token,
        pages,
        rows,
        references,
        blobs: blob_bytes,
    }
}

// Independent fixed objects, not captured invocation mutations or private SQL
// row producers. These bodies cross the ordinary 64KiB canonical inline limit.
fn literal_referenced_object(target: bool) -> (Object, Vec<u8>, Digest32) {
    let (id, owner, type_byte, data_byte): (u8, u8, u8, u8) = if target {
        (61, 62, 63, 64)
    } else {
        (161, 162, 163, 164)
    };
    let object: Object = Object {
        id: ObjectId::new([id; 32]),
        version: 1,
        owner: Owner::Address(Address::new([owner; 32])),
        type_hash: digest(type_byte),
        schema_version: 1,
        data: vec![data_byte; REFERENCED_OBJECT_DATA_BYTES],
    };
    let canonical: Vec<u8> = objects::encode_object(&object).unwrap();
    assert!(canonical.len() > 65_536);
    let object_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            ProtocolVersion::new(1),
            namespace().chain_id(),
            &canonical,
        )
        .unwrap();
    (object, canonical, object_digest)
}

fn expected_reference_keys(target_present: bool) -> BTreeMap<DurableRecordKey, Digest32> {
    let mut expected: BTreeMap<DurableRecordKey, Digest32> = BTreeMap::new();
    for target in [false, true] {
        let target: bool = target;
        if target && !target_present {
            continue;
        }
        let (object, _bytes, digest): (Object, Vec<u8>, Digest32) =
            literal_referenced_object(target);
        let key: DurableRecordKey =
            DurableRecordKey::ObjectVersion(object.id, DurableObjectVersion::new(1).unwrap());
        assert!(expected.insert(key, digest).is_none());
    }
    expected
}

// The original publication owner AND its warmed read-only observer remain
// alive through the structured fault. No blob write occurs after new().
struct BlobFixture {
    // Fields drop in declaration order: discard live-sidecar observations
    // before either SQLite owner can perform legitimate last-close cleanup.
    attachment: Mutex<native_files::ImportFile>,
    reader: SqliteBlobStore,
    writer: SqliteBlobStore,
    path: PathBuf,
    main_identity: Identity,
    expected: BTreeMap<Digest32, (Object, Vec<u8>)>,
}

impl BlobFixture {
    fn new(directory: &FaultDirectory) -> Self {
        directory.check();
        let path: PathBuf = directory.path.join("blob.db");
        let writer: SqliteBlobStore = SqliteBlobStore::create_new_fresh(&path).unwrap();
        let main: Metadata = fs::symlink_metadata(&path).unwrap();
        assert!(main.is_file() && !main.file_type().is_symlink() && main.nlink() == 1);
        assert_eq!(main.dev(), directory.directory_identity.device);
        let main_identity: Identity = identity(&main);
        for name in ["state.db", "probe.db"] {
            let name: &str = name;
            let other: Metadata = fs::symlink_metadata(directory.path.join(name)).unwrap();
            assert_ne!(
                main_identity,
                identity(&other),
                "fixture database inode alias"
            );
        }
        let mut expected: BTreeMap<Digest32, (Object, Vec<u8>)> = BTreeMap::new();
        for target in [false, true] {
            let target: bool = target;
            let (object, canonical, digest): (Object, Vec<u8>, Digest32) =
                literal_referenced_object(target);
            assert_eq!(writer.get_blob(&digest).unwrap(), None);
            writer.put_blob(digest, canonical.clone()).unwrap();
            assert_eq!(writer.get_blob(&digest).unwrap(), Some(canonical.clone()));
            assert!(expected.insert(digest, (object, canonical)).is_none());
            directory.check();
        }
        assert_eq!(expected.len(), 2);
        writer.sync_created().unwrap();
        let reader: SqliteBlobStore = SqliteBlobStore::open_existing(&path).unwrap();
        // Warm both reads and attach any legitimate read-side sidecars before
        // the filesystem fills. A failure is never repaired or skipped.
        for (digest, (_, canonical)) in &expected {
            assert_eq!(reader.get_blob(digest).unwrap().as_ref(), Some(canonical));
        }
        let attachment: native_files::ImportFile = native_files::open_existing(&path).unwrap();
        let fixture: Self = Self {
            writer,
            reader,
            attachment: Mutex::new(attachment),
            path,
            main_identity,
            expected,
        };
        let observed: BTreeMap<Digest32, Vec<u8>> = fixture.observe(directory);
        assert_eq!(observed.len(), 2);
        fixture
    }

    fn observe(&self, directory: &FaultDirectory) -> BTreeMap<Digest32, Vec<u8>> {
        directory.check();
        self.attachment.lock().unwrap().check().unwrap();
        let named: Metadata = fs::symlink_metadata(&self.path).unwrap();
        assert!(named.is_file() && !named.file_type().is_symlink() && named.nlink() == 1);
        assert_eq!(identity(&named), self.main_identity);
        let mut observed: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
        for (expected_digest, (expected_object, expected_bytes)) in &self.expected {
            let mut observed_bytes: Option<Vec<u8>> = None;
            let owners: [&SqliteBlobStore; 2] = [&self.writer, &self.reader];
            for owner in owners {
                let owner: &SqliteBlobStore = owner;
                directory.check();
                let actual: Vec<u8> = owner.get_blob(expected_digest).unwrap().unwrap();
                assert_eq!(&actual, expected_bytes, "prepublished blob bytes changed");
                let actual_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
                    .hash(
                        protocol_types::HashPurpose::Object,
                        ProtocolVersion::new(1),
                        namespace().chain_id(),
                        &actual,
                    )
                    .unwrap();
                assert_eq!(actual_digest, *expected_digest);
                let object: Object = objects::decode_object(&actual).unwrap();
                assert_eq!(&object, expected_object);
                assert_eq!(objects::encode_object(&object).unwrap(), actual);
                observed_bytes = Some(actual);
                self.attachment.lock().unwrap().check().unwrap();
                directory.check();
            }
            assert!(
                observed
                    .insert(*expected_digest, observed_bytes.unwrap())
                    .is_none()
            );
        }
        assert_eq!(observed.len(), 2);
        observed
    }

    fn reopen(self, directory: &FaultDirectory) -> Self {
        directory.check();
        let Self {
            writer,
            reader,
            attachment,
            path,
            main_identity,
            expected,
        }: Self = self;
        // Old live-sidecar observations must be discarded BEFORE last-close.
        // ImportFile retains directories only, never an independent main/SHM FD.
        drop(attachment);
        drop(reader);
        drop(writer);
        let named: Metadata = fs::symlink_metadata(&path).unwrap();
        assert!(named.is_file() && !named.file_type().is_symlink() && named.nlink() == 1);
        assert_eq!(identity(&named), main_identity);
        let writer: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&path).unwrap();
        let reader: SqliteBlobStore = SqliteBlobStore::open_existing(&path).unwrap();
        for (digest, (_, canonical)) in &expected {
            assert_eq!(reader.get_blob(digest).unwrap().as_ref(), Some(canonical));
        }
        let attachment: native_files::ImportFile = native_files::open_existing(&path).unwrap();
        let reopened: Self = Self {
            writer,
            reader,
            attachment: Mutex::new(attachment),
            path,
            main_identity,
            expected,
        };
        let observed: BTreeMap<Digest32, Vec<u8>> = reopened.observe(directory);
        assert_eq!(observed.len(), 2);
        reopened
    }
}

fn target_input(state_length: usize, fixture: ObjectFixture) -> DurableInvocationTransaction {
    let existing: DurableInvocationTransaction = invocation();
    let state: DurableStateTransaction = DurableStateTransaction::new(
        namespace().domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"state".to_vec(), StateRevision::INITIAL).unwrap(),
            StateReadAssertion::new(nonce_key(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(
                b"state".to_vec(),
                StateMutation::Put(vec![71; state_length]),
            )
            .unwrap(),
            StateMutationEntry::new(nonce_key(), StateMutation::Put(nonce_record_bytes())).unwrap(),
        ],
    )
    .unwrap();
    let changes: DurableObjectChanges = match fixture {
        ObjectFixture::Inline => existing.objects(),
        ObjectFixture::Referenced => {
            let (object, _canonical, digest): (Object, Vec<u8>, Digest32) =
                literal_referenced_object(true);
            let version: DurableObjectVersionRecord =
                DurableObjectVersionRecord::from_blob_reference(
                    object.id,
                    DurableObjectVersion::new(object.version).unwrap(),
                    digest,
                    object.schema_version,
                    DurableObjectProvenance::new(
                        namespace().chain_id().clone(),
                        ProtocolVersion::new(1),
                    ),
                    7,
                    digest,
                );
            DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    object.id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    object.id,
                    DurableObjectMutation::Create {
                        version,
                        owner_projection: DurableObjectOwnerProjection::from_owner(object.owner)
                            .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
                    },
                )],
            )
            .unwrap()
        }
    };
    DurableInvocationTransaction::new(
        namespace().domain(),
        Some(state),
        changes,
        existing.receipt().clone(),
        existing.outbox().cloned(),
    )
    .unwrap()
}

fn seed_input(fixture: ObjectFixture) -> DurableInvocationTransaction {
    let object: Object = Object {
        id: ObjectId::new([161; 32]),
        version: 1,
        owner: Owner::Address(Address::new([162; 32])),
        type_hash: digest(163),
        schema_version: 1,
        data: match fixture {
            ObjectFixture::Inline => vec![164],
            ObjectFixture::Referenced => vec![164; REFERENCED_OBJECT_DATA_BYTES],
        },
    };
    let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
    let object_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            ProtocolVersion::new(1),
            namespace().chain_id(),
            &bytes,
        )
        .unwrap();
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(namespace().chain_id().clone(), ProtocolVersion::new(1));
    let version: DurableObjectVersionRecord = match fixture {
        ObjectFixture::Inline => {
            DurableObjectVersionRecord::from_inline_object(object, object_digest, provenance, 17)
                .unwrap()
        }
        ObjectFixture::Referenced => DurableObjectVersionRecord::from_blob_reference(
            object.id,
            DurableObjectVersion::new(object.version).unwrap(),
            object_digest,
            object.schema_version,
            provenance,
            17,
            object_digest,
        ),
    };
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            ObjectId::new([161; 32]),
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            ObjectId::new([161; 32]),
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                    Address::new([162; 32]),
                ))
                .unwrap(),
                routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
            },
        )],
    )
    .unwrap();
    let state: DurableStateTransaction = DurableStateTransaction::new(
        namespace().domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"unrelated".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(b"unrelated".to_vec(), StateMutation::Put(vec![171, 172]))
                .unwrap(),
        ],
    )
    .unwrap();
    let request: OutboxRequestId = OutboxRequestId::new([181; 32]).unwrap();
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request, digest(182), vec![183, 184]).unwrap();
    let outbox: DurableOutboxBatch = DurableOutboxBatch::new(
        request,
        digest(182),
        vec![DurableOutboxMessage::new(digest(185), vec![186]).unwrap()],
    )
    .unwrap();
    DurableInvocationTransaction::new(
        namespace().domain(),
        Some(state),
        changes,
        receipt,
        Some(outbox),
    )
    .unwrap()
}

fn probe_database(path: &Path) -> Connection {
    let file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    drop(file);
    let connection: Connection =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE fault_probe (value BLOB NOT NULL)").unwrap();
    connection
}

fn raw_probe_full(connection: &Connection, directory: &FaultDirectory) {
    directory.check();
    let bytes: Vec<u8> = vec![0x96; LARGE_STATE_BYTES];
    let result: rusqlite::Result<usize> = connection.execute(
        "INSERT INTO fault_probe(value) VALUES (?1)",
        rusqlite::params![bytes],
    );
    match result {
        Err(rusqlite::Error::SqliteFailure(error, _)) => {
            assert_eq!(error.extended_code & 0xff, rusqlite::ffi::SQLITE_FULL);
        }
        other => panic!("independent probe did not observe raw SQLITE_FULL: {other:?}"),
    }
    directory.check();
}

fn assert_target_absent(
    store: &SqliteDurableStore,
    directory: &FaultDirectory,
    image: &CompleteImage,
) {
    let context: &DurableOperationContext = &directory.context;
    let domain: AtomicityDomainId = namespace().domain();
    assert_eq!(
        store
            .get_versioned_durable(context, domain, b"state")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
    assert_eq!(
        store
            .get_versioned_durable(context, domain, b"state")
            .unwrap()
            .value(),
        None
    );
    assert_eq!(
        store
            .get_versioned_durable(context, domain, &nonce_key())
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
    assert_eq!(
        store
            .get_versioned_durable(context, domain, &nonce_key())
            .unwrap()
            .value(),
        None
    );
    assert!(
        store
            .get_request_receipt(context, domain, OutboxRequestId::new([81; 32]).unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_object_head(context, domain, ObjectId::new([61; 32]))
            .unwrap(),
        DurableObjectHead::Absent
    );
    assert!(
        store
            .get_object_version(
                context,
                domain,
                ObjectId::new([61; 32]),
                DurableObjectVersion::new(1).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert!(
        !image
            .rows
            .contains_key(&DurableRecordKey::State(b"state".to_vec()))
    );
    assert!(
        !image
            .rows
            .contains_key(&DurableRecordKey::State(nonce_key()))
    );
    assert!(!image.rows.contains_key(&DurableRecordKey::Receipt(
        OutboxRequestId::new([81; 32]).unwrap()
    )));
    assert!(
        !image
            .rows
            .contains_key(&DurableRecordKey::ObjectHead(ObjectId::new([61; 32])))
    );
    assert!(!image.rows.contains_key(&DurableRecordKey::ObjectVersion(
        ObjectId::new([61; 32]),
        DurableObjectVersion::new(1).unwrap()
    )));
    for table in ["durable_outbox_messages", "durable_outbox_delivery"] {
        let table: &str = table;
        assert!(
            image.sql[table]
                .rows()
                .iter()
                .all(|row: &SqlRow| row.blob(0).unwrap() != [81; 32])
        );
    }
    assert!(
        image.sql["durable_outbox_attempts"]
            .rows()
            .iter()
            .all(|row: &SqlRow| row.blob(1).unwrap() != [81; 32])
    );
}

fn literal_nonce() -> Vec<u8> {
    // Independently fixed canonical bytes: sender51, epoch7, next nonce9.
    const HEX: &str = concat!(
        "534e524506e001000300010020000000",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "0200080000000700000000000000",
        "0300080000000900000000000000"
    );
    let bytes: Vec<u8> = HEX
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    bytes
}

fn literal_object() -> (Object, Vec<u8>, Digest32) {
    // Not invocation(), its object_changes(), or a private row producer.
    let object: Object = Object {
        id: ObjectId::new([61; 32]),
        version: 1,
        owner: Owner::Address(Address::new([62; 32])),
        type_hash: digest(63),
        schema_version: 1,
        data: vec![64],
    };
    let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
    let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            ProtocolVersion::new(1),
            namespace().chain_id(),
            &bytes,
        )
        .unwrap();
    (object, bytes, digest)
}

fn append_expected(image: &CompleteImage, state_length: usize, fixture: ObjectFixture) -> SqlImage {
    let mut sql: SqlImage = image.sql.clone();
    let (object, canonical, object_digest): (Object, Vec<u8>, Digest32) = match fixture {
        ObjectFixture::Inline => literal_object(),
        ObjectFixture::Referenced => literal_referenced_object(true),
    };
    let (inline, blob_algorithm, blob_bytes): (SqlValue, SqlValue, SqlValue) = match fixture {
        ObjectFixture::Inline => (SqlValue::Blob(canonical), SqlValue::Null, SqlValue::Null),
        ObjectFixture::Referenced => (
            SqlValue::Null,
            SqlValue::Integer(i64::from(object_digest.algorithm().as_u16())),
            SqlValue::Blob(object_digest.bytes().to_vec()),
        ),
    };
    let owner: Vec<u8> = objects::encode_owner(&Owner::Address(Address::new([62; 32]))).unwrap();
    let revision: Vec<u8> = 1_u64.to_be_bytes().to_vec();
    let zero: Vec<u8> = 0_u64.to_be_bytes().to_vec();
    let algorithm: i64 = i64::from(HashAlgorithmId::Sha2_256.as_u16());
    let additions: [(&str, Vec<SqlRow>); 6] = [
        (
            "durable_state",
            vec![
                SqlRow::new(vec![
                    SqlValue::Blob(b"state".to_vec()),
                    SqlValue::Blob(revision.clone()),
                    SqlValue::Blob(vec![71; state_length]),
                ]),
                SqlRow::new(vec![
                    SqlValue::Blob(nonce_key()),
                    SqlValue::Blob(revision.clone()),
                    SqlValue::Blob(literal_nonce()),
                ]),
            ],
        ),
        (
            "durable_object_heads",
            vec![SqlRow::new(vec![
                SqlValue::Blob(vec![61; 32]),
                SqlValue::Integer(1),
                SqlValue::Blob(revision.clone()),
                SqlValue::Blob(revision.clone()),
                SqlValue::Integer(algorithm),
                SqlValue::Blob(object_digest.bytes().to_vec()),
                SqlValue::Blob(owner),
                SqlValue::Null,
            ])],
        ),
        (
            "durable_object_versions",
            vec![SqlRow::new(vec![
                SqlValue::Blob(vec![61; 32]),
                SqlValue::Blob(revision),
                SqlValue::Integer(algorithm),
                SqlValue::Blob(object_digest.bytes().to_vec()),
                SqlValue::Integer(1),
                SqlValue::Integer(i64::from(runtime::DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID)),
                SqlValue::Text(String::from("native-ownership")),
                SqlValue::Integer(1),
                SqlValue::Blob(7_u64.to_be_bytes().to_vec()),
                inline,
                blob_algorithm,
                blob_bytes,
            ])],
        ),
        (
            "durable_receipts",
            vec![SqlRow::new(vec![
                SqlValue::Blob(vec![81; 32]),
                SqlValue::Integer(algorithm),
                SqlValue::Blob(vec![82; 32]),
                SqlValue::Blob(vec![83, 84]),
            ])],
        ),
        (
            "durable_outbox_messages",
            vec![SqlRow::new(vec![
                SqlValue::Blob(vec![81; 32]),
                SqlValue::Integer(0),
                SqlValue::Integer(algorithm),
                SqlValue::Blob(vec![85; 32]),
                SqlValue::Blob(vec![86]),
            ])],
        ),
        (
            "durable_outbox_delivery",
            vec![SqlRow::new(vec![
                SqlValue::Blob(vec![81; 32]),
                SqlValue::Integer(1),
                SqlValue::Integer(0),
                SqlValue::Integer(0),
                SqlValue::Blob(zero.clone()),
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::Blob(zero),
            ])],
        ),
    ];
    assert_eq!(object.id, ObjectId::new([61; 32]));
    for addition in additions {
        let (name, extra): (&str, Vec<SqlRow>) = addition;
        let mut rows: Vec<SqlRow> = sql[name].rows().to_vec();
        rows.extend(extra);
        rows.sort_by(|left: &SqlRow, right: &SqlRow| {
            left.blob(0).unwrap().cmp(right.blob(0).unwrap())
        });
        sql.insert(name.to_owned(), SqlRows::new(rows, 0));
    }
    let metadata: &SqlRows = &sql["durable_metadata"];
    assert_eq!(metadata.rows().len(), 1);
    let old: &SqlRow = &metadata.rows()[0];
    let mut values: Vec<SqlValue> = (0..old.len())
        .map(|index: usize| old.value(index).unwrap().clone())
        .collect();
    values[6] = SqlValue::Blob(
        image
            .token
            .mutation_sequence()
            .checked_add(1)
            .unwrap()
            .to_be_bytes()
            .to_vec(),
    );
    sql.insert(
        String::from("durable_metadata"),
        SqlRows::new(vec![SqlRow::new(values)], 0),
    );
    sql
}

fn assert_target_present(
    store: &SqliteDurableStore,
    directory: &FaultDirectory,
    baseline: &CompleteImage,
    current: &CompleteImage,
    state_length: usize,
    fixture: ObjectFixture,
) {
    assert_eq!(
        current.sql,
        append_expected(baseline, state_length, fixture),
        "complete literal write set and every unrelated/protected row"
    );
    assert_eq!(current.token.namespace(), baseline.token.namespace());
    assert_eq!(current.token.domain(), baseline.token.domain());
    assert_eq!(current.token.writer_fence(), baseline.token.writer_fence());
    assert_eq!(
        current.token.mutation_sequence(),
        baseline.token.mutation_sequence().checked_add(1).unwrap()
    );
    let (object, canonical, object_digest): (Object, Vec<u8>, Digest32) = match fixture {
        ObjectFixture::Inline => literal_object(),
        ObjectFixture::Referenced => literal_referenced_object(true),
    };
    let context: &DurableOperationContext = &directory.context;
    let domain: AtomicityDomainId = namespace().domain();
    let state: VersionedStateValue = store
        .get_versioned_durable(context, domain, b"state")
        .unwrap();
    assert_eq!(state.revision(), StateRevision::new(1));
    assert_eq!(state.value(), Some(vec![71; state_length].as_slice()));
    let nonce: VersionedStateValue = store
        .get_versioned_durable(context, domain, &nonce_key())
        .unwrap();
    assert_eq!(nonce.revision(), StateRevision::new(1));
    assert_eq!(nonce.value(), Some(literal_nonce().as_slice()));
    let receipt: DurableRequestReceipt = store
        .get_request_receipt(context, domain, OutboxRequestId::new([81; 32]).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt,
        DurableRequestReceipt::new(
            OutboxRequestId::new([81; 32]).unwrap(),
            digest(82),
            vec![83, 84]
        )
        .unwrap()
    );
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(namespace().chain_id().clone(), ProtocolVersion::new(1));
    let expected_version: DurableObjectVersionRecord = match fixture {
        ObjectFixture::Inline => {
            DurableObjectVersionRecord::from_inline_object(object, object_digest, provenance, 7)
                .unwrap()
        }
        ObjectFixture::Referenced => DurableObjectVersionRecord::from_blob_reference(
            object.id,
            DurableObjectVersion::new(object.version).unwrap(),
            object_digest,
            object.schema_version,
            provenance,
            7,
            object_digest,
        ),
    };
    assert_eq!(
        store
            .get_object_version(
                context,
                domain,
                ObjectId::new([61; 32]),
                DurableObjectVersion::new(1).unwrap()
            )
            .unwrap(),
        Some(expected_version)
    );
    let head: DurableObjectHead = DurableObjectHead::Current {
        head_revision: ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::new(1).unwrap(),
        digest: object_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new(
            [62; 32],
        )))
        .unwrap(),
        routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
    };
    assert_eq!(
        store
            .get_object_head(context, domain, ObjectId::new([61; 32]))
            .unwrap(),
        head
    );
    let expected: [(DurableRecordKey, DurableRecordMetadata, Option<Vec<u8>>); 5] = [
        (
            DurableRecordKey::State(b"state".to_vec()),
            DurableRecordMetadata::State {
                revision: StateRevision::new(1),
                value_length: Some(state_length),
            },
            Some(vec![71; state_length]),
        ),
        (
            DurableRecordKey::State(nonce_key()),
            DurableRecordMetadata::State {
                revision: StateRevision::new(1),
                value_length: Some(literal_nonce().len()),
            },
            Some(literal_nonce()),
        ),
        (
            DurableRecordKey::Receipt(OutboxRequestId::new([81; 32]).unwrap()),
            DurableRecordMetadata::Receipt {
                event_digest: digest(82),
                length: NonZeroUsize::new(2).unwrap(),
            },
            Some(vec![83, 84]),
        ),
        (
            DurableRecordKey::ObjectHead(ObjectId::new([61; 32])),
            DurableRecordMetadata::ObjectHead(head),
            None,
        ),
        (
            DurableRecordKey::ObjectVersion(
                ObjectId::new([61; 32]),
                DurableObjectVersion::new(1).unwrap(),
            ),
            DurableRecordMetadata::ObjectVersion {
                digest: object_digest,
                schema_version: 1,
                provenance: DurableObjectProvenance::new(
                    namespace().chain_id().clone(),
                    ProtocolVersion::new(1),
                ),
                created_checkpoint: 7,
                payload: match fixture {
                    ObjectFixture::Inline => DurablePayloadDescriptor::Inline(
                        NonZeroUsize::new(canonical.len()).unwrap(),
                    ),
                    ObjectFixture::Referenced => {
                        DurablePayloadDescriptor::BlobReference(object_digest)
                    }
                },
            },
            match fixture {
                ObjectFixture::Inline => Some(canonical),
                ObjectFixture::Referenced => None,
            },
        ),
    ];
    for entry in expected {
        let (key, metadata, payload): (DurableRecordKey, DurableRecordMetadata, Option<Vec<u8>>) =
            entry;
        let descriptor: DurableRecordDescriptor =
            DurableRecordDescriptor::new(key.clone(), metadata).unwrap();
        assert_eq!(current.rows.get(&key), Some(&(descriptor, payload)));
    }
    for entry in &baseline.rows {
        let (key, value): (
            &DurableRecordKey,
            &(DurableRecordDescriptor, Option<Vec<u8>>),
        ) = entry;
        assert_eq!(
            current.rows.get(key),
            Some(value),
            "unrelated portable row changed"
        );
    }
    assert_eq!(
        current.rows.len(),
        baseline.rows.len().checked_add(5).unwrap()
    );
    assert_eq!(current.pages.len(), 4);
    assert_eq!(
        current.blobs, baseline.blobs,
        "no blob rewrite during structured commit"
    );
    match fixture {
        ObjectFixture::Inline => {
            assert!(baseline.references.is_empty() && current.references.is_empty());
            assert!(baseline.blobs.is_empty() && current.blobs.is_empty());
        }
        ObjectFixture::Referenced => {
            assert_eq!(baseline.references, expected_reference_keys(false));
            assert_eq!(current.references, expected_reference_keys(true));
            assert_eq!(current.blobs.len(), 2);
            assert_referenced_version_sql(current, true);
            assert_referenced_version_sql(current, false);
        }
    }
}

// Independent complete physical version row, including NULL inline bytes.
fn assert_referenced_version_sql(image: &CompleteImage, target: bool) {
    let (object, _canonical, digest): (Object, Vec<u8>, Digest32) =
        literal_referenced_object(target);
    let expected: SqlRow = SqlRow::new(vec![
        SqlValue::Blob(object.id.as_bytes().to_vec()),
        SqlValue::Blob(1_u64.to_be_bytes().to_vec()),
        SqlValue::Integer(i64::from(digest.algorithm().as_u16())),
        SqlValue::Blob(digest.bytes().to_vec()),
        SqlValue::Integer(1),
        SqlValue::Integer(i64::from(runtime::DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID)),
        SqlValue::Text(String::from("native-ownership")),
        SqlValue::Integer(1),
        SqlValue::Blob((if target { 7_u64 } else { 17_u64 }).to_be_bytes().to_vec()),
        SqlValue::Null,
        SqlValue::Integer(i64::from(digest.algorithm().as_u16())),
        SqlValue::Blob(digest.bytes().to_vec()),
    ]);
    let matching: Vec<&SqlRow> = image.sql["durable_object_versions"]
        .rows()
        .iter()
        .filter(|row: &&SqlRow| row.blob(0).unwrap() == object.id.as_bytes())
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0], &expected);
}

fn seed(
    store: &SqliteDurableStore,
    directory: &FaultDirectory,
    fixture: ObjectFixture,
    blobs: Option<&BlobFixture>,
) -> CompleteImage {
    assert_eq!(
        store.commit_invocation(&directory.context, seed_input(fixture)),
        DurableCommitOutcome::Committed
    );
    let lease: DurableOutboxLeaseId = DurableOutboxLeaseId::new([191; 32]).unwrap();
    let outcome: DurableOutboxClaimOutcome = store.claim_due_outbox(
        &directory.context,
        DueOutboxClaimRequest::new(namespace().domain(), 0, lease, 120_000).unwrap(),
    );
    let claim: runtime::DurableOutboxClaim = match outcome {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        other => panic!("unrelated public claim was not installed: {other:?}"),
    };
    assert_eq!(claim.request_id(), OutboxRequestId::new([181; 32]).unwrap());
    assert_eq!(claim.message_index(), 0);
    assert_eq!(claim.lease_id(), lease);
    assert_eq!(claim.lease_expires_at_unix_millis(), 120_000);
    assert_eq!(claim.canonical_payload(), &[186]);
    let baseline: CompleteImage = complete_image(store, directory, fixture, blobs);
    assert_eq!(baseline.token.writer_fence(), fence(1));
    assert_eq!(baseline.token.mutation_sequence(), 2);
    assert_eq!(baseline.sql["durable_outbox_attempts"].rows().len(), 1);
    assert_eq!(
        baseline.sql["durable_conditional_readiness"].rows().len(),
        0
    );
    assert_eq!(baseline.rows.len(), 4);
    let value: VersionedStateValue = store
        .get_versioned_durable(&directory.context, namespace().domain(), b"unrelated")
        .unwrap();
    assert_eq!(value.revision(), StateRevision::new(1));
    assert_eq!(value.value(), Some([171, 172].as_slice()));
    assert_eq!(
        store
            .get_request_receipt(
                &directory.context,
                namespace().domain(),
                OutboxRequestId::new([181; 32]).unwrap()
            )
            .unwrap(),
        Some(
            DurableRequestReceipt::new(
                OutboxRequestId::new([181; 32]).unwrap(),
                digest(182),
                vec![183, 184]
            )
            .unwrap()
        )
    );
    let object: Object = Object {
        id: ObjectId::new([161; 32]),
        version: 1,
        owner: Owner::Address(Address::new([162; 32])),
        type_hash: digest(163),
        schema_version: 1,
        data: vec![164],
    };
    let version: DurableObjectVersionRecord = store
        .get_object_version(
            &directory.context,
            namespace().domain(),
            object.id,
            DurableObjectVersion::new(1).unwrap(),
        )
        .unwrap()
        .unwrap();
    match fixture {
        ObjectFixture::Inline => {
            assert_eq!(version.payload().inline().unwrap().object(), &object);
            assert_eq!(
                version.payload().inline().unwrap().canonical_bytes(),
                objects::encode_object(&object).unwrap()
            );
            assert!(baseline.references.is_empty() && baseline.blobs.is_empty());
        }
        ObjectFixture::Referenced => {
            let (expected_object, _canonical, expected_digest): (Object, Vec<u8>, Digest32) =
                literal_referenced_object(false);
            let expected_version: DurableObjectVersionRecord =
                DurableObjectVersionRecord::from_blob_reference(
                    expected_object.id,
                    DurableObjectVersion::new(expected_object.version).unwrap(),
                    expected_digest,
                    expected_object.schema_version,
                    DurableObjectProvenance::new(
                        namespace().chain_id().clone(),
                        ProtocolVersion::new(1),
                    ),
                    17,
                    expected_digest,
                );
            assert_eq!(version, expected_version);
            assert_eq!(baseline.references, expected_reference_keys(false));
            assert_eq!(baseline.blobs.len(), 2);
            assert_referenced_version_sql(&baseline, false);
        }
    }
    assert_target_absent(store, directory, &baseline);
    baseline
}

fn wal_path(path: &Path) -> PathBuf {
    let mut name: std::ffi::OsString = path.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

fn wal_empty(path: &Path) {
    let metadata: Metadata = fs::symlink_metadata(wal_path(path)).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        metadata.len(),
        0,
        "WAL already extended before literal COMMIT"
    );
    assert_eq!(metadata.blocks(), 0, "WAL still has allocated blocks");
}

fn recover_and_once(
    store: Arc<SqliteDurableStore>,
    directory: &Arc<FaultDirectory>,
    path: &Path,
    baseline: &CompleteImage,
    state_length: usize,
    fixture: ObjectFixture,
    blobs: Option<BlobFixture>,
) {
    directory.check();
    // Reconcile the live original owner after removal before last-close. No
    // same-request immediate retry is hidden in either failure branch.
    let original: CompleteImage = complete_image(&store, directory, fixture, blobs.as_ref());
    assert_eq!(&original, baseline);
    assert_target_absent(&store, directory, &original);
    let original_main: Metadata = fs::symlink_metadata(path).unwrap();
    assert!(
        original_main.is_file()
            && !original_main.file_type().is_symlink()
            && original_main.nlink() == 1
    );
    let original_identity: Identity = identity(&original_main);
    drop(store);
    let blobs: Option<BlobFixture> = blobs.map(|owner: BlobFixture| owner.reopen(directory));
    let same_main: Metadata = fs::symlink_metadata(path).unwrap();
    assert!(same_main.is_file() && !same_main.file_type().is_symlink() && same_main.nlink() == 1);
    assert_eq!(identity(&same_main), original_identity);
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(path, namespace()).unwrap();
    let reconciled: CompleteImage = complete_image(&reopened, directory, fixture, blobs.as_ref());
    assert_eq!(
        &reconciled, baseline,
        "same DB/namespace full reconciliation before retry"
    );
    assert_target_absent(&reopened, directory, &reconciled);
    assert_eq!(
        reopened.commit_invocation(&directory.context, target_input(state_length, fixture)),
        DurableCommitOutcome::Committed
    );
    let committed: CompleteImage = complete_image(&reopened, directory, fixture, blobs.as_ref());
    assert_target_present(
        &reopened,
        directory,
        baseline,
        &committed,
        state_length,
        fixture,
    );
    assert_eq!(
        reopened.commit_invocation(&directory.context, target_input(state_length, fixture)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert_eq!(
        complete_image(&reopened, directory, fixture, blobs.as_ref()),
        committed,
        "receipt-first replay must not change any raw row, payload, page or token"
    );
}

#[test]
#[ignore = "requires a fresh isolated Docker /fault 64MiB tmpfs noswap and exact outer limits"]
fn docker_noswap_enospc_before_commit_publishes_no_partial_write_set() {
    enospc_before_commit(ObjectFixture::Inline);
}

fn enospc_before_commit(fixture: ObjectFixture) {
    let _serial: MutexGuard<'static, ()> = serial_guard();
    let directory: Arc<FaultDirectory> = FaultDirectory::new();
    let path: PathBuf = directory.path.join("state.db");
    let probe: Connection = probe_database(&directory.path.join("probe.db"));
    let store: Arc<SqliteDurableStore> =
        Arc::new(SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap());
    let blobs: Option<BlobFixture> = match fixture {
        ObjectFixture::Inline => None,
        ObjectFixture::Referenced => Some(BlobFixture::new(&directory)),
    };
    let baseline: CompleteImage = seed(&store, &directory, fixture, blobs.as_ref());
    let mut attachment: native_files::ImportFile = native_files::open_existing(&path).unwrap();
    attachment.check().unwrap();
    let before: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let marker: Arc<Mutex<usize>> = Arc::clone(&before);
    store.engine.backend().on_commit(
        CommitBoundary::BeforeDispatch,
        move || -> Result<(), SqlBackendError> {
            let mut count: MutexGuard<'_, usize> = marker.lock().unwrap();
            *count = count.checked_add(1).unwrap();
            Ok(())
        },
    );
    let mut filler: Filler = Filler::new(Arc::clone(&directory));
    filler.fill();
    raw_probe_full(&probe, &directory);
    filler.fill();
    let input: DurableInvocationTransaction = target_input(LARGE_STATE_BYTES, fixture);
    let outcome: DurableCommitOutcome = store.commit_invocation(&directory.context, input);
    assert_eq!(
        outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
    );
    assert_eq!(
        *before.lock().unwrap(),
        0,
        "must fail before COMMIT hook/dispatch"
    );
    attachment.check().unwrap();
    if let Some(blobs) = &blobs {
        let blobs: &BlobFixture = blobs;
        // The target body is expected unreachable residue, not structured
        // publication. Both blob owners remain live while /fault is full.
        assert_eq!(blobs.observe(&directory), baseline.blobs);
    }
    assert!(filler.enospc_observations >= 2);
    filler.remove();
    drop(attachment);
    recover_and_once(
        store,
        &directory,
        &path,
        &baseline,
        LARGE_STATE_BYTES,
        fixture,
        blobs,
    );
    drop(probe);
}

#[test]
#[ignore = "requires a fresh isolated Docker /fault 64MiB tmpfs noswap and exact outer limits"]
fn docker_noswap_enospc_during_literal_commit_remains_indeterminate() {
    enospc_during_literal_commit(ObjectFixture::Inline);
}

fn enospc_during_literal_commit(fixture: ObjectFixture) {
    let _serial: MutexGuard<'static, ()> = serial_guard();
    let directory: Arc<FaultDirectory> = FaultDirectory::new();
    let path: PathBuf = directory.path.join("state.db");
    let probe: Connection = probe_database(&directory.path.join("probe.db"));
    let store: Arc<SqliteDurableStore> =
        Arc::new(SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap());
    let blobs: Option<BlobFixture> = match fixture {
        ObjectFixture::Inline => None,
        ObjectFixture::Referenced => Some(BlobFixture::new(&directory)),
    };
    let baseline: CompleteImage = seed(&store, &directory, fixture, blobs.as_ref());
    store
        .engine
        .backend()
        .inspect_test(|connection: &Connection| {
            let checkpoint: (i64, i64, i64) = connection
                .query_row(
                    "PRAGMA wal_checkpoint(TRUNCATE)",
                    [],
                    |row: &rusqlite::Row<'_>| -> rusqlite::Result<(i64, i64, i64)> {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    },
                )
                .unwrap();
            assert_eq!(checkpoint, (0, 0, 0));
        });
    wal_empty(&path);
    let attachment: Arc<Mutex<native_files::ImportFile>> =
        Arc::new(Mutex::new(native_files::open_existing(&path).unwrap()));
    attachment.lock().unwrap().check().unwrap();
    let before: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let after: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let filler: Arc<Mutex<Filler>> = Arc::new(Mutex::new(Filler::new(Arc::clone(&directory))));
    let weak: Weak<SqliteDurableStore> = Arc::downgrade(&store);
    let before_marker: Arc<Mutex<usize>> = Arc::clone(&before);
    let after_marker: Arc<Mutex<usize>> = Arc::clone(&after);
    let action_filler: Arc<Mutex<Filler>> = Arc::clone(&filler);
    let action_attachment: Arc<Mutex<native_files::ImportFile>> = Arc::clone(&attachment);
    let action_path: PathBuf = path.clone();
    store.engine.backend().on_commit(
        CommitBoundary::BeforeDispatch,
        move || -> Result<(), SqlBackendError> {
            let mut count: MutexGuard<'_, usize> = before_marker.lock().unwrap();
            *count = count.checked_add(1).unwrap();
            drop(count);
            // No connection inspection here: its mutex is already held. The
            // consumed hook's own slot mutex has been released by test_boundary.
            wal_empty(&action_path);
            action_attachment.lock().unwrap().check().unwrap();
            let owner: Arc<SqliteDurableStore> =
                weak.upgrade().expect("original store remains live");
            owner.engine.backend().on_commit(
                CommitBoundary::AfterCommit,
                move || -> Result<(), SqlBackendError> {
                    let mut count: MutexGuard<'_, usize> = after_marker.lock().unwrap();
                    *count = count.checked_add(1).unwrap();
                    Ok(())
                },
            );
            action_filler.lock().unwrap().fill();
            action_attachment.lock().unwrap().check().unwrap();
            wal_empty(&action_path);
            Ok(())
        },
    );
    let outcome: DurableCommitOutcome =
        store.commit_invocation(&directory.context, target_input(1, fixture));
    assert_eq!(
        outcome,
        DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
    );
    assert_eq!(*before.lock().unwrap(), 1);
    assert_eq!(
        *after.lock().unwrap(),
        0,
        "successful COMMIT would reach installed After marker"
    );
    attachment.lock().unwrap().check().unwrap();
    if let Some(blobs) = &blobs {
        let blobs: &BlobFixture = blobs;
        assert_eq!(blobs.observe(&directory), baseline.blobs);
    }
    // Raw SQLITE_FULL is independently observed on probe.db, outside the
    // hook. The mapped main outcome deliberately does not expose its code.
    raw_probe_full(&probe, &directory);
    assert!(filler.lock().unwrap().enospc_observations >= 1);
    filler.lock().unwrap().remove();
    drop(attachment);
    recover_and_once(store, &directory, &path, &baseline, 1, fixture, blobs);
    assert_eq!(
        *after.lock().unwrap(),
        0,
        "old-owner pending hook is not retried"
    );
    drop(probe);
}

#[test]
#[ignore = "requires a fresh isolated Docker /fault 64MiB tmpfs noswap and exact outer limits"]
fn docker_noswap_enospc_before_commit_preserves_referenced_blob_closure() {
    enospc_before_commit(ObjectFixture::Referenced);
}

#[test]
#[ignore = "requires a fresh isolated Docker /fault 64MiB tmpfs noswap and exact outer limits"]
fn docker_noswap_enospc_during_literal_commit_preserves_referenced_blob_closure() {
    enospc_during_literal_commit(ObjectFixture::Referenced);
}
