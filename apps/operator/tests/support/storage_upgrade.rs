//! Opt-in actual prior-release -> independent-anchor software/storage upgrade.
//! The prior ELF is an explicit, independently qualified build input. Neither
//! its missing path nor incompatible rollback may fall back to current code.
use super::*;
use compiled_source_host_process::spawn_strict_bounded_output;
use node_core::NodeResponse;
use protocol_types::HashPurpose;
use runtime::{
    BlobStore, DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead,
    DurableObjectHeadRead, DurableObjectMutation, DurableObjectMutationEntry,
    DurableObjectOwnerProjection, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableRequestId, DurableRequestReceipt,
    ObjectHeadRevision, StructuredDurableDomainStateStore,
};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
};

const PRIOR_SOURCE: &str = "9de634a7bdcd38b0b2f78c6dcab695eaf8f80853";
const PRIOR_SHA256: &str = "00fdc14a864249d798460562cfa10dbd3e2e8e50da91dcc85ab691001bc7ae24";
const PRIOR_BYTES: u64 = 20_055_432;
const PRIOR_ENV: &str = "SUNRISE_EDGE_PREVIOUS_SQLITE_SOURCE_HOST";
const MAX_STOPPED_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl FileStamp {
    fn of(metadata: &fs::Metadata) -> Self {
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

fn effective_uid() -> u32 {
    let mut file: fs::File = fs::File::open("/proc/self/status").unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    Read::by_ref(&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024, "bounded kernel process status");
    let text: &str = std::str::from_utf8(&bytes).unwrap();
    let mut lines = text
        .lines()
        .filter_map(|line: &str| line.strip_prefix("Uid:"));
    let fields: Vec<u32> = lines
        .next()
        .unwrap()
        .split_whitespace()
        .map(|value: &str| value.parse::<u32>().unwrap())
        .collect();
    assert_eq!(fields.len(), 4);
    assert!(lines.next().is_none());
    fields[1]
}

/// Fixed admission precedes allocation; the no-follow descriptor and named
/// attachment must agree before and after a bounded complete read.
fn prior_bytes(path: &Path, mode: u32) -> (FileStamp, Vec<u8>) {
    use rustix::fs::{Mode, OFlags};
    assert!(
        path.is_absolute(),
        "explicit prior executable must be absolute"
    );
    assert_eq!(
        fs::canonicalize(path).unwrap(),
        path,
        "no symlink ancestors"
    );
    let stamp: FileStamp = FileStamp::of(&fs::symlink_metadata(path).unwrap());
    assert_eq!(stamp.uid, effective_uid());
    assert_eq!(stamp.mode & 0o7777, mode);
    assert_eq!(stamp.links, 1);
    assert_eq!(stamp.length, PRIOR_BYTES);
    let descriptor: rustix::fd::OwnedFd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let mut file: fs::File = descriptor.into();
    assert_eq!(FileStamp::of(&file.metadata().unwrap()), stamp);
    let mut bytes: Vec<u8> = Vec::new();
    Read::by_ref(&mut file)
        .take(PRIOR_BYTES.checked_add(1).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, PRIOR_BYTES);
    assert_eq!(&bytes[..4], b"\x7fELF");
    let digest: sha2::digest::Output<Sha256> = Sha256::digest(&bytes);
    assert_eq!(
        hex(digest.as_slice()),
        PRIOR_SHA256,
        "exact prior RELEASE ELF"
    );
    assert_eq!(FileStamp::of(&file.metadata().unwrap()), stamp);
    assert_eq!(FileStamp::of(&fs::symlink_metadata(path).unwrap()), stamp);
    (stamp, bytes)
}

struct PreviousHost {
    original: PathBuf,
    original_stamp: FileStamp,
    private_copy: PathBuf,
    private_stamp: FileStamp,
}
impl PreviousHost {
    fn pin(network: &Network) -> Self {
        let original: PathBuf = std::env::var_os(PRIOR_ENV)
            .map(PathBuf::from)
            .expect("selected upgrade requires SUNRISE_EDGE_PREVIOUS_SQLITE_SOURCE_HOST");
        let (original_stamp, bytes): (FileStamp, Vec<u8>) = prior_bytes(&original, 0o755);
        let directory: PathBuf = network.fixture.directory.join("previous-release");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let private_copy: PathBuf = directory.join("sqlite_source_host");
        write_private_new(&private_copy, &bytes);
        fs::set_permissions(&private_copy, fs::Permissions::from_mode(0o555)).unwrap();
        let (private_stamp, copied): (FileStamp, Vec<u8>) = prior_bytes(&private_copy, 0o555);
        assert_eq!(copied, bytes);
        assert_ne!(
            (private_stamp.device, private_stamp.inode),
            (original_stamp.device, original_stamp.inode),
            "read-only task copy must not chmod or hardlink the retained artifact"
        );
        eprintln!("upgrade_prior source={PRIOR_SOURCE} sha256={PRIOR_SHA256} bytes={PRIOR_BYTES}");
        Self {
            original,
            original_stamp,
            private_copy,
            private_stamp,
        }
    }

    fn check(&self) {
        assert_eq!(prior_bytes(&self.original, 0o755).0, self.original_stamp);
        assert_eq!(prior_bytes(&self.private_copy, 0o555).0, self.private_stamp);
    }

    /// Exactly the original host flags, all independently valid. In particular
    /// an unknown anchor flag cannot masquerade as incompatible-storage refusal.
    fn command(&self, network: &Network, index: usize, peer: &DirectPeer) -> Command {
        let mut command: Command = Command::new(&self.private_copy);
        command
            .args(network.host_root_pins(index))
            .arg("--signing-key-file")
            .arg(&network.signing_keys[index])
            .args([
                "--created-checkpoint",
                "10",
                "--timeout-seconds",
                "30",
                "--max-concurrent",
                "4",
                "--confirm-offline-fence-advance",
                "--listen",
            ])
            .arg(peer.address.to_string())
            .arg("--tls-cert-der-file")
            .arg(&peer.cert_file)
            .arg("--tls-key-pkcs8-der-file")
            .arg(&peer.key_file)
            .stderr(Stdio::piped());
        command
    }

    fn start(&self, network: &Network, peers: &mut [DirectPeer]) -> Vec<Host> {
        assert!(network.independent_anchors.is_none());
        peers
            .iter_mut()
            .enumerate()
            .map(|(index, peer): (usize, &mut DirectPeer)| {
                self.check();
                let command: Command = self.command(network, index, peer);
                let cap: NonZeroUsize =
                    compiled_source_host_process::compiled_host_startup_line_limit(
                        network.fixture.context.chain_id().as_str(),
                    );
                let (guard, line): (ChildGuard, String) =
                    spawn_bounded_status_line(command, PROCESS_DEADLINE, cap);
                assert!(line.contains("complete=true mode=serving"), "{line}");
                assert_eq!(field(&line, "writer_generation="), "2");
                let address: SocketAddr = field(&line, "listen=").parse().unwrap();
                assert_ne!(address.port(), 0);
                if peer.address.port() != 0 {
                    assert_eq!(address, peer.address);
                }
                peer.address = address;
                self.check();
                Host { guard, address }
            })
            .collect()
    }
}

/// A separate test-inserted historical object, never a paid Coin or claimed
/// quorum effect. Literal identity/owner/data follow the existing positive-body
/// storage fixture; its digest uses this actual authored chain/protocol context.
struct BodyOracle {
    object: Object,
    bytes: Vec<u8>,
    digest: Digest32,
    version: DurableObjectVersionRecord,
    head: DurableObjectHead,
    receipt: DurableRequestReceipt,
}
impl BodyOracle {
    fn install(network: &Network) -> Self {
        let object: Object = Object {
            id: ObjectId::new([61; 32]),
            version: 1,
            owner: Owner::Address(Address::new([62; 32])),
            type_hash: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [63; 32]),
            schema_version: 1,
            data: vec![64; 70 * 1024],
        };
        let bytes: Vec<u8> = encode_object(&object).unwrap();
        assert!(bytes.len() > 64 * 1024 && bytes.len() <= 80 * 1024);
        assert_eq!(objects::decode_object(&bytes).unwrap(), object);
        let digest: Digest32 = network
            .fixture
            .resolver
            .hash_for_purpose(network.fixture.context.epoch(), HashPurpose::Object, &bytes)
            .unwrap();
        let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
            object.id,
            DurableObjectVersion::FIRST,
            digest,
            object.schema_version,
            DurableObjectProvenance::new(
                network.fixture.context.chain_id().clone(),
                network.fixture.context.protocol_version(),
            ),
            7,
            digest,
        );
        let head: DurableObjectHead = DurableObjectHead::Current {
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(object.owner.clone())
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        let request: RequestId = RequestId::new([81; 32]).unwrap();
        let event: Digest32 = network
            .fixture
            .resolver
            .hash_for_purpose(
                network.fixture.context.epoch(),
                HashPurpose::NodeEvent,
                &bytes,
            )
            .unwrap();
        let response: NodeResponse =
            NodeResponse::new(request, NodeResponseStatus::Accepted, Some(bytes.clone())).unwrap();
        let record: NodeDedupRecord = NodeDedupRecord::new(request, event, vec![response]).unwrap();
        let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
            DurableRequestId::new([81; 32]).unwrap(),
            event,
            record.encode().unwrap(),
        )
        .unwrap();
        for index in 0..VALIDATORS {
            let store: SqliteDurableStore = open_store(network, index);
            let blobs: SqliteBlobStore =
                SqliteBlobStore::open_existing_writable(network.blob_db(index)).unwrap();
            blobs.put_blob(digest, bytes.clone()).unwrap();
            let changes: DurableObjectChanges = DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    object.id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    object.id,
                    DurableObjectMutation::Create {
                        version: version.clone(),
                        owner_projection: DurableObjectOwnerProjection::from_owner(
                            object.owner.clone(),
                        )
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
            )
            .unwrap();
            let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
                network.domain,
                None,
                changes,
                receipt.clone(),
                None,
            )
            .unwrap();
            assert_eq!(
                store.commit_invocation(
                    &operation(store.writer_fence().unwrap(), 0x71),
                    transaction
                ),
                DurableCommitOutcome::Committed
            );
        }
        Self {
            object,
            bytes,
            digest,
            version,
            head,
            receipt,
        }
    }

    fn verify(&self, network: &Network, peers: &[DirectPeer]) {
        use runtime::portable::DurableCollection;
        for (index, peer) in peers.iter().enumerate() {
            let store: SqliteDurableStore = open_store(network, index);
            let context: DurableOperationContext = operation(store.writer_fence().unwrap(), 0x72);
            assert_eq!(
                store
                    .get_object_head(&context, network.domain, self.object.id)
                    .unwrap(),
                self.head
            );
            assert_eq!(
                store
                    .get_object_version(
                        &context,
                        network.domain,
                        self.object.id,
                        DurableObjectVersion::FIRST
                    )
                    .unwrap(),
                Some(self.version.clone())
            );
            assert_eq!(
                store
                    .get_request_receipt(&context, network.domain, self.receipt.request_id())
                    .unwrap(),
                Some(self.receipt.clone())
            );
            drop(store);
            let captured: SourceBusinessSnapshot = snapshot(network, index);
            assert_eq!(
                captured.referenced_blobs.get(&self.digest),
                Some(&self.bytes)
            );
            let collections: BTreeSet<DurableCollection> = captured
                .records
                .iter()
                .map(|record| record.descriptor.key().collection())
                .collect();
            assert_eq!(
                collections,
                BTreeSet::from([
                    DurableCollection::State,
                    DurableCollection::Receipts,
                    DurableCollection::ObjectHeads,
                    DurableCollection::ObjectVersions
                ])
            );
            assert_eq!(
                peer.client().query_object(self.object.id).unwrap(),
                HttpObjectQueryResult::CurrentBlobReference {
                    object_id: self.object.id,
                    head_revision: ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest: self.digest,
                    blob_digest: self.digest
                }
            );
        }
    }
}

fn assert_structural_version_five(network: &Network) {
    for index in 0..VALIDATORS {
        let connection: rusqlite::Connection = rusqlite::Connection::open_with_flags(
            network.state_db(index),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            version, 5,
            "authority profile enrollment does not change structural version"
        );
        connection.close().unwrap();
    }
}

/// Closed stopped interval only. Capture optional WAL/SHM/journal presence as
/// well as every source/body/authority/lease byte; no sidecar is removed here.
fn stopped_files(network: &Network) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    assert_no_parent_sqlite_handles(network);
    let anchors: &IndependentAnchors = network.independent_anchors.as_ref().unwrap();
    let mut result: BTreeMap<PathBuf, Option<Vec<u8>>> = BTreeMap::new();
    let mut total: u64 = 0;
    for index in 0..VALIDATORS {
        for main in [
            network.state_db(index),
            network.blob_db(index),
            anchors.paths[index].clone(),
        ] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let mut name: OsString = main.as_os_str().to_owned();
                name.push(suffix);
                let path: PathBuf = name.into();
                let bytes: Option<Vec<u8>> = match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                        total = total.checked_add(metadata.len()).unwrap();
                        assert!(
                            total <= MAX_STOPPED_BYTES,
                            "finite stopped bytes before copy"
                        );
                        let mut file: fs::File = fs::File::open(&path).unwrap();
                        let mut bytes: Vec<u8> = Vec::new();
                        Read::by_ref(&mut file)
                            .take(metadata.len().checked_add(1).unwrap())
                            .read_to_end(&mut bytes)
                            .unwrap();
                        assert_eq!(bytes.len() as u64, metadata.len());
                        Some(bytes)
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound && !suffix.is_empty() => None,
                    Err(error) => panic!("stopped inventory {}: {error}", path.display()),
                };
                assert!(result.insert(path, bytes).is_none());
            }
        }
        let mut name: OsString = anchors.paths[index].as_os_str().to_owned();
        name.push(".lease");
        let path: PathBuf = name.into();
        let metadata: fs::Metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.len(), 0);
        let mut lease_bytes: Vec<u8> = Vec::new();
        fs::File::open(&path)
            .unwrap()
            .take(1)
            .read_to_end(&mut lease_bytes)
            .unwrap();
        assert!(lease_bytes.is_empty());
        assert!(result.insert(path, Some(Vec::new())).is_none());
    }
    assert_eq!(result.len(), VALIDATORS * 13);
    result
}

fn incompatible_previous_refuses(previous: &PreviousHost, network: &Network, peers: &[DirectPeer]) {
    assert_structural_version_five(network);
    let rows: Vec<sqlite_durable_image::Image> = sqlite_durable_images(network);
    let anchors: Vec<sqlite_durable_image::AnchorImage> =
        network.independent_anchors.as_ref().unwrap().images();
    // Finish all logical observations before physical fingerprinting. A real
    // current SQLite owner closes any observer-created source sidecars; its
    // independently retained acknowledgement must remain exactly unchanged.
    let authority: &IndependentAnchors = network.independent_anchors.as_ref().unwrap();
    for index in 0..VALIDATORS {
        assert_eq!(
            authority.checkpoint(network, index),
            authority.enrolled[index]
        );
    }
    let bytes: BTreeMap<PathBuf, Option<Vec<u8>>> = stopped_files(network);
    for (index, peer) in peers.iter().enumerate() {
        previous.check();
        let available: TcpListener = TcpListener::bind(peer.address).unwrap();
        drop(available);
        let output: Output =
            spawn_strict_bounded_output(previous.command(network, index, peer), PROCESS_DEADLINE);
        assert_eq!(
            output.status.code(),
            Some(1),
            "ordinary incompatible prior writer refusal"
        );
        assert!(
            output.stdout.is_empty(),
            "prior writer cannot advertise READY or serving"
        );
        assert_eq!(
            output.stderr,
            b"sqlite-source-host: SQLite structured schema identity is unsupported\n"
        );
        let available: TcpListener = TcpListener::bind(peer.address)
            .expect("schema refusal leaves exact prior endpoint available");
        drop(available);
        previous.check();
        assert_eq!(
            stopped_files(network),
            bytes,
            "refused rollback preserves all stopped bytes/sidecars before any SQL observer"
        );
    }
    // These new read-only SQLite observations are outside the byte interval.
    // No ordinary sidecar unlink, repair, reset or downgraded schema is used.
    assert_eq!(
        sqlite_durable_images(network),
        rows,
        "refused rollback claims no fence and changes no row"
    );
    assert_eq!(authority.images(), anchors);
    assert_structural_version_five(network);
    assert_no_parent_sqlite_handles(network);
}

pub(super) fn exercise() {
    let mut network: Network = author_inspect_and_prepare();
    fs::set_permissions(
        &network.fixture.directory,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let previous: PreviousHost = PreviousHost::pin(&network);
    let body: BodyOracle = BodyOracle::install(&network);
    let mut peers: Vec<DirectPeer> = direct_peers(&network);
    let mut hosts: Vec<Host> = previous.start(&network, &mut peers);
    assert_eq!(hosts.len(), VALIDATORS);
    let endpoints: Vec<SocketAddr> = peers.iter().map(|peer: &DirectPeer| peer.address).collect();
    assert_eq!(
        endpoints
            .iter()
            .copied()
            .collect::<BTreeSet<SocketAddr>>()
            .len(),
        VALIDATORS
    );
    let lines: Vec<String> = direct_lines(&network, &peers);
    let config: PathBuf = write_config(
        &network.tls_dir.join("previous-release-network.conf"),
        &lines,
    );
    let contexts: Vec<(Vec<u8>, Vec<u8>)> = direct_contexts(&peers);
    let certificates: Vec<Vec<u8>> = peers.iter().map(DirectPeer::received).collect();
    let inputs: Vec<(PathBuf, Vec<u8>)> = std::iter::once(network.genesis.clone())
        .chain(network.signing_keys.iter().cloned())
        .chain(std::iter::once(network.owner_seed.clone()))
        .chain(peers.iter().map(|peer: &DirectPeer| peer.ca_file.clone()))
        .chain(peers.iter().map(|peer: &DirectPeer| peer.cert_file.clone()))
        .chain(peers.iter().map(|peer: &DirectPeer| peer.key_file.clone()))
        .chain(std::iter::once(config.clone()))
        .map(|path: PathBuf| {
            let length: u64 = fs::metadata(&path).unwrap().len();
            assert!(length <= 1024 * 1024, "fixture input admitted before copy");
            let mut bytes: Vec<u8> = Vec::new();
            fs::File::open(&path)
                .unwrap()
                .take(length.checked_add(1).unwrap())
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes.len() as u64, length);
            (path, bytes)
        })
        .collect();
    assert_eq!(inputs.len(), 19);
    let sender: Address = Address::new(network.fixture.owner);
    let request: RequestId = RequestId::new(TRANSFER_REQUEST).unwrap();
    let initial: Observation = observe(
        &peers,
        &[ObjectId::new(APP_COIN), ObjectId::new(FEE_COIN)],
        request,
        sender,
    );
    let nonce: u64 = verify_initial(&network, &initial, sender);
    let first: Outputs = Outputs::new(&network.artifacts_dir, "previous-release-paid");
    let output: Output = run_cli(transfer_args(
        &network,
        &config,
        peers[0].address,
        &network.owner_seed,
        TRANSFER_REQUEST,
        nonce,
        &first,
    ));
    assert!(
        output.status.success(),
        "old-host paid CLI: {} {}",
        lossy(&output.stdout),
        lossy(&output.stderr)
    );
    assert_eq!(
        lossy(&output.stdout)
            .matches("status=received paid_status=Success")
            .count(),
        VALIDATORS
    );
    let saved: Saved = Saved::read(&first);
    let committed: Committed = verify_saved_artifacts(&network, &saved, nonce);
    let ids: Vec<ObjectId> = observed_ids(&committed.result);
    let committed_view: Observation = observe(&peers, &ids, request, sender);
    verify_committed_state(&network, &committed, &saved, &committed_view);
    body.verify(&network, &peers);
    let before: Vec<SourceBusinessSnapshot> = snapshots(&network);
    let raw_before: Vec<sqlite_durable_image::Image> = sqlite_durable_images(&network);
    assert_structural_version_five(&network);
    assert_no_parent_sqlite_handles(&network);
    let prior_pids: BTreeSet<u32> = hosts
        .iter_mut()
        .enumerate()
        .map(|(index, host): (usize, &mut Host)| {
            assert_eq!(host.address, endpoints[index]);
            assert!(host.guard.try_wait().unwrap().is_none());
            host.guard.child_mut().id()
        })
        .collect();
    assert_eq!(prior_pids.len(), VALIDATORS);
    for host in hosts {
        let summary: Vec<u8> = host.guard.stop_orderly_terminate(PROCESS_DEADLINE);
        assert_native_termination_summary(&summary, "sigterm");
    }
    for pid in &prior_pids {
        assert_absent(
            &Path::new("/proc").join(pid.to_string()),
            "old host actually reaped",
        );
    }
    assert_no_parent_sqlite_handles(&network);
    previous.check();
    assert_eq!(sqlite_durable_images(&network), raw_before);
    assert_unchanged(
        &before,
        &snapshots(&network),
        "orderly stopped prior release",
    );

    // Independent observations are retained by enroll outside every source
    // tree before they are passed back as exact explicit expected-root flags.
    network.independent_anchors = Some(IndependentAnchors::enroll(&network));
    let enrolled: Vec<sqlite_durable_image::Image> = sqlite_durable_images(&network);
    sqlite_durable_image::assert_only_anchor_identity_changed(&raw_before, &enrolled);
    assert_structural_version_five(&network);
    assert_unchanged(
        &before,
        &snapshots(&network),
        "profile enrollment preserves complete business history",
    );
    assert_no_parent_sqlite_handles(&network);
    incompatible_previous_refuses(&previous, &network, &peers);

    let mut hosts: Vec<Host> = start_direct_hosts(&network, &mut peers, 3);
    let current_pids: BTreeSet<u32> = hosts
        .iter_mut()
        .map(|host: &mut Host| {
            assert!(host.guard.try_wait().unwrap().is_none());
            host.guard.child_mut().id()
        })
        .collect();
    assert_eq!(current_pids.len(), VALIDATORS);
    assert!(current_pids.is_disjoint(&prior_pids));
    assert_eq!(hosts.len(), VALIDATORS);
    for (index, host) in hosts.iter().enumerate() {
        assert_eq!(host.address, endpoints[index]);
    }
    assert_eq!(direct_lines(&network, &peers), lines);
    assert_eq!(direct_contexts(&peers), contexts);
    assert_eq!(
        peers
            .iter()
            .map(DirectPeer::received)
            .collect::<Vec<Vec<u8>>>(),
        certificates
    );
    let reopened: Vec<SourceBusinessSnapshot> = snapshots(&network);
    assert_reopened(&before, &reopened, 2, 3);
    sqlite_durable_image::assert_only_fence_changed(
        &enrolled,
        &sqlite_durable_images(&network),
        2,
        3,
    );
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &reopened,
        &committed_view,
        "current upgraded before replay",
    );
    body.verify(&network, &peers);
    let anchor_before: Vec<sqlite_durable_image::AnchorImage> =
        network.independent_anchors.as_ref().unwrap().images();
    let replay: Outputs = Outputs::new(&network.artifacts_dir, "upgraded-prior-replay");
    let output: Output = run_cli(replay_args(
        &network,
        &config,
        &first.intent,
        Some(&first),
        &replay,
    ));
    assert_exact_replay(
        &output,
        &replay,
        &saved,
        "prior-release receipt after upgrade",
    );
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &reopened,
        &committed_view,
        "current upgraded after replay",
    );
    sqlite_durable_image::assert_only_fence_changed(
        &enrolled,
        &sqlite_durable_images(&network),
        2,
        3,
    );
    assert_eq!(
        network.independent_anchors.as_ref().unwrap().images(),
        anchor_before
    );
    assert_fresh_paid_transfer_after_recovery(
        RecoveryTransfer {
            network: &network,
            peers: &peers,
            config: &config,
            first: &first,
            saved: &saved,
            committed: &committed,
            committed_view: &committed_view,
            nonce,
        },
        [0x0e; 32],
        "upgraded-fresh-paid",
        true,
    );
    assert_ne!(
        network.independent_anchors.as_ref().unwrap().images(),
        anchor_before
    );
    body.verify(&network, &peers);
    let final_rows: Vec<sqlite_durable_image::Image> = sqlite_durable_images(&network);
    let final_business: Vec<SourceBusinessSnapshot> = snapshots(&network);
    let final_anchors: Vec<sqlite_durable_image::AnchorImage> =
        network.independent_anchors.as_ref().unwrap().images();
    for host in hosts {
        host.guard.stop_orderly(PROCESS_DEADLINE);
    }
    for pid in &current_pids {
        assert_absent(
            &Path::new("/proc").join(pid.to_string()),
            "current host actually reaped",
        );
    }
    assert_no_parent_sqlite_handles(&network);
    assert_eq!(sqlite_durable_images(&network), final_rows);
    assert_unchanged(
        &final_business,
        &snapshots(&network),
        "upgraded ordinary tail stop",
    );
    assert_eq!(
        network.independent_anchors.as_ref().unwrap().images(),
        final_anchors
    );
    assert_structural_version_five(&network);
    assert_eq!(Saved::read(&first), saved);
    for (path, expected) in inputs {
        assert_eq!(fs::metadata(&path).unwrap().len(), expected.len() as u64);
        let mut actual: Vec<u8> = Vec::new();
        fs::File::open(&path)
            .unwrap()
            .take((expected.len() as u64).checked_add(1).unwrap())
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, expected, "unchanged input {}", path.display());
    }
    previous.check();
}
