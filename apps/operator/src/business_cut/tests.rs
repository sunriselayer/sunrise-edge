//! Transfer-file bounds only. These tests do not construct a verified cut.
use super::*;
use crate::business_snapshot::capture_source_business_snapshot;
use canonical_encoding::{CanonicalStruct, encode_digest32};
use hashing::HashSuiteResolver;
use node_core::business_reconstruction::cut::{
    BusinessCutChunk, BusinessCutComponentDescriptor, decode_business_cut_descriptor,
    encode_business_cut_descriptor,
};
use protocol_types::{ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[path = "../../tests/support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "../../tests/support/genesis_fixture.rs"]
mod genesis_fixture;
#[path = "../../tests/business_cut/fixture.rs"]
// The same genuine source fixture has integration-only executable/history
// helpers. This unit target deliberately uses only its source construction.
#[allow(dead_code)]
mod source_fixture;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let sequence: u64 = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf =
            std::env::temp_dir().join(format!("cut-file-bounds-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

fn digest() -> Digest32 {
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        ChainId::new("cut-file-bounds").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::NodeEvent,
            b"test-file-integrity-only",
        )
        .unwrap()
}

fn descriptor(length: u64) -> BusinessCutComponentDescriptor {
    let mut metadata: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
    metadata.field_u16(1, 1).unwrap();
    metadata.field_u16(2, 1).unwrap();
    BusinessCutComponentDescriptor {
        collection: BusinessCutCollection::State,
        key: b"file-bounds".to_vec(),
        metadata: metadata.finish().unwrap(),
        length,
        digest: digest(),
    }
}

#[test]
fn maximum_payload_chunk_keeps_descriptor_overhead_and_refuses_truncation() {
    let directory: Directory = Directory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    let chunk: BusinessCutChunk = BusinessCutChunk {
        cut_digest: digest(),
        package_digest: digest(),
        descriptor: descriptor(MAX_BUSINESS_CUT_CHUNK_BYTES as u64),
        offset: 0,
        total_length: MAX_BUSINESS_CUT_CHUNK_BYTES as u64,
        bytes: vec![0x71; MAX_BUSINESS_CUT_CHUNK_BYTES],
    };
    let encoded: Vec<u8> = encode_business_cut_chunk(&chunk).unwrap();
    assert!(encoded.len() > MAX_BUSINESS_CUT_CHUNK_BYTES);
    assert!(encoded.len() <= MAX_SAVED_CHUNK_BYTES);
    archive.publish("legal.bin", &encoded).unwrap();
    assert_eq!(
        decode_business_cut_chunk(&archive.read("legal.bin", MAX_SAVED_CHUNK_BYTES).unwrap())
            .unwrap(),
        chunk
    );
    assert!(
        archive
            .read("legal.bin", MAX_BUSINESS_CUT_CHUNK_BYTES)
            .is_err()
    );
    assert!(decode_business_cut_chunk(&encoded[..encoded.len() - 1]).is_err());
    let mut corrupted: Vec<u8> = encoded.clone();
    corrupted[0] ^= 1;
    assert!(decode_business_cut_chunk(&corrupted).is_err());
    let mut oversized: BusinessCutChunk = chunk;
    oversized.bytes.push(0);
    assert!(encode_business_cut_chunk(&oversized).is_err());
}

#[test]
fn descriptor_body_length_is_checked_before_saved_body_allocation() {
    let valid: BusinessCutComponentDescriptor = descriptor(1);
    let mut raw: CanonicalStruct = CanonicalStruct::new(0x64B3, 1);
    raw.field_u16(1, BusinessCutCollection::State as u16)
        .unwrap();
    raw.field_bytes(2, valid.key.clone()).unwrap();
    raw.field_bytes(3, valid.metadata.clone()).unwrap();
    raw.field_u64(4, u64::MAX).unwrap();
    raw.field_bytes(5, encode_digest32(&valid.digest).unwrap())
        .unwrap();
    assert!(decode_business_cut_descriptor(&raw.finish().unwrap()).is_err());
    assert!(encode_business_cut_descriptor(&descriptor(u64::MAX)).is_err());
}

#[test]
fn invocation_bounds_and_exact_local_token_frames_fail_closed() {
    for (page, chunk, new_work) in [
        (0, 1, 1),
        (129, 1, 1),
        (1, 0, 1),
        (1, 1_048_577, 1),
        (1, 1, 0),
        (1, 1, 4097),
    ] {
        assert!(CutArchiveLimits::new(page, chunk, new_work).is_err());
    }
    let maximum: CutArchiveLimits = CutArchiveLimits::new(128, 1_048_576, 4096).unwrap();
    assert!(CutArchiveLimits::from_transfer_bytes(&maximum.transfer_bytes().unwrap()).is_ok());
    let token: PortableSnapshotToken = PortableSnapshotToken::new(
        b"exact-source".to_vec(),
        AtomicityDomainId::new([0x81; 32]).unwrap(),
        WriterFenceGeneration::new(2).unwrap(),
        91,
    )
    .unwrap();
    let bytes: Vec<u8> = source_bytes(&token).unwrap();
    assert_eq!(read_source_token(&bytes).unwrap(), token);
    assert!(read_source_token(&bytes[..bytes.len() - 1]).is_err());
    let mut extra: Vec<u8> = bytes;
    extra.push(0);
    assert!(read_source_token(&extra).is_err());
}

#[test]
fn real_source_fence_change_after_payloads_refuses_completion_marker() {
    let fixture: source_fixture::Fixture = source_fixture::Fixture::new();
    fixture.freeze_and_complete();
    let (identity, history) = fixture.history();
    let cut: VerifiedBusinessCut = derive_source_business_cut(
        fixture.plan(&identity, fixture.operation),
        &fixture.stores[0],
        &fixture.blobs,
        &history,
    )
    .unwrap();
    let output: Directory = Directory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&output.0).unwrap();
    let token: PortableSnapshotToken = cut.source_token().unwrap().clone();
    let result = publish_source_cut(
        &cut,
        &fixture.network.resolver,
        &archive,
        CutArchiveLimits::new(4, 65536, 4096).unwrap(),
        || {
            // This callback is reached only after every expected payload was saved.
            let names = archive.names().unwrap();
            assert!(names.iter().any(|name| name.starts_with("page-07-")));
            assert!(names.iter().any(|name| name.starts_with("chunk-07-")));
            assert!(!names.contains("complete"));
            fixture.stores[0]
                .advance_writer_fence(
                    WriterFenceGeneration::new(1).unwrap(),
                    WriterFenceGeneration::new(2).unwrap(),
                )
                .unwrap();
            fixture.stores[0].check_portable_outbox_empty_at(
                &fixture.operation,
                fixture.network.domain,
                &token,
            )?;
            Ok(())
        },
    );
    assert!(matches!(result, Err(CutArchiveError::Source(_))));
    assert!(!archive.contains("complete").unwrap());
    assert!(
        verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive).is_err()
    );
}

/// Ordinary test inventory entry, intentionally a no-op without explicit
/// subprocess role. No ignored selector or production failpoint is added.
#[test]
fn subprocess_cut_export_worker() {
    if std::env::var("SUNRISE_CUT_TEST_ROLE").as_deref() != Ok("cut-export-worker") {
        return;
    }
    let arguments_file: PathBuf = std::env::var_os("SUNRISE_CUT_TEST_ARGUMENTS")
        .unwrap()
        .into();
    assert!(std::fs::metadata(&arguments_file).unwrap().len() <= 16 * 1024);
    let arguments: String = std::fs::read_to_string(arguments_file).unwrap();
    let arguments: Vec<std::ffi::OsString> =
        arguments.lines().map(std::ffi::OsString::from).collect();
    assert!(super::run(arguments).is_ok());
    panic!("armed child must stop at a publication checkpoint before completion");
}

#[cfg(unix)]
#[test]
fn genuine_cut_export_resumes_after_process_kills_at_all_publication_boundaries() {
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    let fixture: source_fixture::Fixture = source_fixture::Fixture::new();
    fixture.freeze_and_complete();
    let (identity, history) = fixture.history();
    let source_before = fixture.snapshot();
    let history_root: PathBuf = fixture.directory.0.join("crash-test-history");
    fixture.write_history(&history_root, &identity, &history);
    let genesis_file: PathBuf = fixture.directory.0.join("crash-test-genesis.bin");
    std::fs::write(&genesis_file, &fixture.network.manifest_bytes).unwrap();
    let expected: VerifiedBusinessCut = derive_source_business_cut(
        fixture.plan(&identity, fixture.operation),
        &fixture.stores[0],
        &fixture.blobs,
        &history,
    )
    .unwrap();
    let hex = |bytes: &[u8]| -> String {
        bytes
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect()
    };
    struct RunningChild(Child);
    impl Drop for RunningChild {
        fn drop(&mut self) {
            let _ignored = self.0.kill();
            let _ignored = self.0.wait();
        }
    }
    for point in [
        "after-stage-sync",
        "after-link",
        "before-cleanup",
        "after-cleanup",
    ] {
        let container: Directory = Directory::new();
        let root: PathBuf = container.0.join("archive");
        std::fs::create_dir(&root).unwrap();
        let signal: PathBuf = container.0.join("checkpoint-reached");
        let arguments_file: PathBuf = container.0.join("arguments.txt");
        let arguments: Vec<OsString> = [
            "export-sqlite".to_string(),
            "--chain-id".into(),
            fixture.network.chain_id.as_str().into(),
            "--protocol-version".into(),
            fixture.network.protocol_version.get().to_string(),
            "--epoch".into(),
            fixture.network.epoch.get().to_string(),
            "--domain".into(),
            hex(fixture.network.domain.as_bytes()),
            "--suite".into(),
            "0:1:1:1:1:1:1:1".into(),
            "--genesis-manifest".into(),
            genesis_file.to_str().unwrap().into(),
            "--expected-genesis-digest".into(),
            hex(&fixture.network.manifest_digest),
            "--ordered-history-dir".into(),
            history_root.to_str().unwrap().into(),
            "--out-dir".into(),
            root.to_str().unwrap().into(),
            "--state-db".into(),
            fixture
                .directory
                .0
                .join("state-0.sqlite")
                .to_str()
                .unwrap()
                .into(),
            "--blob-db".into(),
            fixture
                .directory
                .0
                .join("blobs.sqlite")
                .to_str()
                .unwrap()
                .into(),
            "--validator-id".into(),
            hex(fixture.network.validators[0].validator_id.as_bytes()),
            "--page-size".into(),
            "4".into(),
            "--chunk-size".into(),
            "65536".into(),
            "--max-new-work".into(),
            "4096".into(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let argument_text: String = arguments
            .iter()
            .map(|value: &OsString| value.to_str().unwrap())
            .collect::<Vec<&str>>()
            .join("\n");
        std::fs::write(&arguments_file, argument_text).unwrap();
        let mut child: RunningChild = RunningChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "business_cut::tests::subprocess_cut_export_worker",
                    "--nocapture",
                ])
                .env("SUNRISE_CUT_TEST_ROLE", "cut-export-worker")
                .env("SUNRISE_CUT_TEST_CHECKPOINT", point)
                .env("SUNRISE_CUT_TEST_ROOT", &root)
                .env("SUNRISE_CUT_TEST_SIGNAL", &signal)
                .env("SUNRISE_CUT_TEST_ARGUMENTS", &arguments_file)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline: Instant = Instant::now() + Duration::from_secs(30);
        while !signal.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before {point}"
            );
            assert!(Instant::now() < deadline, "child did not reach {point}");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(std::fs::read_to_string(&signal).unwrap(), point);
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "actual SIGKILL required at {point}"
        );
        let staging: PathBuf = root.join(".cut-staging-v1");
        let orphans: BTreeMap<String, Vec<u8>> = std::fs::read_dir(&staging)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect();
        assert_eq!(orphans.len(), usize::from(point != "after-cleanup"));
        let archive: ImmutableArchive = ImmutableArchive::open(&root).unwrap();
        assert!(!archive.contains("complete").unwrap());
        let resumed = export_source_business_cut(
            fixture.plan(&identity, fixture.operation),
            &fixture.stores[0],
            &fixture.blobs,
            &history,
            &archive,
            CutArchiveLimits::new(4, 65536, 4096).unwrap(),
        )
        .unwrap();
        assert!(resumed.complete, "resume failed at {point}");
        assert_eq!(resumed.cut_digest, expected.cut_digest());
        assert_eq!(resumed.package_digest, expected.package_digest());
        let verified =
            verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive)
                .unwrap();
        assert_eq!(verified.cut_digest(), expected.cut_digest());
        for (name, bytes) in &orphans {
            assert_eq!(std::fs::read(staging.join(name)).unwrap(), *bytes);
        }
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), orphans.len());
        assert_eq!(fixture.snapshot(), source_before);
    }
}
