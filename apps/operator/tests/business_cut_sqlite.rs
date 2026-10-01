//! Genuine compiled operator and production library consumer acceptance.
//! Local SQLite evidence does not qualify a deployed provider or import.

#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;
mod support {
    pub use super::genesis_fixture;
}
#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "business_cut/fixture.rs"]
mod fixture;

use fixture::{Directory, Fixture, copy_files, files};
use node_core::business_reconstruction::{
    SourceBusinessSnapshot,
    cut::{decode_business_cut_chunk, encode_business_cut_chunk},
};
use node_core::ordered_economics::{OrderedHistoryHeightMaterial, OrderedHistoryIdentity};
use protocol_types::HashPurpose;
use runtime::WriterFenceGeneration;
use std::{
    num::NonZeroUsize,
    path::Path,
    process::{Command, Output},
};
use sunrise_edge_operator::{
    business_cut::{CutArchiveLimits, export_source_business_cut, verify_business_cut_archive},
    business_snapshot::capture_source_business_snapshot,
    immutable_archive::ImmutableArchive,
    source_sqlite::ExistingSqliteSource,
};

fn command(fixture: &Fixture, history: &Path, output: &Path, mode: &str) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_business_cut"));
    command.arg(mode).args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        fixture.directory.0.join("genesis.bin").to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--ordered-history-dir",
        history.to_str().unwrap(),
        "--out-dir",
        output.to_str().unwrap(),
    ]);
    if mode == "export-sqlite" {
        command.args([
            "--state-db",
            fixture.directory.0.join("state-0.sqlite").to_str().unwrap(),
            "--blob-db",
            fixture.directory.0.join("blobs.sqlite").to_str().unwrap(),
            "--validator-id",
            &hex(fixture.network.validators[0].validator_id.as_bytes()),
            "--page-size",
            "4",
            "--chunk-size",
            "65536",
            "--max-new-work",
            "4096",
        ]);
    }
    command
}
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn genuine_sqlite_cut_immutable_resume_reopen_offline_verify_and_fence_refusal() {
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        fixture.history();
    let before: SourceBusinessSnapshot = fixture.snapshot();
    let output: Directory = Directory::new("library-resume");
    let archive: ImmutableArchive = ImmutableArchive::open(&output.0).unwrap();
    let first = export_source_business_cut(
        fixture.plan(&identity, fixture.operation),
        &fixture.stores[0],
        &fixture.blobs,
        &ordered,
        &archive,
        CutArchiveLimits::new(4, 65536, 1).unwrap(),
    )
    .unwrap();
    assert!(!first.complete);
    assert_eq!(first.newly_saved_files, 1);
    assert_eq!(
        archive.names().unwrap(),
        ["source-token.bin".to_string()].into()
    );
    assert!(
        verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive).is_err()
    );
    let second = export_source_business_cut(
        fixture.plan(&identity, fixture.operation),
        &fixture.stores[0],
        &fixture.blobs,
        &ordered,
        &archive,
        CutArchiveLimits::new(4, 65536, 2).unwrap(),
    )
    .unwrap();
    assert!(!second.complete);
    assert_eq!(second.newly_saved_files, 2);
    assert_eq!(second.cut_digest, first.cut_digest);
    assert_eq!(second.package_digest, first.package_digest);
    let resumed = export_source_business_cut(
        fixture.plan(&identity, fixture.operation),
        &fixture.stores[0],
        &fixture.blobs,
        &ordered,
        &archive,
        CutArchiveLimits::new(4, 65536, 4096).unwrap(),
    )
    .unwrap();
    assert!(resumed.complete);
    assert!(resumed.newly_saved_files <= 4096);
    let complete_files = files(&output.0);
    let verified =
        verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive).unwrap();
    assert_eq!(verified.cut_digest(), first.cut_digest);
    assert_eq!(verified.package_digest(), first.package_digest);
    assert!(verified.source_token().is_none());
    let replay = export_source_business_cut(
        fixture.plan(&identity, fixture.operation),
        &fixture.stores[0],
        &fixture.blobs,
        &ordered,
        &archive,
        CutArchiveLimits::new(4, 65536, 1).unwrap(),
    )
    .unwrap();
    assert!(replay.complete);
    assert_eq!(replay.newly_saved_files, 0);
    assert_eq!(files(&output.0), complete_files);
    assert_eq!(fixture.snapshot(), before);
    // Close all writer handles; composition uses existing files and current
    // fence only. No copied source authority or fixture reseeding occurs.
    fixture.stores.clear();
    let source: ExistingSqliteSource = ExistingSqliteSource::open(
        &fixture.directory.0.join("state-0.sqlite"),
        &fixture.directory.0.join("blobs.sqlite"),
        fixture.network.chain_id.clone(),
        fixture.network.validators[0].validator_id,
        fixture.network.domain,
        300,
    )
    .unwrap();
    let reopened: SourceBusinessSnapshot = capture_source_business_snapshot(
        &source.durable,
        &source.blobs,
        &source.operation,
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    assert_eq!(reopened, before);
    let reopened_replay = export_source_business_cut(
        fixture.plan(&identity, source.operation),
        &source.durable,
        &source.blobs,
        &ordered,
        &archive,
        CutArchiveLimits::new(4, 65536, 1).unwrap(),
    )
    .unwrap();
    assert!(reopened_replay.complete);
    assert_eq!(reopened_replay.newly_saved_files, 0);
    // A partial observation must not silently move onto a newer writer.
    let partial: Directory = Directory::new("stale-continuation");
    let partial_archive: ImmutableArchive = ImmutableArchive::open(&partial.0).unwrap();
    export_source_business_cut(
        fixture.plan(&identity, source.operation),
        &source.durable,
        &source.blobs,
        &ordered,
        &partial_archive,
        CutArchiveLimits::new(4, 65536, 1).unwrap(),
    )
    .unwrap();
    let partial_before = files(&partial.0);
    let first_fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let second_fence: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    source
        .durable
        .advance_writer_fence(first_fence, second_fence)
        .unwrap();
    assert!(
        export_source_business_cut(
            fixture.plan(&identity, source.operation),
            &source.durable,
            &source.blobs,
            &ordered,
            &partial_archive,
            CutArchiveLimits::new(4, 65536, 4096).unwrap()
        )
        .is_err()
    );
    drop(source);
    let current: ExistingSqliteSource = ExistingSqliteSource::open(
        &fixture.directory.0.join("state-0.sqlite"),
        &fixture.directory.0.join("blobs.sqlite"),
        fixture.network.chain_id.clone(),
        fixture.network.validators[0].validator_id,
        fixture.network.domain,
        300,
    )
    .unwrap();
    assert!(
        export_source_business_cut(
            fixture.plan(&identity, current.operation),
            &current.durable,
            &current.blobs,
            &ordered,
            &partial_archive,
            CutArchiveLimits::new(4, 65536, 4096).unwrap()
        )
        .is_err()
    );
    assert_eq!(files(&partial.0), partial_before);
    let fresh: Directory = Directory::new("new-observation");
    let fresh_archive: ImmutableArchive = ImmutableArchive::open(&fresh.0).unwrap();
    let fresh_progress = export_source_business_cut(
        fixture.plan(&identity, current.operation),
        &current.durable,
        &current.blobs,
        &ordered,
        &fresh_archive,
        CutArchiveLimits::new(4, 65536, 4096).unwrap(),
    )
    .unwrap();
    assert!(fresh_progress.complete);
    assert_eq!(fresh_progress.cut_digest, first.cut_digest);
    assert_eq!(fresh_progress.package_digest, first.package_digest);
    assert_ne!(
        fresh_archive.read("source-token.bin", 4096).unwrap(),
        archive.read("source-token.bin", 4096).unwrap()
    );
    // Independently saved verification of the old complete observation remains
    // valid: a later writer does not turn local tokens into semantic roots.
    assert_eq!(
        verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive)
            .unwrap()
            .cut_digest(),
        first.cut_digest
    );
}

#[test]
fn compiled_cut_export_and_database_free_verifier_refuse_corrupted_or_surplus_material() {
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    let (identity, ordered) = fixture.history();
    let before: SourceBusinessSnapshot = fixture.snapshot();
    let history = fixture.directory.0.join("ordered-history");
    fixture.write_history(&history, &identity, &ordered);
    std::fs::write(
        fixture.directory.0.join("genesis.bin"),
        &fixture.network.manifest_bytes,
    )
    .unwrap();
    let output: Directory = Directory::new("compiled-cut");
    assert!(
        success(
            command(&fixture, &history, &output.0, "export-sqlite")
                .output()
                .unwrap()
        )
        .contains("business_cut=complete")
    );
    assert!(
        success(
            command(&fixture, &history, &output.0, "verify-saved")
                .output()
                .unwrap()
        )
        .contains("business_cut=independently-verified")
    );
    assert_eq!(fixture.snapshot(), before);
    let saved = files(&output.0);
    let chunks: Vec<String> = saved
        .keys()
        .filter(|name| name.starts_with("chunk-"))
        .cloned()
        .collect();
    let pages: Vec<String> = saved
        .keys()
        .filter(|name| name.starts_with("page-01-"))
        .cloned()
        .collect();
    assert!(chunks.len() > 1 && pages.len() > 1);
    for scenario in 0..6 {
        let corrupted: Directory = Directory::new("corrupt-cut");
        copy_files(&output.0, &corrupted.0);
        match scenario {
            0 => {
                std::fs::remove_file(corrupted.0.join(&chunks[0])).unwrap();
            }
            1 => {
                let bytes = &saved[&chunks[0]];
                std::fs::write(corrupted.0.join(&chunks[0]), &bytes[..bytes.len() - 1]).unwrap();
            }
            2 => {
                std::fs::write(corrupted.0.join("foreign.bin"), b"not in the exact package")
                    .unwrap();
            }
            3 => {
                std::fs::write(corrupted.0.join(&chunks[0]), &saved[&chunks[1]]).unwrap();
                std::fs::write(corrupted.0.join(&chunks[1]), &saved[&chunks[0]]).unwrap();
            }
            4 => {
                std::fs::write(corrupted.0.join(&pages[0]), &saved[&pages[1]]).unwrap();
                std::fs::write(corrupted.0.join(&pages[1]), &saved[&pages[0]]).unwrap();
            }
            _ => {
                let mut chunk = decode_business_cut_chunk(&saved[&chunks[0]]).unwrap();
                chunk.cut_digest = fixture
                    .network
                    .resolver
                    .hash_for_purpose(
                        fixture.network.epoch,
                        HashPurpose::NodeEvent,
                        b"foreign-cut",
                    )
                    .unwrap();
                std::fs::write(
                    corrupted.0.join(&chunks[0]),
                    encode_business_cut_chunk(&chunk).unwrap(),
                )
                .unwrap();
            }
        }
        let corrupt_before = files(&corrupted.0);
        assert!(
            !command(&fixture, &history, &corrupted.0, "verify-saved")
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(
            !command(&fixture, &history, &corrupted.0, "export-sqlite")
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(files(&corrupted.0), corrupt_before);
    }
    // No source flag is accepted by the offline mode; it opens no database.
    let mut irrelevant_source = command(&fixture, &history, &output.0, "verify-saved");
    irrelevant_source.args(["--state-db", "does-not-exist.sqlite"]);
    assert!(!irrelevant_source.output().unwrap().status.success());
    fixture.stores.clear();
    let state_path = fixture.directory.0.join("state-0.sqlite");
    let moved_path = fixture.directory.0.join("source-is-unavailable.sqlite");
    std::fs::rename(&state_path, &moved_path).unwrap();
    assert!(
        success(
            command(&fixture, &history, &output.0, "verify-saved")
                .output()
                .unwrap()
        )
        .contains("independently-verified")
    );
    std::fs::rename(moved_path, state_path).unwrap();
    let reopened: ExistingSqliteSource = ExistingSqliteSource::open(
        &fixture.directory.0.join("state-0.sqlite"),
        &fixture.directory.0.join("blobs.sqlite"),
        fixture.network.chain_id.clone(),
        fixture.network.validators[0].validator_id,
        fixture.network.domain,
        300,
    )
    .unwrap();
    assert_eq!(
        capture_source_business_snapshot(
            &reopened.durable,
            &reopened.blobs,
            &reopened.operation,
            fixture.network.domain,
            NonZeroUsize::new(128).unwrap()
        )
        .unwrap(),
        before
    );
}
