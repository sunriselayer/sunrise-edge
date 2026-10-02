//! Compiled local readiness over a genuinely frozen/drained SQLite source.
//! Core separately verifies actual initial E registration and A/B/C/E staging.
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;
mod support {
    pub use super::genesis_fixture;
}
#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "business_cut/fixture.rs"]
mod fixture;

use consensus::readiness::{
    ReadinessCertificate, ReadinessCertifier, ReadinessVote, decode_readiness_certificate,
    decode_readiness_vote,
};
use fixture::{Directory, Fixture, copy_files, files};
use node_core::business_reconstruction::{
    SourceBusinessSnapshot,
    cut::{
        BUSINESS_CUT_STREAMS, BusinessCutChunk, BusinessCutPage, SavedBusinessCut,
        SavedBusinessCutComponent, VerifiedBusinessCut,
    },
    inactive_import::verify_saved_business_import,
};
use protocol_types::ValidatorId;
use runtime::portable::DurablePortableSnapshotRepository;
use runtime::{
    InactiveImportRepository, ReadinessRetentionRepository, ReadinessSlot, ReadinessSlotObservation,
};
use runtime_sqlite::{SqliteImportTarget, SqliteNamespace};
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use sunrise_edge_operator::{
    business_cut::{CutArchiveLimits, export_source_business_cut, verify_business_cut_archive},
    business_snapshot::capture_source_business_snapshot,
    immutable_archive::ImmutableArchive,
};
use validator_set::{ValidatorInfo, ValidatorSet, encode_validator_set};

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

/// Assemble public paginated transport from a genuinely verified archive;
/// private import verification must still reconstruct it independently.
fn public_transfer(
    cut: &VerifiedBusinessCut,
    resolver: &hashing::HashSuiteResolver,
) -> SavedBusinessCut {
    let mut saved: SavedBusinessCut = SavedBusinessCut {
        identity: cut.identity().clone(),
        package: cut.package_identity().clone(),
        components: Vec::new(),
    };
    for collection in BUSINESS_CUT_STREAMS {
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page: BusinessCutPage = cut
                .read_page(
                    resolver,
                    collection,
                    after.as_deref(),
                    NonZeroUsize::new(128).unwrap(),
                )
                .unwrap();
            for descriptor in page.descriptors {
                let mut bytes: Vec<u8> = Vec::new();
                let mut offset: u64 = 0;
                loop {
                    let chunk: BusinessCutChunk = cut
                        .read_chunk(&descriptor, offset, NonZeroUsize::new(1048576).unwrap())
                        .unwrap();
                    offset = offset
                        .checked_add(u64::try_from(chunk.bytes.len()).unwrap())
                        .unwrap();
                    bytes.extend_from_slice(&chunk.bytes);
                    if offset == descriptor.length {
                        break;
                    }
                }
                after = Some(descriptor.key.clone());
                saved
                    .components
                    .push(SavedBusinessCutComponent { descriptor, bytes });
            }
            if page.terminal {
                break;
            }
        }
    }
    saved
}
fn pins(command: &mut Command, fixture: &Fixture, history: &Path, cut: &Path) {
    command.args([
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
        "--cut-dir",
        cut.to_str().unwrap(),
    ]);
}
#[allow(clippy::too_many_arguments)]
fn voting(
    fixture: &Fixture,
    history: &Path,
    cut: &Path,
    next: &Path,
    destination: &Path,
    output: &Path,
    validator: ValidatorId,
    key: &Path,
) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_conditional_readiness"));
    command.arg("vote-sqlite");
    pins(&mut command, fixture, history, cut);
    command.args([
        "--next-set",
        next.to_str().unwrap(),
        "--out-dir",
        output.to_str().unwrap(),
        "--state-db",
        destination.join("state.db").to_str().unwrap(),
        "--blob-db",
        destination.join("body.db").to_str().unwrap(),
        "--validator-id",
        &hex(validator.as_bytes()),
        "--signer-key-file",
        key.to_str().unwrap(),
    ]);
    command
}

#[test]
fn compiled_conditional_readiness_real_retention_restart_and_distinct_certificate() {
    let fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    std::fs::write(
        fixture.directory.0.join("genesis.bin"),
        &fixture.network.manifest_bytes,
    )
    .unwrap();
    let (identity, ordered) = fixture.history();
    let history: Directory = Directory::new("ready-history-parent");
    let history_root: PathBuf = history.0.join("history");
    fixture.write_history(&history_root, &identity, &ordered);
    let cut: Directory = Directory::new("ready-cut");
    let archive: ImmutableArchive = ImmutableArchive::open(&cut.0).unwrap();
    assert!(
        export_source_business_cut(
            fixture.plan(&identity, fixture.operation),
            &fixture.stores[0],
            &fixture.blobs,
            &ordered,
            &archive,
            CutArchiveLimits::new(128, 1048576, 4096).unwrap()
        )
        .unwrap()
        .complete
    );
    let verified_cut: VerifiedBusinessCut =
        verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive).unwrap();
    let saved: SavedBusinessCut = public_transfer(&verified_cut, &fixture.network.resolver);
    let verified =
        verify_saved_business_import(fixture.plan(&identity, fixture.operation), &saved).unwrap();
    let original_cut: BTreeMap<String, Vec<u8>> = files(&cut.0);
    let before: SourceBusinessSnapshot = fixture.snapshot();
    let set: ValidatorSet = ValidatorSet::new(
        protocol_types::Epoch::new(fixture.network.epoch.get() + 1),
        fixture
            .root
            .manifest()
            .validator_set
            .validators
            .iter()
            .map(|member| ValidatorInfo {
                id: member.id,
                voting_power: member.voting_power,
                signature_scheme: member.signature_scheme,
                public_key: member.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    let next: PathBuf = fixture.directory.0.join("next-set.bin");
    std::fs::write(&next, encode_validator_set(&set).unwrap()).unwrap();
    let expected_subject = node_core::conditional_readiness::readiness_subject_for_candidate(
        verified.binding(),
        &fixture.network.resolver,
        &set,
    )
    .unwrap();
    let owner: ReadinessCertifier<'_> =
        ReadinessCertifier::new(&fixture.network.resolver, &expected_subject, &set).unwrap();
    let mut votes: Vec<(Directory, Vec<u8>)> = Vec::new();
    let mut destinations: Vec<Directory> = Vec::new();
    for (index, validator) in fixture.network.validators.iter().take(3).enumerate() {
        let destination: Directory = Directory::new(&format!("ready-import-{index}"));
        let mut importer: Command = Command::new(env!("CARGO_BIN_EXE_business_import"));
        importer.arg("create-sqlite");
        pins(&mut importer, &fixture, &history_root, &cut.0);
        importer.args([
            "--state-db",
            destination.0.join("state.db").to_str().unwrap(),
            "--blob-db",
            destination.0.join("body.db").to_str().unwrap(),
            "--validator-id",
            &hex(validator.validator_id.as_bytes()),
            "--max-new-batches",
            "4096",
        ]);
        assert!(success(importer.output().unwrap()).contains("business_import=complete-inactive"));
        let key: PathBuf = destination.0.join("private.key");
        std::fs::write(&key, validator.signing_key.as_ref()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let output: Directory = Directory::new(&format!("ready-vote-{index}"));
        if index == 0 {
            #[cfg(unix)]
            {
                let alias: PathBuf = fixture.directory.0.join("linked-key-directory");
                std::os::unix::fs::symlink(&destination.0, &alias).unwrap();
                assert!(
                    !voting(
                        &fixture,
                        &history_root,
                        &cut.0,
                        &next,
                        &destination.0,
                        &output.0,
                        validator.validator_id,
                        &alias.join("private.key")
                    )
                    .output()
                    .unwrap()
                    .status
                    .success()
                );
                assert!(!output.0.join("vote.bin").exists());
            }
            std::fs::write(output.0.join("vote.bin"), b"invalid retained artifact").unwrap();
            assert!(
                !voting(
                    &fixture,
                    &history_root,
                    &cut.0,
                    &next,
                    &destination.0,
                    &output.0,
                    validator.validator_id,
                    &key
                )
                .output()
                .unwrap()
                .status
                .success()
            );
            let target: SqliteImportTarget = SqliteImportTarget::open_existing(
                destination.0.join("state.db"),
                SqliteNamespace::new(
                    fixture.network.chain_id.clone(),
                    validator.validator_id,
                    fixture.network.domain,
                ),
                verified.binding(),
            )
            .unwrap();
            let token = target
                .begin_portable_snapshot(&fixture.operation, fixture.network.domain)
                .unwrap();
            let progress = target
                .read_import_progress(&fixture.operation, fixture.network.domain)
                .unwrap()
                .unwrap();
            let slot: ReadinessSlot = ReadinessSlot {
                identity: expected_subject
                    .identity(&fixture.network.resolver)
                    .unwrap(),
                signer: validator.validator_id,
            };
            assert_eq!(
                target
                    .read_ready_slot_at(
                        &fixture.operation,
                        fixture.network.domain,
                        verified.binding(),
                        &progress,
                        &token,
                        &slot
                    )
                    .unwrap(),
                ReadinessSlotObservation::Absent
            );
            assert_eq!(
                std::fs::read(output.0.join("vote.bin")).unwrap(),
                b"invalid retained artifact"
            );
            std::fs::remove_file(output.0.join("vote.bin")).unwrap();
        }
        assert!(
            success(
                voting(
                    &fixture,
                    &history_root,
                    &cut.0,
                    &next,
                    &destination.0,
                    &output.0,
                    validator.validator_id,
                    &key
                )
                .output()
                .unwrap()
            )
            .contains("conditional_readiness=retained-vote")
        );
        let original: Vec<u8> = std::fs::read(output.0.join("vote.bin")).unwrap();
        let vote: ReadinessVote = decode_readiness_vote(&original).unwrap();
        owner.verify_vote(&vote).unwrap();
        assert_eq!(vote.signer, validator.validator_id);
        let mut retry: Command = voting(
            &fixture,
            &history_root,
            &cut.0,
            &next,
            &destination.0,
            &output.0,
            validator.validator_id,
            &key,
        );
        assert!(success(retry.output().unwrap()).contains("conditional_readiness=retained-vote"));
        assert_eq!(
            std::fs::read(output.0.join("vote.bin")).unwrap(),
            original,
            "separate restarted process returns the original artifact"
        );
        votes.push((output, original));
        destinations.push(destination);
    }
    let copied_vote: Directory = Directory::new("ready-public-vote-copy");
    copy_files(&votes[0].0.0, &copied_vote.0);
    assert_eq!(files(&votes[0].0.0), files(&copied_vote.0));
    let certificates: Directory = Directory::new("ready-certificates");
    let assembly = |count: usize, duplicate: bool| -> Command {
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_conditional_readiness"));
        command.arg("certificate");
        pins(&mut command, &fixture, &history_root, &cut.0);
        command.args([
            "--next-set",
            next.to_str().unwrap(),
            "--out-dir",
            certificates.0.to_str().unwrap(),
        ]);
        for index in 0..count {
            let selected: usize = if duplicate { 0 } else { index };
            let directory: &Path = if selected == 0 {
                &copied_vote.0
            } else {
                &votes[selected].0.0
            };
            command.arg("--vote").arg(directory.join("vote.bin"));
        }
        command
    };
    assert!(!assembly(2, false).output().unwrap().status.success());
    assert!(!assembly(3, true).output().unwrap().status.success());
    assert!(!certificates.0.join("certificate.bin").exists());
    assert!(
        success(assembly(3, false).output().unwrap())
            .contains("conditional_readiness=verified-certificate")
    );
    let bytes: Vec<u8> = std::fs::read(certificates.0.join("certificate.bin")).unwrap();
    let certificate: ReadinessCertificate = decode_readiness_certificate(&bytes).unwrap();
    owner.verify_certificate(&certificate).unwrap();
    success(assembly(3, false).output().unwrap());
    assert_eq!(
        std::fs::read(certificates.0.join("certificate.bin")).unwrap(),
        bytes
    );
    let roles: BTreeMap<ValidatorId, Vec<u8>> = votes
        .iter()
        .map(|(_, bytes)| {
            let vote: ReadinessVote = decode_readiness_vote(bytes).unwrap();
            (vote.signer, bytes.clone())
        })
        .collect();
    assert_eq!(roles.len(), 3);
    assert_eq!(files(&cut.0), original_cut);
    assert_eq!(
        fixture.snapshot(),
        before,
        "local readiness cannot mutate the source"
    );
}
