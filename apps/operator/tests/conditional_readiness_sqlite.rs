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
#[path = "support/ordered_seal_sqlite_acceptance.rs"]
mod ordered_seal_sqlite_acceptance;
#[path = "support/successor_host_acceptance.rs"]
mod successor_host_acceptance;

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
    BlobStore, InactiveImportRepository, ReadinessRetentionRepository, ReadinessSlot,
    ReadinessSlotObservation,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_conditional_readiness_real_retention_restart_and_distinct_certificate() {
    let mut fixture: Fixture = Fixture::new();
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
    for (index, validator) in fixture.network.validators.iter().enumerate() {
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
    let assembly = |count: usize, duplicate: bool, offset: usize, out_dir: &Path| -> Command {
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_conditional_readiness"));
        command.arg("certificate");
        pins(&mut command, &fixture, &history_root, &cut.0);
        command.args([
            "--next-set",
            next.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ]);
        for index in 0..count {
            let selected: usize = if duplicate { 0 } else { offset + index };
            let directory: &Path = if selected == 0 {
                &copied_vote.0
            } else {
                &votes[selected].0.0
            };
            command.arg("--vote").arg(directory.join("vote.bin"));
        }
        command
    };
    assert!(
        !assembly(2, false, 0, &certificates.0)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !assembly(3, true, 0, &certificates.0)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!certificates.0.join("certificate.bin").exists());
    assert!(
        success(assembly(3, false, 0, &certificates.0).output().unwrap())
            .contains("conditional_readiness=verified-certificate")
    );
    let bytes: Vec<u8> = std::fs::read(certificates.0.join("certificate.bin")).unwrap();
    let certificate: ReadinessCertificate = decode_readiness_certificate(&bytes).unwrap();
    owner.verify_certificate(&certificate).unwrap();
    success(assembly(3, false, 0, &certificates.0).output().unwrap());
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
    assert_eq!(roles.len(), 4);
    // Reuse the independently reconstructed cut and genuine successor quorum
    // above. Preparation is a separate compiled process, not a raw storage
    // completion, and adding this step does not duplicate the expensive setup.
    let seal_output: Directory = Directory::new("unsigned-seal-preparation");
    let prepare =
        |certificate_path: &Path, state: &Path, blobs: &Path, out_dir: &Path| -> Command {
            let mut command: Command = Command::new(env!("CARGO_BIN_EXE_ordered_seal"));
            command.arg("prepare-sqlite");
            pins(&mut command, &fixture, &history_root, &cut.0);
            command.args([
                "--certificate",
                certificate_path.to_str().unwrap(),
                "--state-db",
                state.to_str().unwrap(),
                "--blob-db",
                blobs.to_str().unwrap(),
                "--validator-id",
                &hex(fixture.network.validators[0].validator_id.as_bytes()),
                "--out-dir",
                out_dir.to_str().unwrap(),
            ]);
            command
        };
    let certificate_path: PathBuf = certificates.0.join("certificate.bin");
    let source_state: PathBuf = fixture.directory.0.join("state-0.sqlite");
    let source_blobs: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let certificate_digest = node_core::ordered_economics::seal_certificate_digest(
        &fixture.network.resolver,
        fixture.network.epoch,
        &bytes,
    )
    .unwrap();
    assert!(
        fixture
            .blobs
            .get_blob(&certificate_digest)
            .unwrap()
            .is_none()
    );
    assert!(
        !prepare(
            &certificate_path,
            &destinations[0].0.join("state.db"),
            &destinations[0].0.join("body.db"),
            &seal_output.0,
        )
        .output()
        .unwrap()
        .status
        .success(),
        "an inactive successor target is not an outgoing source"
    );
    assert!(!seal_output.0.join("candidate.bin").exists());
    assert!(
        success(
            prepare(
                &certificate_path,
                &source_state,
                &source_blobs,
                &seal_output.0
            )
            .output()
            .unwrap()
        )
        .contains("ordered_seal=prepared")
    );
    let candidate_bytes: Vec<u8> = std::fs::read(seal_output.0.join("candidate.bin")).unwrap();
    let candidate =
        node_core::ordered_economics::decode_ordered_candidate(&candidate_bytes).unwrap();
    assert_eq!(
        candidate.kind,
        node_core::ordered_economics::OrderedOperationKind::Seal
    );
    let seal = node_core::ordered_economics::decode_seal_intent(&candidate.intent).unwrap();
    assert_eq!(seal.readiness_subject, expected_subject);
    assert_eq!(
        candidate.created_checkpoint,
        saved.identity.ordered_history.through_height
    );
    assert_eq!(seal.certificate_digest, certificate_digest);
    assert_eq!(
        fixture.blobs.get_blob(&certificate_digest).unwrap(),
        Some(bytes.clone())
    );
    success(
        prepare(
            &certificate_path,
            &source_state,
            &source_blobs,
            &seal_output.0,
        )
        .output()
        .unwrap(),
    );
    assert_eq!(
        std::fs::read(seal_output.0.join("candidate.bin")).unwrap(),
        candidate_bytes
    );
    let bad_certificate: PathBuf = fixture.directory.0.join("invalid-seal-certificate.bin");
    let mut altered: ReadinessCertificate = certificate.clone();
    altered.votes[0].signature[0] ^= 1;
    std::fs::write(
        &bad_certificate,
        consensus::readiness::encode_readiness_certificate(&altered).unwrap(),
    )
    .unwrap();
    assert!(
        !prepare(
            &bad_certificate,
            &source_state,
            &source_blobs,
            &seal_output.0
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(
        std::fs::read(seal_output.0.join("candidate.bin")).unwrap(),
        candidate_bytes
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "preparation never changes source state or receipts"
    );
    assert_eq!(files(&cut.0), original_cut);
    assert_eq!(
        fixture.snapshot(),
        before,
        "local readiness cannot mutate the source"
    );
    // DR-0187: build a second, genuinely quorum-backed Seal candidate that
    // shares this exact semantic target but a distinct certificate variant
    // (a different 3-of-4 successor combination), never a raw-fabricated
    // protocol proof. The operator acceptance replays it after the first
    // candidate is accepted to show the Sealed barrier -- not stale
    // completion bookkeeping -- rejects it.
    let certificates_b: Directory = Directory::new("ready-certificates-competing");
    assert!(
        success(assembly(3, false, 1, &certificates_b.0).output().unwrap())
            .contains("conditional_readiness=verified-certificate")
    );
    let competing_certificate_bytes: Vec<u8> =
        std::fs::read(certificates_b.0.join("certificate.bin")).unwrap();
    assert_ne!(competing_certificate_bytes, bytes);
    let competing_certificate: ReadinessCertificate =
        decode_readiness_certificate(&competing_certificate_bytes).unwrap();
    owner.verify_certificate(&competing_certificate).unwrap();
    let seal_output_b: Directory = Directory::new("unsigned-seal-preparation-competing");
    let competing_certificate_path: PathBuf = certificates_b.0.join("certificate.bin");
    assert!(
        success(
            prepare(
                &competing_certificate_path,
                &source_state,
                &source_blobs,
                &seal_output_b.0
            )
            .output()
            .unwrap()
        )
        .contains("ordered_seal=prepared")
    );
    let competing_candidate_bytes: Vec<u8> =
        std::fs::read(seal_output_b.0.join("candidate.bin")).unwrap();
    let competing_candidate =
        node_core::ordered_economics::decode_ordered_candidate(&competing_candidate_bytes).unwrap();
    assert_eq!(
        competing_candidate.kind,
        node_core::ordered_economics::OrderedOperationKind::Seal
    );
    assert_ne!(competing_candidate.request_id, candidate.request_id);
    assert_eq!(
        competing_candidate.created_checkpoint,
        candidate.created_checkpoint
    );
    let competing_seal =
        node_core::ordered_economics::decode_seal_intent(&competing_candidate.intent).unwrap();
    assert_eq!(competing_seal.readiness_subject, seal.readiness_subject);
    assert_eq!(competing_seal.predecessor_tag, seal.predecessor_tag);
    assert_eq!(competing_seal.predecessor_digest, seal.predecessor_digest);
    assert_ne!(competing_seal.certificate_digest, seal.certificate_digest);
    let competing_certificate_digest = node_core::ordered_economics::seal_certificate_digest(
        &fixture.network.resolver,
        fixture.network.epoch,
        &competing_certificate_bytes,
    )
    .unwrap();
    assert_eq!(
        competing_seal.certificate_digest,
        competing_certificate_digest
    );
    let subject_identity = seal
        .readiness_subject
        .identity(&fixture.network.resolver)
        .unwrap();
    let competing_subject_identity = competing_seal
        .readiness_subject
        .identity(&fixture.network.resolver)
        .unwrap();
    let target = node_core::ordered_economics::seal_target_digest(
        &fixture.network.resolver,
        &fixture.network.context,
        subject_identity,
        seal.predecessor_tag,
        seal.predecessor_digest,
    )
    .unwrap();
    let competing_target = node_core::ordered_economics::seal_target_digest(
        &fixture.network.resolver,
        &fixture.network.context,
        competing_subject_identity,
        competing_seal.predecessor_tag,
        competing_seal.predecessor_digest,
    )
    .unwrap();
    assert_eq!(
        target, competing_target,
        "the competing branch shares the exact same semantic Seal target"
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "the competing variant's preparation never changes source state or receipts"
    );
    ordered_seal_sqlite_acceptance::run_compiled_four_host_seal(
        &fixture,
        &seal_output.0.join("candidate.bin"),
        &candidate,
    );
    ordered_seal_sqlite_acceptance::run(
        &mut fixture,
        &seal_output.0.join("candidate.bin"),
        &candidate,
        &competing_candidate,
        &successor_host_acceptance::SuccessorProcessInputs {
            plan_history: history_root.clone(),
            cut: cut.0.clone(),
            certificate: certificates.0.clone(),
            competing_certificate: certificates_b.0.clone(),
            targets: destinations
                .iter()
                .map(|destination: &Directory| destination.0.clone())
                .collect(),
            binding: verified.binding().clone(),
        },
    )
    .await;
}
