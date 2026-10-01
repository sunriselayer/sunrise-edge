//! The new client gate is locally pinned and runs before endpoint I/O.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use ed25519_zebra::SigningKey;
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind,
};
use node_core::genesis::genesis_manifest_signing_frame;
use node_core::logical_generation::CommitmentProfile;
use node_core::{GenesisManifest, encode_genesis_manifest, genesis_manifest_commitment};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use sunrise_edge_client::{
    Client, ClientError, FastVoteEndpoint, FastVoteNetworkError, FastVoteQuorumError,
    HashSuiteResolver, LocalSigner, PublicationContext, SignedPaidIntent, TrustedFastVoteGenesis,
    load_trusted_fastvote_genesis_with_profile,
    transport::{Transport, TransportError, WireRequest, WireResponse},
};
use sunrise_edge_devnet::{DEVNET_PAID_GENESIS_SEED, DevOwner, build_paid_genesis_manifest};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct ManifestFile(PathBuf);
impl Drop for ManifestFile {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_file(&self.0);
    }
}

struct NoIo;
impl Transport for NoIo {
    fn send(&self, _request: &WireRequest) -> Result<WireResponse, TransportError> {
        panic!("invalid causal lane must fail before any endpoint I/O")
    }
}

fn pinned() -> (
    ManifestFile,
    TrustedFastVoteGenesis,
    HashSuiteResolver,
    GenesisManifest,
) {
    let context: PublicationContext = PublicationContext::new(
        ChainId::new("causal-sdk-pin").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let signer: LocalSigner = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
    let owner: DevOwner = DevOwner::new(*signer.address().as_bytes());
    let (mut manifest, _) =
        build_paid_genesis_manifest(&resolver, &context, &[owner], owner).unwrap();
    manifest.commitment_profile = CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 1;
    manifest.signature = SigningKey::from(DEVNET_PAID_GENESIS_SEED)
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let path: ManifestFile = ManifestFile(std::env::temp_dir().join(format!(
        "sunrise-causal-sdk-{}-{}.manifest",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    std::fs::write(&path.0, encode_genesis_manifest(&manifest).unwrap()).unwrap();
    let trusted: TrustedFastVoteGenesis = load_trusted_fastvote_genesis_with_profile(
        &path.0,
        &resolver,
        genesis_manifest_commitment(&resolver, &manifest)
            .unwrap()
            .bytes(),
        &context,
    )
    .unwrap();
    (path, trusted, resolver, manifest)
}

#[test]
fn signed_v4_client_pin_refuses_ordered_or_synthetic_owned_ids_before_io() {
    let (_path, mut trusted, resolver, manifest) = pinned();
    assert!(trusted.admission_profile().is_causal());
    assert!(trusted.require_owned_request_id(&[1; 32]).is_ok());
    assert!(trusted.require_owned_request_id(&[0x81; 32]).is_err());
    let mut synthetic: [u8; 32] = [1; 32];
    synthetic[..8].copy_from_slice(b"SE:FPv1:");
    assert!(trusted.require_owned_request_id(&synthetic).is_err());
    let mut signed: SignedPaidIntent = SignedPaidIntent {
        intent: PaidIntent {
            context: manifest.context().clone(),
            request_id: [0x81; 32],
            sender: manifest.genesis_authority,
            nonce: 0,
            fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(
                &resolver,
                &manifest.fee_policy,
            )
            .unwrap(),
            consent: FeeSourceConsent {
                source: objects::ObjectRef {
                    id: objects::ObjectId::new([0x22; 32]),
                    version: 1,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
                },
                access: ReservationAccessKind::Write,
                max_fee: fees::Amount::new(1),
                refund_recipient: manifest.genesis_authority,
            },
            application: PaidApplication::Publish(manifest.publication),
            gas_limit: 1,
            authorizations: Vec::new(),
        },
        signature: [0; 64],
    };
    let endpoints: Vec<FastVoteEndpoint<NoIo>> = vec![FastVoteEndpoint {
        validator_id: protocol_types::ValidatorId::new(manifest.genesis_authority),
        endpoint_label: "never-dial".to_owned(),
        client: Client::new(NoIo),
    }];
    let error: FastVoteQuorumError = trusted
        .collect_owned_certificate(
            &endpoints,
            &resolver,
            &signed,
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        FastVoteQuorumError::Network(FastVoteNetworkError::Preflight(ClientError::NodeCore(_)))
    ));

    signed.intent.request_id = [1; 32];
    let mut members: Vec<validator_set::ValidatorInfo> =
        trusted.certifier.validator_set().validators().to_vec();
    members[0].voting_power =
        protocol_types::VotingPower::new(members[0].voting_power.get().checked_add(1).unwrap());
    let altered: validator_set::ValidatorSet =
        validator_set::ValidatorSet::new(Epoch::new(0), members).unwrap();
    trusted.certifier = consensus::FastPathCertifier::new(
        trusted.certifier.chain_id().clone(),
        trusted.certifier.protocol_version(),
        trusted.certifier.epoch(),
        altered,
    )
    .unwrap();
    let error: FastVoteQuorumError = trusted
        .collect_owned_certificate(
            &endpoints,
            &resolver,
            &signed,
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        FastVoteQuorumError::Network(FastVoteNetworkError::Preflight(
            ClientError::PublicationTrustMismatch
        ))
    ));
}

#[test]
fn public_descriptive_profile_cannot_downgrade_the_private_pin() {
    let (_path, mut trusted, _, _) = pinned();
    trusted.commitment_profile = CommitmentProfile::PhysicalCheckpointV1;
    assert!(trusted.require_owned_request_id(&[0x81; 32]).is_err());
    assert_eq!(
        trusted.admission_profile().commitment_profile(),
        CommitmentProfile::CausalAdmission
    );
}

struct ArchiveDirectory(PathBuf);

impl ArchiveDirectory {
    fn new() -> Self {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-causal-archive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for ArchiveDirectory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn saved_ordering_marker_cannot_replace_complete_pinned_prefix_verification() {
    use node_core::ordered_economics::{
        OrderedEconomicsPolicy, OrderedHistoryIdentity, encode_ordered_history_identity,
    };
    use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive;
    let (_path, trusted, resolver, manifest) = pinned();
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        manifest.context().clone(),
        protocol_types::AtomicityDomainId::new([0x41; 32]).unwrap(),
        genesis_manifest_commitment(&resolver, &manifest).unwrap(),
        Some(&manifest),
        trusted.certifier.validator_set().clone(),
        resolver,
    )
    .unwrap();
    let mut identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: manifest.context().clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        anchor: policy.anchor(),
        through_height: 0,
        through_view: 0,
        through_digest: policy.anchor(),
    };
    let archive: ArchiveDirectory = ArchiveDirectory::new();
    let encoded: Vec<u8> = encode_ordered_history_identity(&identity).unwrap();
    std::fs::write(archive.0.join("identity.bin"), &encoded).unwrap();
    std::fs::write(archive.0.join("chunk-size.bin"), 1024_u32.to_be_bytes()).unwrap();
    std::fs::write(archive.0.join("complete"), &encoded).unwrap();
    let (verified, heights) = read_verified_ordered_history_archive(&policy, &archive.0).unwrap();
    assert_eq!(verified, identity);
    assert!(heights.is_empty());

    std::fs::write(archive.0.join("complete"), b"trusted cursor").unwrap();
    assert!(read_verified_ordered_history_archive(&policy, &archive.0).is_err());

    // Even a perfectly consistent identity/marker pair cannot invent its
    // omitted proof/candidate/result chunks or advance the verified cursor.
    identity.through_height = 1;
    identity.through_view = 1;
    identity.through_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x72; 32]);
    let encoded: Vec<u8> = encode_ordered_history_identity(&identity).unwrap();
    std::fs::write(archive.0.join("identity.bin"), &encoded).unwrap();
    std::fs::write(archive.0.join("complete"), &encoded).unwrap();
    assert!(read_verified_ordered_history_archive(&policy, &archive.0).is_err());
}

#[test]
fn saved_archive_reader_rejects_oversize_and_non_regular_relative_paths() {
    use std::path::Path;
    use sunrise_edge_client::ordered_history_archive::read_regular_archive_file;
    let archive: ArchiveDirectory = ArchiveDirectory::new();
    std::fs::write(archive.0.join("material.bin"), [1; 4]).unwrap();
    assert_eq!(
        read_regular_archive_file(&archive.0, Path::new("material.bin"), 4).unwrap(),
        [1; 4]
    );
    assert!(read_regular_archive_file(&archive.0, Path::new("material.bin"), 3).is_err());
    assert!(read_regular_archive_file(&archive.0, Path::new("../material.bin"), 4).is_err());
    assert!(read_regular_archive_file(&archive.0, Path::new("."), 4).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(archive.0.join("material.bin"), archive.0.join("alias.bin"))
            .unwrap();
        assert!(read_regular_archive_file(&archive.0, Path::new("alias.bin"), 4).is_err());
    }
}
