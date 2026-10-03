//! The new client gate is locally pinned and runs before endpoint I/O.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use crypto::SignatureSigner;
use ed25519_zebra::SigningKey;
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind, paid_intent_signing_frame,
};
use node_core::genesis::genesis_manifest_signing_frame;
use node_core::logical_generation::CommitmentProfile;
use node_core::{GenesisManifest, encode_genesis_manifest, genesis_manifest_commitment};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    SignatureSchemeId,
};
use sunrise_edge_client::{
    Client, ClientError, FastVoteEndpoint, FastVoteGenesisTrustError, FastVoteNetworkError,
    FastVoteQuorumError, HashSuiteResolver, LocalSigner, PublicationContext, SignedPaidIntent,
    TrustedFastVoteGenesis, load_trusted_fastvote_genesis_with_profile,
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

fn context_fixture() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("causal-sdk-pin").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap()
}

fn resolver_fixture(context: &PublicationContext) -> HashSuiteResolver {
    HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

fn write_manifest(manifest: &GenesisManifest) -> ManifestFile {
    let path: ManifestFile = ManifestFile(std::env::temp_dir().join(format!(
        "sunrise-causal-sdk-{}-{}.manifest",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    std::fs::write(&path.0, encode_genesis_manifest(manifest).unwrap()).unwrap();
    path
}

fn pinned() -> (
    ManifestFile,
    TrustedFastVoteGenesis,
    HashSuiteResolver,
    GenesisManifest,
) {
    let context: PublicationContext = context_fixture();
    let resolver: HashSuiteResolver = resolver_fixture(&context);
    let signer: LocalSigner = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
    let owner: DevOwner = DevOwner::new(*signer.address().as_bytes());
    let (mut manifest, _) =
        build_paid_genesis_manifest(&resolver, &context, &[owner], owner).unwrap();
    manifest.commitment_profile = CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 1;
    manifest.signature = SigningKey::from(DEVNET_PAID_GENESIS_SEED)
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let path: ManifestFile = write_manifest(&manifest);
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
    let (_path, trusted, resolver, manifest) = pinned();
    assert!(trusted.admission_profile().is_causal());
    assert!(trusted.require_owned_request_id(&[1; 32]).is_ok());
    assert!(trusted.require_owned_request_id(&[0x81; 32]).is_err());
    let mut synthetic: [u8; 32] = [1; 32];
    synthetic[..8].copy_from_slice(b"SE:FPv1:");
    assert!(trusted.require_owned_request_id(&synthetic).is_err());
    let signed: SignedPaidIntent = SignedPaidIntent {
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
            application: PaidApplication::Publish(
                manifest.publication.request().artifact().clone(),
            ),
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
            &signed,
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        FastVoteQuorumError::Network(FastVoteNetworkError::Preflight(ClientError::NodeCore(_)))
    ));
}

/// `commitment_profile()` and `admission_profile().commitment_profile()` are
/// both derived from the one immutable root's one signed manifest, so they
/// can never independently disagree -- there is no longer any separate
/// mutable profile tag a caller or an internal bug could downgrade.
#[test]
fn commitment_profile_always_matches_its_own_admission_profile() {
    let (_path, trusted, _, _) = pinned();
    assert_eq!(
        trusted.commitment_profile(),
        trusted.admission_profile().commitment_profile()
    );
    assert!(trusted.require_owned_request_id(&[0x81; 32]).is_err());
}

/// A signed genesis whose original committee names a non-Ed25519 validator
/// must be rejected while constructing the `TrustedFastVoteGenesis` itself --
/// before any endpoint is ever configured or dialed, not merely before a
/// caller-chosen request signs anything.
#[test]
fn causal_signed_genesis_with_unsupported_validator_scheme_is_rejected_before_any_io() {
    let context: PublicationContext = context_fixture();
    let resolver: HashSuiteResolver = resolver_fixture(&context);
    let signer: LocalSigner = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
    let owner: DevOwner = DevOwner::new(*signer.address().as_bytes());
    let (mut manifest, _) =
        build_paid_genesis_manifest(&resolver, &context, &[owner], owner).unwrap();
    manifest.validator_set.validators[0].signature_scheme = SignatureSchemeId::Secp256k1;
    manifest.signature = SigningKey::from(DEVNET_PAID_GENESIS_SEED)
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let digest: Digest32 = genesis_manifest_commitment(&resolver, &manifest).unwrap();
    let path: ManifestFile = write_manifest(&manifest);
    // `TrustedFastVoteGenesis` does not implement `Debug`, so match
    // explicitly here instead of `unwrap_err`, which requires the success
    // type to be `Debug`.
    let error: FastVoteGenesisTrustError = match load_trusted_fastvote_genesis_with_profile(
        &path.0,
        &resolver,
        digest.bytes(),
        &context,
    ) {
        Ok(_) => panic!("unsupported committee signature scheme must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        FastVoteGenesisTrustError::InvalidValidatorSet(reason)
            if reason == "FastVote phase 1 supports only Ed25519 validators"
    ));
}

/// A signed intent whose own context disagrees with the locally pinned
/// root's authenticated context must be rejected before any endpoint is
/// ever contacted -- a genuine per-request check, distinct from the removed
/// self-consistency checks among `certifier`/`commitment_profile`/
/// `admission_profile`, all of which are derived from that same root and so
/// can no longer disagree with each other. The intent carries a real
/// signature from the genesis authority's own key over its own (wrong)
/// context, so the context field is the sole reason for rejection, not an
/// incidentally invalid signature.
#[test]
fn causal_signed_intent_with_wrong_context_is_rejected_before_any_io() {
    let (_path, trusted, resolver, manifest) = pinned();
    let wrong_context: PublicationContext = PublicationContext::new(
        manifest.context().chain_id().clone(),
        manifest.context().protocol_version(),
        Epoch::new(manifest.context().epoch().get() + 1),
    )
    .unwrap();
    let signer: LocalSigner = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
    let owner: DevOwner = DevOwner::new(*signer.address().as_bytes());
    // Publish artifacts bind their own context too. Build a genuinely valid
    // intent for the other epoch, rather than failing to encode/sign a mixed
    // context fixture before reaching the client boundary under test.
    let (wrong_manifest, _) =
        build_paid_genesis_manifest(&resolver, &wrong_context, &[owner], owner).unwrap();
    let intent: PaidIntent = PaidIntent {
        context: wrong_context.clone(),
        request_id: [1; 32],
        sender: manifest.genesis_authority,
        nonce: 0,
        fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(
            &resolver,
            &wrong_manifest.fee_policy,
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
        application: PaidApplication::Publish(
            wrong_manifest.publication.request().artifact().clone(),
        ),
        gas_limit: 1,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&wrong_context, &intent).unwrap();
    let signature_bytes: Vec<u8> = signer.sign_framed(&frame).unwrap();
    let signature: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
    let signed: SignedPaidIntent = SignedPaidIntent { intent, signature };
    let signed_bytes: Vec<u8> =
        execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    execution::paid_execution::authenticate_paid_intent(&resolver, &wrong_context, &signed_bytes)
        .expect("the wrong-epoch intent must independently authenticate under its own context");
    let endpoints: Vec<FastVoteEndpoint<NoIo>> = vec![FastVoteEndpoint {
        validator_id: protocol_types::ValidatorId::new(manifest.genesis_authority),
        endpoint_label: "never-dial".to_owned(),
        client: Client::new(NoIo),
    }];
    let error: FastVoteQuorumError = trusted
        .collect_owned_certificate(
            &endpoints,
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
    let (_path, trusted, _, manifest) = pinned();
    let domain: protocol_types::AtomicityDomainId =
        protocol_types::AtomicityDomainId::new([0x41; 32]).unwrap();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(trusted.genesis_root(), domain).unwrap();
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

#[test]
fn full_history_reader_requires_a_present_completion_marker() {
    use node_core::ordered_economics::{
        OrderedEconomicsPolicy, OrderedHistoryIdentity, encode_ordered_history_identity,
    };
    use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive;
    let (_path, trusted, _, manifest) = pinned();
    let domain: protocol_types::AtomicityDomainId =
        protocol_types::AtomicityDomainId::new([0x43; 32]).unwrap();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(trusted.genesis_root(), domain).unwrap();
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: manifest.context().clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        anchor: policy.anchor(),
        through_height: 0,
        through_view: 0,
        through_digest: policy.anchor(),
    };
    let archive: ArchiveDirectory = ArchiveDirectory::new();
    std::fs::write(
        archive.0.join("identity.bin"),
        encode_ordered_history_identity(&identity).unwrap(),
    )
    .unwrap();
    std::fs::write(archive.0.join("chunk-size.bin"), 1024_u32.to_be_bytes()).unwrap();
    // No "complete" marker file exists at all, as opposed to one present but
    // differing (already covered above): a missing marker must also refuse,
    // never fall back to treating the identity file alone as authoritative.
    assert!(read_verified_ordered_history_archive(&policy, &archive.0).is_err());
}

#[test]
fn single_height_transport_rejects_corruption_and_mismatched_target() {
    use node_core::ordered_economics::{
        OrderedEconomicsPolicy, OrderedHistoryComponentKind, OrderedHistoryComponentRef,
        OrderedHistoryHeightDescriptor, OrderedHistoryIdentity,
        encode_ordered_history_height_descriptor, ordered_history_component_digest,
    };
    use sunrise_edge_client::ordered_history_archive::read_ordered_history_height;
    let (_path, trusted, _, manifest) = pinned();
    let domain: protocol_types::AtomicityDomainId =
        protocol_types::AtomicityDomainId::new([0x44; 32]).unwrap();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(trusted.genesis_root(), domain).unwrap();
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: manifest.context().clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        anchor: policy.anchor(),
        through_height: 1,
        through_view: 1,
        through_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x51; 32]),
    };
    let component_bytes: Vec<u8> = vec![0xAB; 48];
    let digest: Digest32 = ordered_history_component_digest(&policy, &component_bytes).unwrap();
    let descriptor: OrderedHistoryHeightDescriptor = OrderedHistoryHeightDescriptor {
        identity: identity.clone(),
        height: 1,
        view: 1,
        block_digest: identity.through_digest,
        components: vec![OrderedHistoryComponentRef {
            kind: OrderedHistoryComponentKind::CommitProof,
            length: component_bytes.len() as u64,
            digest,
        }],
    };
    let archive: ArchiveDirectory = ArchiveDirectory::new();
    std::fs::write(archive.0.join("chunk-size.bin"), 1024_u32.to_be_bytes()).unwrap();
    let height_dir: PathBuf = archive.0.join(format!("height-{:020}", 1));
    std::fs::create_dir(&height_dir).unwrap();
    let descriptor_path: PathBuf = height_dir.join("descriptor.bin");
    let descriptor_bytes: Vec<u8> = encode_ordered_history_height_descriptor(&descriptor).unwrap();
    std::fs::write(&descriptor_path, &descriptor_bytes).unwrap();
    let component_dir: PathBuf =
        height_dir.join(format!("component-{:02}", OrderedHistoryComponentKind::CommitProof as u16));
    std::fs::create_dir(&component_dir).unwrap();
    let chunk_path: PathBuf = component_dir.join(format!("chunk-{:020}.bin", 0));
    std::fs::write(&chunk_path, &component_bytes).unwrap();

    let good = read_ordered_history_height(&policy, &archive.0, &identity, 1).unwrap();
    assert_eq!(good.descriptor, descriptor);
    assert_eq!(
        good.components,
        vec![(OrderedHistoryComponentKind::CommitProof, component_bytes.clone())]
    );

    // Height outside the fixed target, both directions.
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 0).is_err());
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 2).is_err());

    // A claimed identity differing from the saved descriptor target.
    let mut wrong_identity: OrderedHistoryIdentity = identity.clone();
    wrong_identity.domain = protocol_types::AtomicityDomainId::new([0x99; 32]).unwrap();
    assert!(read_ordered_history_height(&policy, &archive.0, &wrong_identity, 1).is_err());

    // Missing descriptor.
    std::fs::remove_file(&descriptor_path).unwrap();
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 1).is_err());

    // Malformed descriptor.
    std::fs::write(&descriptor_path, b"not a canonical descriptor frame").unwrap();
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 1).is_err());
    std::fs::write(&descriptor_path, &descriptor_bytes).unwrap();

    // Truncated chunk: fewer bytes than the descriptor declares.
    std::fs::write(&chunk_path, &component_bytes[..component_bytes.len() - 10]).unwrap();
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 1).is_err());

    // Oversized chunk: more bytes than the descriptor declares and bounds.
    let mut oversized: Vec<u8> = component_bytes.clone();
    oversized.extend_from_slice(&[0xFF; 20]);
    std::fs::write(&chunk_path, &oversized).unwrap();
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 1).is_err());

    // Exact length, wrong content: digest mismatch.
    let mut tampered: Vec<u8> = component_bytes.clone();
    tampered[0] ^= 0xFF;
    std::fs::write(&chunk_path, &tampered).unwrap();
    assert!(read_ordered_history_height(&policy, &archive.0, &identity, 1).is_err());

    // Restoring the exact original bytes must read genuinely again, proving
    // every prior failure came from the corruption, not residual state.
    std::fs::write(&chunk_path, &component_bytes).unwrap();
    assert_eq!(
        read_ordered_history_height(&policy, &archive.0, &identity, 1)
            .unwrap()
            .components,
        vec![(OrderedHistoryComponentKind::CommitProof, component_bytes)]
    );
}
