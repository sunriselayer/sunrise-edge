use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use node_core::fast_path::records::FastPathValidatorEntry;
use node_core::genesis::encode_genesis_manifest;
use protocol_types::{ChainId, Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion, ValidatorId};
use sunrise_edge_devnet::{DEVNET_PAID_GENESIS_SEED, DevOwner, build_paid_genesis_manifest};

use crate::fastvote_client::{FastVoteGenesisTrustError, load_trusted_fastvote_genesis};
use crate::key::LocalSigner;
use crate::ordered_economics_client::{OrderedGenesisTrustError, load_trusted_ordered_policy};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-sdk-local-genesis-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

fn context(epoch: u64) -> PublicationContext {
    PublicationContext::new(
        ChainId::new("sdk-local-genesis").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(epoch),
    )
    .unwrap()
}

#[test]
fn bounded_read_preserves_exact_bytes_and_existing_size_error() {
    let directory: TestDirectory = TestDirectory::new();
    let path: PathBuf = directory.path("bytes");
    let bytes: [u8; 4] = [0, 0xff, 0x80, 1];
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(read_bounded(&path, bytes.len()).unwrap(), bytes);
    let error: std::io::Error = read_bounded(&path, bytes.len() - 1).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(
        error.to_string(),
        "genesis manifest exceeds the maximum accepted size"
    );
    assert!(read_bounded(&path, 0).is_err());
    std::fs::write(&path, []).unwrap();
    assert!(read_bounded(&path, 0).unwrap().is_empty());
    assert!(read_bounded(&directory.path("missing"), 4).is_err());
}

#[cfg(unix)]
#[test]
fn bounded_read_keeps_following_input_symlinks() {
    let directory: TestDirectory = TestDirectory::new();
    let original: PathBuf = directory.path("original");
    let link: PathBuf = directory.path("link");
    std::fs::write(&original, b"exact\0bytes").unwrap();
    std::os::unix::fs::symlink(&original, &link).unwrap();
    assert_eq!(read_bounded(&link, 11).unwrap(), b"exact\0bytes");
    assert!(read_bounded(&link, 10).is_err());
}

#[test]
fn pinned_genesis_preserves_verification_order_and_public_error_mappings() {
    let directory: TestDirectory = TestDirectory::new();
    let path: PathBuf = directory.path("manifest");
    let expected_context: PublicationContext = context(0);
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        expected_context.chain_id().clone(),
        expected_context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let signer: LocalSigner = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
    let owner: DevOwner = DevOwner::new(*signer.address().as_bytes());
    let (mut manifest, _) =
        build_paid_genesis_manifest(&resolver, &expected_context, &[owner], owner).unwrap();
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: Digest32 = genesis_manifest_commitment(&resolver, &manifest).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let pinned: PinnedGenesis =
        load_pinned_genesis(&path, &resolver, digest.bytes(), &expected_context).unwrap();
    assert_eq!(pinned.digest, digest);
    assert_eq!(encode_genesis_manifest(&pinned.manifest).unwrap(), bytes);

    let wrong_context: PublicationContext = context(1);
    let mut wrong_digest: [u8; 32] = digest.bytes();
    wrong_digest[0] ^= 1;
    assert!(matches!(
        load_pinned_genesis(&path, &resolver, wrong_digest, &wrong_context),
        Err(LocalGenesisError::CommitmentMismatch)
    ));
    assert!(matches!(
        load_trusted_fastvote_genesis(&path, &resolver, wrong_digest, &wrong_context),
        Err(FastVoteGenesisTrustError::CommitmentMismatch)
    ));
    assert!(matches!(
        load_trusted_ordered_policy(
            &path,
            &resolver,
            wrong_digest,
            &wrong_context,
            protocol_types::AtomicityDomainId::new([0x55; 32]),
        ),
        Err(OrderedGenesisTrustError::CommitmentMismatch)
    ));
    assert!(matches!(
        load_pinned_genesis(&path, &resolver, digest.bytes(), &wrong_context),
        Err(LocalGenesisError::ContextMismatch)
    ));

    manifest.signature[0] ^= 1;
    let invalid_digest: Digest32 = genesis_manifest_commitment(&resolver, &manifest).unwrap();
    std::fs::write(&path, encode_genesis_manifest(&manifest).unwrap()).unwrap();
    assert!(matches!(
        load_pinned_genesis(&path, &resolver, invalid_digest.bytes(), &expected_context),
        Err(LocalGenesisError::InvalidSignature)
    ));
    std::fs::write(&path, b"not a canonical manifest").unwrap();
    assert!(matches!(
        load_pinned_genesis(&path, &resolver, digest.bytes(), &expected_context),
        Err(LocalGenesisError::Decode(_))
    ));
    assert!(matches!(
        load_pinned_genesis(
            &directory.path("missing"),
            &resolver,
            digest.bytes(),
            &expected_context
        ),
        Err(LocalGenesisError::Io(_))
    ));
}

#[test]
fn validator_conversion_preserves_members_and_owner_specific_diagnostics() {
    let expected_context: PublicationContext = context(0);
    let mut record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: expected_context.clone(),
        validators: vec![FastPathValidatorEntry {
            id: ValidatorId::new([0x11; 32]),
            voting_power: 7,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![0x22; 32],
        }],
    };
    let validator_set: ValidatorSet =
        validator_set_from_record(&record, &expected_context, "unsupported").unwrap();
    assert_eq!(validator_set.epoch(), expected_context.epoch());
    assert_eq!(
        validator_set.validators(),
        &[ValidatorInfo {
            id: record.validators[0].id,
            voting_power: record.validators[0].voting_power,
            signature_scheme: record.validators[0].signature_scheme,
            public_key: record.validators[0].public_key.clone(),
        }]
    );
    record.validators[0].signature_scheme = SignatureSchemeId::Secp256k1;
    assert_eq!(
        validator_set_from_record(&record, &context(1), "unsupported").unwrap_err(),
        "validator set record context mismatch"
    );
    for diagnostic in [
        "FastVote phase 1 supports only Ed25519 validators",
        "ordered economics fixed-epoch profile supports only Ed25519 validators",
    ] {
        assert_eq!(
            validator_set_from_record(&record, &expected_context, diagnostic).unwrap_err(),
            diagnostic
        );
    }
    record.validators[0].signature_scheme = SignatureSchemeId::Ed25519;
    record.validators[0].voting_power = 0;
    let error: String =
        validator_set_from_record(&record, &expected_context, "unsupported").unwrap_err();
    assert_eq!(
        error,
        validator_set::ValidatorSetError::ZeroVotingPower(record.validators[0].id).to_string()
    );
}
