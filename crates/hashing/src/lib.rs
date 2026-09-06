#![forbid(unsafe_code)]

//! Domain-separated hashing primitives and hash-suite resolution.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
    ProtocolVersion,
};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;
use std::{error::Error, fmt};

const HASH_DOMAIN_VERSION: u16 = 1;
const HASH_FRAME_ENCODING_VERSION: u16 = 1;
const HASH_FRAME_TYPE_ID: u16 = 0x1001;
/// Stable canonical type identifier for the type-identity hash frame. See
/// [`frame_type_identity_input`].
const TYPE_IDENTITY_FRAME_TYPE_ID: u16 = 0x1002;

/// Hashing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashingError {
    /// The requested hash algorithm is not currently implemented.
    UnsupportedAlgorithm(HashAlgorithmId),
    /// Canonical framing failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// The hash-suite schedule was empty.
    EmptySchedule,
    /// The schedule must start at epoch 0.
    MissingGenesisSuite,
    /// The schedule contains a non-monotonic epoch entry.
    NonMonotonicSchedule,
    /// No suite is active for the requested epoch.
    NoActiveHashSuite(Epoch),
    /// A type-identity digest named an algorithm that was never selected for
    /// the given purpose by any schedule entry active at or before the
    /// requested epoch. This is distinct from [`Self::UnsupportedAlgorithm`]:
    /// the algorithm may be fully implemented yet still untrusted for this
    /// epoch, for example because its schedule entry only activates later.
    UntrustedAlgorithmForEpoch {
        /// The algorithm recorded on the digest.
        algorithm: HashAlgorithmId,
        /// The purpose the digest was verified against.
        purpose: HashPurpose,
        /// The epoch the verification was performed at.
        epoch: Epoch,
    },
}

impl fmt::Display for HashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "unsupported hash algorithm: {algorithm}")
            }
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::EmptySchedule => write!(f, "hash-suite schedule must not be empty"),
            Self::MissingGenesisSuite => write!(f, "hash-suite schedule must start at epoch 0"),
            Self::NonMonotonicSchedule => {
                write!(f, "hash-suite schedule epochs must be strictly increasing")
            }
            Self::NoActiveHashSuite(epoch) => {
                write!(f, "no active hash suite for epoch {}", epoch.get())
            }
            Self::UntrustedAlgorithmForEpoch {
                algorithm,
                purpose,
                epoch,
            } => write!(
                f,
                "algorithm {algorithm} was never scheduled for {purpose:?} at or before epoch {}",
                epoch.get()
            ),
        }
    }
}

impl Error for HashingError {}

impl From<CanonicalEncodingError> for HashingError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// A hash function implementation.
pub trait HashFunction {
    /// Returns the algorithm identifier.
    fn algorithm_id(&self) -> HashAlgorithmId;

    /// Hashes a canonical payload inside the protocol domain-separation frame.
    fn hash(
        &self,
        purpose: HashPurpose,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        canonical_payload: &[u8],
    ) -> Result<Digest32, HashingError>;
}

/// Built-in protocol hash implementations.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinHashFunction {
    algorithm: HashAlgorithmId,
}

impl BuiltinHashFunction {
    /// Creates a built-in hash implementation.
    #[must_use]
    pub const fn new(algorithm: HashAlgorithmId) -> Self {
        Self { algorithm }
    }
}

impl HashFunction for BuiltinHashFunction {
    fn algorithm_id(&self) -> HashAlgorithmId {
        self.algorithm
    }

    fn hash(
        &self,
        purpose: HashPurpose,
        protocol_version: ProtocolVersion,
        chain_id: &ChainId,
        canonical_payload: &[u8],
    ) -> Result<Digest32, HashingError> {
        if matches!(self.algorithm, HashAlgorithmId::Blake3_256) {
            return Err(HashingError::UnsupportedAlgorithm(self.algorithm));
        }

        let frame = frame_hash_input(
            self.algorithm,
            purpose,
            protocol_version,
            chain_id,
            canonical_payload,
        )?;
        let bytes = hash_unframed_bytes(self.algorithm, &frame)?;
        Ok(Digest32::new(self.algorithm, bytes))
    }
}

/// Frames a hash input according to the canonical domain-separation rules.
pub fn frame_hash_input(
    algorithm: HashAlgorithmId,
    purpose: HashPurpose,
    protocol_version: ProtocolVersion,
    chain_id: &ChainId,
    canonical_payload: &[u8],
) -> Result<Vec<u8>, HashingError> {
    let mut frame = CanonicalStruct::new(HASH_FRAME_TYPE_ID, HASH_FRAME_ENCODING_VERSION);
    frame.field_u16(1, algorithm.as_u16())?;
    frame.field_u16(2, purpose.domain().as_u16())?;
    frame.field_u16(3, HASH_DOMAIN_VERSION)?;
    frame.field_str(4, chain_id.as_str())?;
    frame.field_u32(5, protocol_version.get())?;
    frame.field_bytes(6, canonical_payload)?;
    Ok(frame.finish()?)
}

/// Frames a canonical nominal type-tag payload for [`HashPurpose::ObjectType`].
///
/// This is a distinct frame from [`frame_hash_input`], not a specialization
/// of it: it deliberately excludes `protocol_version` (and never carries an
/// object's `schema_version`, since that lives inside `canonical_payload`'s
/// caller, not this frame) so that an object's nominal type identity survives
/// protocol upgrades and schema migrations. It still binds the algorithm, the
/// `ObjectType` domain and domain version, and the chain id, so type identity
/// remains chain- and algorithm-scoped like every other protocol digest.
pub fn frame_type_identity_input(
    algorithm: HashAlgorithmId,
    chain_id: &ChainId,
    canonical_type_tag_payload: &[u8],
) -> Result<Vec<u8>, HashingError> {
    let mut frame = CanonicalStruct::new(TYPE_IDENTITY_FRAME_TYPE_ID, HASH_FRAME_ENCODING_VERSION);
    frame.field_u16(1, algorithm.as_u16())?;
    frame.field_u16(2, HashPurpose::ObjectType.domain().as_u16())?;
    frame.field_u16(3, HASH_DOMAIN_VERSION)?;
    frame.field_str(4, chain_id.as_str())?;
    frame.field_bytes(5, canonical_type_tag_payload)?;
    Ok(frame.finish()?)
}

/// Derives a nominal object-type identity digest for a canonical type-tag
/// payload, using the hash-suite resolver's currently active
/// [`HashPurpose::ObjectType`] algorithm at `epoch`.
pub fn hash_type_identity(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    canonical_type_tag_payload: &[u8],
) -> Result<Digest32, HashingError> {
    let suite = resolver.suite_for_epoch(epoch)?;
    let algorithm = suite.algorithm_for(HashPurpose::ObjectType);
    let frame =
        frame_type_identity_input(algorithm, resolver.chain_id(), canonical_type_tag_payload)?;
    let bytes = hash_unframed_bytes(algorithm, &frame)?;
    Ok(Digest32::new(algorithm, bytes))
}

/// Verifies a nominal object-type identity digest using the digest's own
/// recorded algorithm.
///
/// Fails closed unless that algorithm is both implemented (see
/// [`hash_unframed_bytes`]) and was selected for
/// [`HashPurpose::ObjectType`] by some schedule entry active at or before
/// `epoch` in `resolver`'s trusted history
/// ([`HashSuiteResolver::is_algorithm_trusted_for_purpose`]). This is
/// stricter than [`verify_digest`], which trusts any digest-recorded
/// algorithm unconditionally; type identity additionally must not let a
/// caller mint a digest under an algorithm the schedule has not yet (or
/// never) activated for this purpose.
pub fn verify_type_identity_digest(
    resolver: &HashSuiteResolver,
    digest: &Digest32,
    epoch: Epoch,
    canonical_type_tag_payload: &[u8],
) -> Result<bool, HashingError> {
    let algorithm = digest.algorithm();
    if !resolver.is_algorithm_trusted_for_purpose(HashPurpose::ObjectType, epoch, algorithm) {
        return Err(HashingError::UntrustedAlgorithmForEpoch {
            algorithm,
            purpose: HashPurpose::ObjectType,
            epoch,
        });
    }
    let frame =
        frame_type_identity_input(algorithm, resolver.chain_id(), canonical_type_tag_payload)?;
    let computed = hash_unframed_bytes(algorithm, &frame)?;
    Ok(computed == digest.bytes())
}

/// Verifies a digest using the algorithm recorded in the digest itself.
pub fn verify_digest(
    digest: &Digest32,
    purpose: HashPurpose,
    protocol_version: ProtocolVersion,
    chain_id: &ChainId,
    canonical_payload: &[u8],
) -> Result<bool, HashingError> {
    let computed = BuiltinHashFunction::new(digest.algorithm()).hash(
        purpose,
        protocol_version,
        chain_id,
        canonical_payload,
    )?;
    Ok(computed == *digest)
}

/// Resolves the active hash suite for a `(chain_id, protocol_version, epoch)` tuple.
#[derive(Debug, Clone)]
pub struct HashSuiteResolver {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    schedules: Vec<HashSuiteSchedule>,
}

impl HashSuiteResolver {
    /// Creates a validated hash-suite resolver.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        schedules: Vec<HashSuiteSchedule>,
    ) -> Result<Self, HashingError> {
        if schedules.is_empty() {
            return Err(HashingError::EmptySchedule);
        }
        if schedules.first().map(|entry| entry.activation_epoch.get()) != Some(0) {
            return Err(HashingError::MissingGenesisSuite);
        }
        if schedules
            .windows(2)
            .any(|pair| pair[0].activation_epoch >= pair[1].activation_epoch)
        {
            return Err(HashingError::NonMonotonicSchedule);
        }

        Ok(Self {
            chain_id,
            protocol_version,
            schedules,
        })
    }

    /// Returns the active suite for an epoch.
    pub fn suite_for_epoch(&self, epoch: Epoch) -> Result<&HashSuite, HashingError> {
        self.schedules
            .iter()
            .rev()
            .find(|entry| entry.activation_epoch <= epoch)
            .map(|entry| &entry.suite)
            .ok_or(HashingError::NoActiveHashSuite(epoch))
    }

    /// Returns the chain context bound to this resolver.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the protocol version bound to this resolver.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns whether `algorithm` was selected for `purpose` by some
    /// schedule entry active at or before `epoch`.
    ///
    /// A future, not-yet-activated schedule entry never makes an algorithm
    /// trusted early: only entries with `activation_epoch <= epoch`
    /// contribute. This bounds which algorithms a verifier accepts for a
    /// given epoch to the resolver's own historical schedule, rather than
    /// trusting whatever algorithm a digest happens to name.
    #[must_use]
    pub fn is_algorithm_trusted_for_purpose(
        &self,
        purpose: HashPurpose,
        epoch: Epoch,
        algorithm: HashAlgorithmId,
    ) -> bool {
        self.schedules
            .iter()
            .filter(|entry| entry.activation_epoch <= epoch)
            .any(|entry| entry.suite.algorithm_for(purpose) == algorithm)
    }

    /// Hashes a canonical payload for the given purpose and epoch.
    pub fn hash_for_purpose(
        &self,
        epoch: Epoch,
        purpose: HashPurpose,
        canonical_payload: &[u8],
    ) -> Result<Digest32, HashingError> {
        let suite = self.suite_for_epoch(epoch)?;
        let algorithm = suite.algorithm_for(purpose);
        BuiltinHashFunction::new(algorithm).hash(
            purpose,
            self.protocol_version,
            &self.chain_id,
            canonical_payload,
        )
    }
}

fn hash_unframed_bytes(algorithm: HashAlgorithmId, input: &[u8]) -> Result<[u8; 32], HashingError> {
    match algorithm {
        HashAlgorithmId::Sha2_256 => Ok(Sha256::digest(input).into()),
        HashAlgorithmId::Sha3_256 => Ok(Sha3_256::digest(input).into()),
        HashAlgorithmId::Blake3_256 => Err(HashingError::UnsupportedAlgorithm(algorithm)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashSuiteId, TypeError};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sample_resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(500),
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn sha256_vector_matches_reference() {
        assert_eq!(
            hex(&hash_unframed_bytes(HashAlgorithmId::Sha2_256, b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha3_vector_matches_reference() {
        assert_eq!(
            hex(&hash_unframed_bytes(HashAlgorithmId::Sha3_256, b"abc").unwrap()),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn cross_domain_hashes_differ() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let version = ProtocolVersion::new(7);

        let transaction = hasher
            .hash(HashPurpose::Transaction, version, &chain_id, b"payload")
            .unwrap();
        let object = hasher
            .hash(HashPurpose::Object, version, &chain_id, b"payload")
            .unwrap();

        assert_ne!(transaction, object);
    }

    #[test]
    fn cross_chain_hashes_differ() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
        let version = ProtocolVersion::new(7);

        let left = hasher
            .hash(
                HashPurpose::Transaction,
                version,
                &ChainId::new("chain-a").unwrap(),
                b"payload",
            )
            .unwrap();
        let right = hasher
            .hash(
                HashPurpose::Transaction,
                version,
                &ChainId::new("chain-b").unwrap(),
                b"payload",
            )
            .unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn cross_protocol_version_hashes_differ() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
        let chain_id = ChainId::new("sunrise-devnet").unwrap();

        let left = hasher
            .hash(
                HashPurpose::Transaction,
                ProtocolVersion::new(1),
                &chain_id,
                b"payload",
            )
            .unwrap();
        let right = hasher
            .hash(
                HashPurpose::Transaction,
                ProtocolVersion::new(2),
                &chain_id,
                b"payload",
            )
            .unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn old_digest_verifies_after_suite_transition() {
        let resolver = sample_resolver();
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let digest = resolver
            .hash_for_purpose(Epoch::new(42), HashPurpose::Object, b"object-v1")
            .unwrap();

        assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
        assert!(
            verify_digest(
                &digest,
                HashPurpose::Object,
                ProtocolVersion::new(1),
                &chain_id,
                b"object-v1"
            )
            .unwrap()
        );
    }

    #[test]
    fn hash_suite_epoch_transition_activates_new_algorithm() {
        let resolver = sample_resolver();

        let before = resolver.suite_for_epoch(Epoch::new(499)).unwrap();
        let after = resolver.suite_for_epoch(Epoch::new(500)).unwrap();

        assert_eq!(
            before.algorithm_for(HashPurpose::Transaction),
            HashAlgorithmId::Sha2_256
        );
        assert_eq!(
            after.algorithm_for(HashPurpose::Transaction),
            HashAlgorithmId::Sha3_256
        );
    }

    #[test]
    fn unsupported_algorithms_fail_without_fallback() {
        let hasher = BuiltinHashFunction::new(HashAlgorithmId::Blake3_256);
        let result = hasher.hash(
            HashPurpose::Transaction,
            ProtocolVersion::new(1),
            &ChainId::new("sunrise-devnet").unwrap(),
            b"payload",
        );

        assert_eq!(
            result,
            Err(HashingError::UnsupportedAlgorithm(
                HashAlgorithmId::Blake3_256
            ))
        );
    }

    #[test]
    fn invalid_schedule_is_rejected() {
        let err = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(1),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap_err();

        assert_eq!(err, HashingError::MissingGenesisSuite);
    }

    #[test]
    fn unknown_algorithm_ids_are_rejected_upstream() {
        assert_eq!(
            HashAlgorithmId::try_from(99),
            Err(TypeError::UnknownHashAlgorithmId(99))
        );
    }

    #[test]
    fn type_identity_frame_vector_is_stable() {
        let chain_id = ChainId::new("sunrise-devnet").unwrap();
        let bytes =
            frame_type_identity_input(HashAlgorithmId::Sha2_256, &chain_id, b"type-tag").unwrap();

        assert_eq!(
            hex(&bytes),
            "534e524502100100050001000200000001000200020000000f00030002000000010004000e00000073756e726973652d6465766e6574050008000000747970652d746167"
        );
    }

    #[test]
    fn type_identity_digest_is_stable_and_round_trips() {
        let resolver = sample_resolver();
        let digest = hash_type_identity(&resolver, Epoch::new(0), b"type-tag").unwrap();

        assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
        assert_eq!(
            hex(&digest.bytes()),
            "017b752dda4ca7abf5dfca9e73c210a107593a4fd6f2780d265bdaf19e2c27da"
        );
        assert_eq!(
            verify_type_identity_digest(&resolver, &digest, Epoch::new(0), b"type-tag"),
            Ok(true)
        );
    }

    #[test]
    fn type_identity_digest_excludes_protocol_version() {
        let payload = b"type-tag";

        let resolver_v1 = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let resolver_v2 = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(2),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();

        let left = hash_type_identity(&resolver_v1, Epoch::new(0), payload).unwrap();
        let right = hash_type_identity(&resolver_v2, Epoch::new(0), payload).unwrap();

        assert_eq!(left, right);
    }

    #[test]
    fn type_identity_digest_changes_with_chain_and_payload() {
        let payload = b"type-tag";

        let chain_a = hash_type_identity(
            &HashSuiteResolver::new(
                ChainId::new("chain-a").unwrap(),
                ProtocolVersion::new(1),
                vec![HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                }],
            )
            .unwrap(),
            Epoch::new(0),
            payload,
        )
        .unwrap();
        let chain_b = hash_type_identity(
            &HashSuiteResolver::new(
                ChainId::new("chain-b").unwrap(),
                ProtocolVersion::new(1),
                vec![HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                }],
            )
            .unwrap(),
            Epoch::new(0),
            payload,
        )
        .unwrap();
        assert_ne!(chain_a, chain_b);

        let resolver = sample_resolver();
        let left = hash_type_identity(&resolver, Epoch::new(0), b"type-tag-a").unwrap();
        let right = hash_type_identity(&resolver, Epoch::new(0), b"type-tag-b").unwrap();
        assert_ne!(left, right);
    }

    #[test]
    fn type_identity_survives_hash_suite_rotation_for_old_digests() {
        let resolver = sample_resolver();
        let digest = hash_type_identity(&resolver, Epoch::new(42), b"type-tag").unwrap();
        assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);

        // The digest still verifies at a later epoch even though the active
        // suite has since rotated to a different algorithm, because
        // verification uses the digest's own recorded algorithm.
        assert_eq!(
            verify_type_identity_digest(&resolver, &digest, Epoch::new(600), b"type-tag"),
            Ok(true)
        );
    }

    #[test]
    fn type_identity_verification_fails_closed_for_unimplemented_algorithm() {
        let resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Blake3_256),
            }],
        )
        .unwrap();
        let forged_digest = Digest32::new(HashAlgorithmId::Blake3_256, [0u8; 32]);

        assert_eq!(
            verify_type_identity_digest(&resolver, &forged_digest, Epoch::new(0), b"type-tag"),
            Err(HashingError::UnsupportedAlgorithm(
                HashAlgorithmId::Blake3_256
            ))
        );
    }

    #[test]
    fn type_identity_verification_fails_closed_for_out_of_schedule_algorithm() {
        // SHA3-256 only becomes trusted for `ObjectType` at epoch 500; a
        // digest computed with SHA3-256 must not verify before that epoch
        // even though the algorithm itself is fully implemented.
        let resolver = sample_resolver();
        let early_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha3_256)
            .hash(
                HashPurpose::Object,
                resolver.protocol_version(),
                resolver.chain_id(),
                b"unused",
            )
            .unwrap();
        let forged_digest = Digest32::new(HashAlgorithmId::Sha3_256, early_digest.bytes());

        assert_eq!(
            verify_type_identity_digest(&resolver, &forged_digest, Epoch::new(499), b"type-tag"),
            Err(HashingError::UntrustedAlgorithmForEpoch {
                algorithm: HashAlgorithmId::Sha3_256,
                purpose: HashPurpose::ObjectType,
                epoch: Epoch::new(499),
            })
        );

        // The same algorithm becomes trusted once the schedule activates.
        let digest_at_rotation =
            hash_type_identity(&resolver, Epoch::new(500), b"type-tag").unwrap();
        assert_eq!(digest_at_rotation.algorithm(), HashAlgorithmId::Sha3_256);
        assert_eq!(
            verify_type_identity_digest(
                &resolver,
                &digest_at_rotation,
                Epoch::new(500),
                b"type-tag"
            ),
            Ok(true)
        );
    }

    #[test]
    fn type_identity_verification_rejects_tampered_payload() {
        let resolver = sample_resolver();
        let digest = hash_type_identity(&resolver, Epoch::new(0), b"type-tag").unwrap();

        assert_eq!(
            verify_type_identity_digest(&resolver, &digest, Epoch::new(0), b"different-tag"),
            Ok(false)
        );
    }
}
