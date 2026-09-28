//! Canonical v2 full-certificate publication bundle (DR-0154 /
//! `epoch-handoff.md`, "Execution-free publication").
//!
//! The accepted design requires the publication input to be "a versioned,
//! canonical bundle, not a certificate plus a caller-chosen list of hashes":
//! it carries the original signed intent, exactly one verifying full
//! [`crate::FastCertificate`], the exact logical commitment witness, and a
//! **closed** manifest of the bytes needed to replay that witness, together
//! with those actual bytes. This module owns that wire family and the
//! stateless verification that turns one bundle into the single
//! [`AvailabilityIdentity`] a retainer may later acknowledge.
//!
//! # What this module proves, and what it deliberately does not
//!
//! [`verify_publication_bundle`] proves, for the bundle it is given:
//!
//! * The carried [`crate::FastCertificate`] is a real quorum certificate of
//!   the caller's registered outgoing set at the exact
//!   `(chain_id, protocol_version, epoch)` the certifier is bound to.
//! * The carried commitment witness bytes hash, under the epoch's committed
//!   [`hashing::HashSuite`] and the existing `HashPurpose::ExecutionEffects`
//!   domain, to exactly that certificate's `execution_effects_hash`. The
//!   quorum therefore attests to the exact witness carried here, not merely
//!   to a hash the caller also supplied.
//! * The manifest is strictly ordered by `(kind, identity)`, duplicate-free
//!   and bounded, and every declared entry has exactly one supplied content
//!   value whose length and content digest match the entry under the hash
//!   purpose that entry's kind fixes. A hash alone is never accepted as
//!   retention: the bytes are present and verified here.
//! * The derived [`AvailabilityIdentity`] depends only on the certificate's
//!   *header* fields, the declared domain/request identity and the manifest
//!   digest -- never on which quorum subset signed. Two bundles carrying
//!   equivalent valid signer subsets for the same operation therefore derive
//!   one identical logical identity, exactly as `epoch-handoff.md` requires
//!   ("Equivalent valid `FastCertificate` signer subsets denote one
//!   operation, not two effects").
//!
//! It deliberately does **not** prove:
//!
//! * That `signed_intent` is the preimage of the certificate's `tx_hash`.
//!   Deriving a signed intent's event digest is `node_core`'s authentication
//!   pipeline, not this crate's; a bundle consumer in `node_core` must
//!   re-derive that digest from these exact bytes and require equality with
//!   `certificate.tx_hash` before retaining anything. This module returns the
//!   intent bytes verbatim and says so rather than implying a binding it
//!   cannot check.
//! * That the manifest is *closed* with respect to the witness. Closure is a
//!   statement about the `0x6424/v2` commitment envelope's signed read,
//!   object and mutation operands, whose encoding belongs to `node_core`.
//!   This module checks the manifest's internal canonical form and content;
//!   the retainer independently derives the required artifact set from the
//!   witness and requires set equality before an ACK.
//! * Anything about durability, apply admission, freeze/drain/seal
//!   sequencing or ingress. Verifying a bundle exposes no signature and
//!   retains nothing.
//!
//! # Allocated identifiers
//!
//! `0xD033/v1` [`ArtifactEntry`], `0xD034/v1` [`ArtifactManifest`] and
//! `0xD035/v1` [`PublicationBundle`], allocated after a repository-wide sweep
//! of every four-hex-digit identifier. No historical identifier or byte
//! encoding changes; the `0x6424/v1` physical commitment envelope and its
//! historical certificates remain exactly as they were, and a bundle whose
//! declared commitment profile is not the handoff-capable v2 profile is
//! refused rather than downgraded.
//!
//! # Bounds
//!
//! One bundle is one canonical frame and therefore fits
//! [`MAX_ENCODED_BUNDLE_BYTES`]. Bounded, resumable multi-chunk transfer of a
//! single operation larger than one frame is a separate DrainSet-stage
//! contract in DR-0154 and is **not** implemented here; a bundle that does
//! not fit is refused, never truncated.

use super::{
    AvailabilityIdentity, ensure_chain_id_bound, ensure_encoded_bound, ensure_request_id_nonzero,
};
use crate::{ConsensusError, ConsensusVerifier, FastCertificate, FastPathCertifier};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, MAX_CANONICAL_FRAME_BYTES, decode_canonical_frame,
    decode_digest32, encode_digest32,
};
use hashing::HashSuiteResolver;
use protocol_types::{AtomicityDomainId, Digest32, HashPurpose};

const ARTIFACT_ENTRY_TYPE_ID: u16 = 0xD033;
const ARTIFACT_MANIFEST_TYPE_ID: u16 = 0xD034;
const PUBLICATION_BUNDLE_TYPE_ID: u16 = 0xD035;
const ENCODING_VERSION: u16 = 1;

/// The only commitment-witness profile this bundle family accepts: the
/// handoff-capable `0x6424/v2` logical envelope, which signs semantic
/// observations and the authenticated execution generation and signs no
/// physical revision or creation checkpoint.
///
/// A `0x6424/v1` historical witness signs per-node physical coordinates and
/// is therefore not portable replay material. Historical v1 certificates and
/// their bytes stay verifiable under their own original rules; they are
/// simply never admissible as a publication bundle. This value is checked
/// explicitly so an unknown or downgraded profile fails closed instead of
/// being silently reinterpreted.
pub const LOGICAL_COMMITMENT_PROFILE: u16 = 2;

/// Upper bound on manifest entries in one bundle.
///
/// One operation's required artifacts are derived from the witness's three
/// attacker-irrelevant but admission-bounded operand lists -- generic state
/// reads, durable object head reads and durable object mutations -- each of
/// which `node_core::fast_path::commitment` already caps at 4,096 entries
/// (itself matching the runtime's `MAX_ATOMIC_STATE_READS` /
/// `MAX_ATOMIC_STATE_WRITES` / `MAX_DURABLE_OBJECT_*` ceilings). Three full
/// lists is therefore the largest closure a successfully admitted operation
/// can possibly require.
pub const MAX_ARTIFACT_MANIFEST_ENTRIES: usize = 3 * 4_096;

/// Upper bound on one manifest entry's identity bytes.
///
/// The widest identity is a generic transactional state key, which the
/// runtime independently bounds at `MAX_STATE_KEY_BYTES` (4 KiB). `consensus`
/// must not depend on `runtime`, so the value is restated here; a longer
/// identity is refused rather than truncated.
pub const MAX_ARTIFACT_IDENTITY_BYTES: usize = 4 * 1024;

/// Upper bound on one artifact's content bytes, matching the runtime's own
/// `MAX_STATE_VALUE_BYTES` / `MAX_DURABLE_INLINE_OBJECT_BYTES` ceiling. The
/// enclosing canonical frame bound ([`MAX_ENCODED_BUNDLE_BYTES`]) is the
/// binding constraint in practice.
pub const MAX_ARTIFACT_CONTENT_BYTES: usize = 32 * 1024 * 1024;

/// Upper bound on the carried original signed intent.
///
/// The largest legal paid application is a `Publish`, which
/// `execution::paid_execution::MAX_PUBLISH_APPLICATION_BYTES` caps at 5 MiB
/// plus 64 bytes; this leaves generous headroom for the signed envelope
/// around it without `consensus` depending on `execution`.
pub const MAX_SIGNED_INTENT_BYTES: usize = 8 * 1024 * 1024;

/// Upper bound on the carried `0x6424/v2` commitment witness envelope, which
/// embeds the canonical paid execution result and every signed operand list.
pub const MAX_COMMITMENT_WITNESS_BYTES: usize = 32 * 1024 * 1024;

/// Upper bound on one encoded [`ArtifactManifest`].
pub const MAX_ENCODED_MANIFEST_BYTES: usize = MAX_CANONICAL_FRAME_BYTES;

/// Upper bound on one encoded [`PublicationBundle`]: one canonical frame.
pub const MAX_ENCODED_BUNDLE_BYTES: usize = MAX_CANONICAL_FRAME_BYTES;

/// Which replay artifact one manifest entry names, and therefore which
/// existing hash domain its content digest was produced under.
///
/// Closed on purpose: an unknown discriminant is a typed refusal
/// ([`PublicationBundleError::UnknownArtifactKind`]), never an artifact
/// verified under a caller-chosen domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactKind {
    /// The exact canonical bytes of one generic transactional state value.
    ///
    /// Identity is the state key verbatim. The content digest is produced
    /// under `HashPurpose::ExecutionEffects`, matching the digest
    /// `node_core`'s logical `StatePresent` read observation already signs,
    /// so a verified artifact is byte-identical to what the quorum attested.
    StateValue,
    /// The exact canonical body bytes of one immutable durable object
    /// version, whether the producing replica stored them inline or behind a
    /// content-addressed blob reference.
    ///
    /// Identity is the 32-byte object id followed by the big-endian object
    /// version. The content digest is produced under `HashPurpose::Object`,
    /// matching the object digest every durable object version record and
    /// blob reference already carries.
    ObjectBody,
}

impl ArtifactKind {
    const STATE_VALUE_TAG: u16 = 1;
    const OBJECT_BODY_TAG: u16 = 2;

    /// Returns the stable wire discriminant.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::StateValue => Self::STATE_VALUE_TAG,
            Self::ObjectBody => Self::OBJECT_BODY_TAG,
        }
    }

    /// Decodes a wire discriminant, failing closed on any other value.
    pub const fn from_u16(tag: u16) -> Result<Self, PublicationBundleError> {
        match tag {
            Self::STATE_VALUE_TAG => Ok(Self::StateValue),
            Self::OBJECT_BODY_TAG => Ok(Self::ObjectBody),
            other => Err(PublicationBundleError::UnknownArtifactKind(other)),
        }
    }

    /// Returns the existing hash domain this kind's content digest is
    /// produced under. No new hash purpose, suite or primitive is introduced.
    #[must_use]
    pub const fn hash_purpose(self) -> HashPurpose {
        match self {
            Self::StateValue => HashPurpose::ExecutionEffects,
            Self::ObjectBody => HashPurpose::Object,
        }
    }
}

/// One declared replay artifact: what it is, which bytes it must be, and how
/// many of them there are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactEntry {
    /// Which artifact family this entry names.
    pub kind: ArtifactKind,
    /// Exact, bounded, non-empty logical identity within `kind`.
    pub identity: Vec<u8>,
    /// Content digest of the exact bytes, under `kind`'s hash purpose.
    pub content_digest: Digest32,
    /// Exact byte length of the content, declared separately so a length
    /// disagreement is caught before any hashing work.
    pub content_length: u32,
}

/// The closed, canonically ordered set of artifacts one witness needs to be
/// replayed.
///
/// "Canonically ordered" means strictly ascending by `(kind, identity)` with
/// no duplicate `(kind, identity)` pair, so one required artifact set has
/// exactly one encoding and therefore exactly one manifest digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactManifest {
    /// Strictly ascending, duplicate-free entries.
    pub entries: Vec<ArtifactEntry>,
}

/// The complete publication input for one operation.
///
/// Field-for-field this is `epoch-handoff.md`'s requirement: the original
/// signed intent, one verifying full certificate, the exact logical
/// commitment witness, a closed artifact manifest, and the actual content
/// bytes -- never a certificate plus a caller-chosen list of hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationBundle {
    /// Logical atomicity domain the operation belongs to.
    pub domain: AtomicityDomainId,
    /// Original request identity, re-derived and checked by the retainer
    /// against `signed_intent`.
    pub request_id: [u8; 32],
    /// Commitment-witness profile; only [`LOGICAL_COMMITMENT_PROFILE`] is
    /// accepted.
    pub commitment_profile: u16,
    /// Exact original signed intent bytes.
    pub signed_intent: Vec<u8>,
    /// Exactly one full verifying certificate. Its signer subset is audit
    /// material; it never enters the derived identity.
    pub certificate: FastCertificate,
    /// Exact `0x6424/v2` logical commitment witness envelope bytes.
    pub witness: Vec<u8>,
    /// Closed, canonically ordered artifact manifest.
    pub manifest: ArtifactManifest,
    /// One content value per manifest entry, in the manifest's own order.
    pub contents: Vec<Vec<u8>>,
}

/// Everything [`verify_publication_bundle`] established, returned together so
/// a caller cannot hold a verified identity without the bytes it was derived
/// from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPublicationBundle {
    /// The single logical identity this bundle denotes, independent of which
    /// valid quorum subset signed the carried certificate.
    pub identity: AvailabilityIdentity,
    /// Digest of the canonical manifest encoding, equal to
    /// `identity.semantic_artifacts_digest`.
    pub manifest_digest: Digest32,
}

/// Typed, actionable failures of this bundle family.
///
/// `consensus`'s shared [`ConsensusError`] is owned by the crate root and is
/// not extended here; bundle-specific conditions get their own variants and
/// shared consensus failures are wrapped verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationBundleError {
    /// A shared consensus check (context, quorum, signature, canonical
    /// framing, hashing) failed.
    Consensus(ConsensusError),
    /// The declared commitment-witness profile is not the handoff-capable
    /// logical profile.
    UnsupportedCommitmentProfile {
        /// The only accepted profile.
        expected: u16,
        /// What the bundle declared.
        actual: u16,
    },
    /// A manifest entry named an artifact family outside the closed schema.
    UnknownArtifactKind(u16),
    /// Manifest entries are not strictly ascending by `(kind, identity)`, or
    /// repeat an identity.
    NonCanonicalManifestOrder,
    /// Too many manifest entries.
    ManifestTooLarge {
        /// Declared or present entry count.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// A manifest entry's identity is empty or too long.
    InvalidArtifactIdentity {
        /// Index within the manifest.
        index: usize,
        /// Observed identity length.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// The number of supplied content values differs from the number of
    /// declared manifest entries.
    ContentCountMismatch {
        /// Declared entries.
        entries: usize,
        /// Supplied contents.
        contents: usize,
    },
    /// One artifact's actual byte length differs from its declared length.
    ArtifactLengthMismatch {
        /// Index within the manifest.
        index: usize,
        /// Length the manifest declared.
        declared: u32,
        /// Length actually supplied.
        actual: usize,
    },
    /// One artifact's content does not hash to its declared content digest
    /// under its kind's hash purpose.
    ArtifactContentDigestMismatch {
        /// Index within the manifest.
        index: usize,
    },
    /// One artifact's content exceeds [`MAX_ARTIFACT_CONTENT_BYTES`].
    ArtifactContentTooLarge {
        /// Index within the manifest.
        index: usize,
        /// Observed length.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// The carried signed intent is empty or exceeds
    /// [`MAX_SIGNED_INTENT_BYTES`].
    InvalidSignedIntentLength {
        /// Observed length.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// The carried witness is empty or exceeds
    /// [`MAX_COMMITMENT_WITNESS_BYTES`].
    InvalidWitnessLength {
        /// Observed length.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// The carried witness does not hash to the certificate's
    /// `execution_effects_hash`: the quorum did not attest to these bytes.
    WitnessCommitmentMismatch,
    /// An encoded bundle, manifest or entry exceeded its explicit bound.
    EncodedFrameTooLarge {
        /// Which frame.
        kind: &'static str,
        /// Observed length.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// Re-encoding a decoded value did not reproduce the input bytes.
    NonCanonicalEncoding {
        /// Which frame.
        kind: &'static str,
    },
    /// A length or count computation would overflow.
    ArithmeticOverflow,
}

impl From<ConsensusError> for PublicationBundleError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<canonical_encoding::CanonicalEncodingError> for PublicationBundleError {
    fn from(error: canonical_encoding::CanonicalEncodingError) -> Self {
        Self::Consensus(ConsensusError::CanonicalEncoding(error))
    }
}

impl From<CanonicalDecodingError> for PublicationBundleError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Consensus(ConsensusError::CanonicalDecoding(error))
    }
}

impl From<hashing::HashingError> for PublicationBundleError {
    fn from(error: hashing::HashingError) -> Self {
        Self::Consensus(ConsensusError::Hashing(error))
    }
}

impl core::fmt::Display for PublicationBundleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Consensus(error) => write!(formatter, "{error}"),
            Self::UnsupportedCommitmentProfile { expected, actual } => write!(
                formatter,
                "publication bundle commitment profile {actual} is not the supported profile {expected}"
            ),
            Self::UnknownArtifactKind(tag) => {
                write!(formatter, "unknown publication artifact kind {tag}")
            }
            Self::NonCanonicalManifestOrder => {
                formatter.write_str("publication artifact manifest is misordered or duplicated")
            }
            Self::ManifestTooLarge { actual, max } => write!(
                formatter,
                "publication artifact manifest has {actual} entries, maximum is {max}"
            ),
            Self::InvalidArtifactIdentity { index, actual, max } => write!(
                formatter,
                "publication artifact {index} identity is {actual} bytes, must be 1..={max}"
            ),
            Self::ContentCountMismatch { entries, contents } => write!(
                formatter,
                "publication bundle declares {entries} artifacts but supplies {contents} contents"
            ),
            Self::ArtifactLengthMismatch {
                index,
                declared,
                actual,
            } => write!(
                formatter,
                "publication artifact {index} declares {declared} bytes but supplies {actual}"
            ),
            Self::ArtifactContentDigestMismatch { index } => write!(
                formatter,
                "publication artifact {index} content does not match its declared digest"
            ),
            Self::ArtifactContentTooLarge { index, actual, max } => write!(
                formatter,
                "publication artifact {index} content is {actual} bytes, maximum is {max}"
            ),
            Self::InvalidSignedIntentLength { actual, max } => write!(
                formatter,
                "publication bundle signed intent is {actual} bytes, must be 1..={max}"
            ),
            Self::InvalidWitnessLength { actual, max } => write!(
                formatter,
                "publication bundle commitment witness is {actual} bytes, must be 1..={max}"
            ),
            Self::WitnessCommitmentMismatch => formatter.write_str(
                "publication bundle witness does not hash to the certificate execution commitment",
            ),
            Self::EncodedFrameTooLarge { kind, actual, max } => {
                write!(formatter, "{kind} is {actual} bytes, maximum is {max}")
            }
            Self::NonCanonicalEncoding { kind } => write!(formatter, "noncanonical {kind}"),
            Self::ArithmeticOverflow => {
                formatter.write_str("publication bundle length arithmetic overflowed")
            }
        }
    }
}

impl std::error::Error for PublicationBundleError {}

/// Orders one entry exactly as the canonical manifest order requires.
fn entry_order_key(entry: &ArtifactEntry) -> (u16, &[u8]) {
    (entry.kind.as_u16(), entry.identity.as_slice())
}

fn bound(kind: &'static str, actual: usize, max: usize) -> Result<(), PublicationBundleError> {
    if actual > max {
        return Err(PublicationBundleError::EncodedFrameTooLarge { kind, actual, max });
    }
    Ok(())
}

/// Validates one entry's own bounds in isolation.
fn validate_entry(index: usize, entry: &ArtifactEntry) -> Result<(), PublicationBundleError> {
    if entry.identity.is_empty() || entry.identity.len() > MAX_ARTIFACT_IDENTITY_BYTES {
        return Err(PublicationBundleError::InvalidArtifactIdentity {
            index,
            actual: entry.identity.len(),
            max: MAX_ARTIFACT_IDENTITY_BYTES,
        });
    }
    let declared: usize = usize::try_from(entry.content_length)
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
    if declared > MAX_ARTIFACT_CONTENT_BYTES {
        return Err(PublicationBundleError::ArtifactContentTooLarge {
            index,
            actual: declared,
            max: MAX_ARTIFACT_CONTENT_BYTES,
        });
    }
    Ok(())
}

/// Validates a whole manifest's count, per-entry bounds and strict canonical
/// order before any encoding, hashing or content work.
pub fn validate_manifest(manifest: &ArtifactManifest) -> Result<(), PublicationBundleError> {
    if manifest.entries.len() > MAX_ARTIFACT_MANIFEST_ENTRIES {
        return Err(PublicationBundleError::ManifestTooLarge {
            actual: manifest.entries.len(),
            max: MAX_ARTIFACT_MANIFEST_ENTRIES,
        });
    }
    let mut previous: Option<(u16, &[u8])> = None;
    for (index, entry) in manifest.entries.iter().enumerate() {
        validate_entry(index, entry)?;
        let current: (u16, &[u8]) = entry_order_key(entry);
        if previous.is_some_and(|seen| seen >= current) {
            return Err(PublicationBundleError::NonCanonicalManifestOrder);
        }
        previous = Some(current);
    }
    Ok(())
}

/// Encodes one [`ArtifactEntry`] (`0xD033/v1`).
pub fn encode_artifact_entry(entry: &ArtifactEntry) -> Result<Vec<u8>, PublicationBundleError> {
    validate_entry(0, entry)?;
    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(ARTIFACT_ENTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, entry.kind.as_u16())?;
    canonical.field_bytes(2, entry.identity.clone())?;
    canonical.field_bytes(3, encode_digest32(&entry.content_digest)?)?;
    canonical.field_u32(4, entry.content_length)?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one [`ArtifactEntry`].
pub fn decode_artifact_entry(input: &[u8]) -> Result<ArtifactEntry, PublicationBundleError> {
    bound(
        "publication artifact entry",
        input.len(),
        // A single entry is a fixed header plus one bounded identity and one
        // Digest32 frame; this ceiling is generous and checked before any
        // parsing allocation.
        MAX_ARTIFACT_IDENTITY_BYTES + 512,
    )?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(ARTIFACT_ENTRY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;

    let kind: ArtifactKind = ArtifactKind::from_u16(frame.required_u16(1)?)?;
    let identity: Vec<u8> = frame.required_field(2)?.to_vec();
    let content_digest: Digest32 = decode_digest32(frame.required_field(3)?)?;
    let content_length: u32 = frame.required_u32(4)?;

    let entry: ArtifactEntry = ArtifactEntry {
        kind,
        identity,
        content_digest,
        content_length,
    };
    validate_entry(0, &entry)?;
    if encode_artifact_entry(&entry)?.as_slice() != input {
        return Err(PublicationBundleError::NonCanonicalEncoding {
            kind: "publication artifact entry",
        });
    }
    Ok(entry)
}

/// Encodes one [`ArtifactManifest`] (`0xD034/v1`), refusing a misordered,
/// duplicated or over-bound manifest before any field is written.
///
/// The digest of these bytes is the `semantic_artifacts_digest` an
/// [`AvailabilityIdentity`] signs.
pub fn encode_artifact_manifest(
    manifest: &ArtifactManifest,
) -> Result<Vec<u8>, PublicationBundleError> {
    validate_manifest(manifest)?;
    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(ARTIFACT_MANIFEST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(manifest.entries.len())
            .map_err(|_| PublicationBundleError::ArithmeticOverflow)?,
    )?;
    for (index, entry) in manifest.entries.iter().enumerate() {
        let field: u16 = u16::try_from(
            index
                .checked_add(2)
                .ok_or(PublicationBundleError::ArithmeticOverflow)?,
        )
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
        canonical.field_bytes(field, encode_artifact_entry(entry)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one [`ArtifactManifest`].
///
/// The declared entry count is bounded *before* any nested entry is decoded,
/// must agree exactly with the fields present, and the decoded manifest must
/// re-encode to the input byte-for-byte.
pub fn decode_artifact_manifest(input: &[u8]) -> Result<ArtifactManifest, PublicationBundleError> {
    bound(
        "publication artifact manifest",
        input.len(),
        MAX_ENCODED_MANIFEST_BYTES,
    )?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(ARTIFACT_MANIFEST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let count: usize = usize::try_from(frame.required_u32(1)?)
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
    if count > MAX_ARTIFACT_MANIFEST_ENTRIES {
        return Err(PublicationBundleError::ManifestTooLarge {
            actual: count,
            max: MAX_ARTIFACT_MANIFEST_ENTRIES,
        });
    }
    let expected_field_count: usize = count
        .checked_add(1)
        .ok_or(PublicationBundleError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(PublicationBundleError::NonCanonicalManifestOrder);
    }
    let mut entries: Vec<ArtifactEntry> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 = u16::try_from(
            index
                .checked_add(2)
                .ok_or(PublicationBundleError::ArithmeticOverflow)?,
        )
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
        entries.push(decode_artifact_entry(frame.required_field(field)?)?);
    }

    let manifest: ArtifactManifest = ArtifactManifest { entries };
    validate_manifest(&manifest)?;
    if encode_artifact_manifest(&manifest)?.as_slice() != input {
        return Err(PublicationBundleError::NonCanonicalEncoding {
            kind: "publication artifact manifest",
        });
    }
    Ok(manifest)
}

/// Checks a bundle's own structural bounds before any encoding or crypto.
fn validate_bundle_shape(bundle: &PublicationBundle) -> Result<(), PublicationBundleError> {
    if bundle.commitment_profile != LOGICAL_COMMITMENT_PROFILE {
        return Err(PublicationBundleError::UnsupportedCommitmentProfile {
            expected: LOGICAL_COMMITMENT_PROFILE,
            actual: bundle.commitment_profile,
        });
    }
    ensure_request_id_nonzero(&bundle.request_id)?;
    if bundle.signed_intent.is_empty() || bundle.signed_intent.len() > MAX_SIGNED_INTENT_BYTES {
        return Err(PublicationBundleError::InvalidSignedIntentLength {
            actual: bundle.signed_intent.len(),
            max: MAX_SIGNED_INTENT_BYTES,
        });
    }
    if bundle.witness.is_empty() || bundle.witness.len() > MAX_COMMITMENT_WITNESS_BYTES {
        return Err(PublicationBundleError::InvalidWitnessLength {
            actual: bundle.witness.len(),
            max: MAX_COMMITMENT_WITNESS_BYTES,
        });
    }
    validate_manifest(&bundle.manifest)?;
    if bundle.manifest.entries.len() != bundle.contents.len() {
        return Err(PublicationBundleError::ContentCountMismatch {
            entries: bundle.manifest.entries.len(),
            contents: bundle.contents.len(),
        });
    }
    for (index, content) in bundle.contents.iter().enumerate() {
        if content.len() > MAX_ARTIFACT_CONTENT_BYTES {
            return Err(PublicationBundleError::ArtifactContentTooLarge {
                index,
                actual: content.len(),
                max: MAX_ARTIFACT_CONTENT_BYTES,
            });
        }
    }
    ensure_chain_id_bound(&bundle.certificate.chain_id)?;
    Ok(())
}

/// Encodes one [`PublicationBundle`] (`0xD035/v1`).
///
/// Refuses an unsupported commitment profile, an out-of-bound intent/witness,
/// a misordered or duplicated manifest and a content count that disagrees
/// with the manifest before any field is written.
pub fn encode_publication_bundle(
    bundle: &PublicationBundle,
) -> Result<Vec<u8>, PublicationBundleError> {
    validate_bundle_shape(bundle)?;
    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(PUBLICATION_BUNDLE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, bundle.domain.as_bytes().to_vec())?;
    canonical.field_bytes(2, bundle.request_id.to_vec())?;
    canonical.field_u16(3, bundle.commitment_profile)?;
    canonical.field_bytes(4, bundle.signed_intent.clone())?;
    canonical.field_bytes(5, crate::encode_fast_certificate(&bundle.certificate)?)?;
    canonical.field_bytes(6, bundle.witness.clone())?;
    canonical.field_bytes(7, encode_artifact_manifest(&bundle.manifest)?)?;
    canonical.field_u32(
        8,
        u32::try_from(bundle.contents.len())
            .map_err(|_| PublicationBundleError::ArithmeticOverflow)?,
    )?;
    for (index, content) in bundle.contents.iter().enumerate() {
        let field: u16 = u16::try_from(
            index
                .checked_add(9)
                .ok_or(PublicationBundleError::ArithmeticOverflow)?,
        )
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
        canonical.field_bytes(field, content.clone())?;
    }
    let bytes: Vec<u8> = canonical.finish()?;
    bound("publication bundle", bytes.len(), MAX_ENCODED_BUNDLE_BYTES)?;
    Ok(bytes)
}

/// Decodes and strictly re-validates one [`PublicationBundle`].
///
/// Bounds the input before any parsing, requires the exact type/version, a
/// declared content count that agrees with the fields actually present, a
/// nested [`FastCertificate`] and [`ArtifactManifest`] that each decode
/// strictly, and byte-exact re-encoding of the decoded value. It performs no
/// signature, quorum, hash or content verification; callers must still call
/// [`verify_publication_bundle`].
pub fn decode_publication_bundle(
    input: &[u8],
) -> Result<PublicationBundle, PublicationBundleError> {
    bound("publication bundle", input.len(), MAX_ENCODED_BUNDLE_BYTES)?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PUBLICATION_BUNDLE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let domain_field: &[u8] = frame.required_field(1)?;
    let domain_bytes: [u8; 32] = domain_field.try_into().map_err(|_| {
        PublicationBundleError::Consensus(ConsensusError::CanonicalDecoding(
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 1,
                expected: 32,
                actual: domain_field.len(),
            },
        ))
    })?;
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(domain_bytes).map_err(ConsensusError::ProtocolType)?;
    let request_field: &[u8] = frame.required_field(2)?;
    let request_id: [u8; 32] = request_field.try_into().map_err(|_| {
        PublicationBundleError::Consensus(ConsensusError::CanonicalDecoding(
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 2,
                expected: 32,
                actual: request_field.len(),
            },
        ))
    })?;
    ensure_request_id_nonzero(&request_id)?;
    let commitment_profile: u16 = frame.required_u16(3)?;
    if commitment_profile != LOGICAL_COMMITMENT_PROFILE {
        return Err(PublicationBundleError::UnsupportedCommitmentProfile {
            expected: LOGICAL_COMMITMENT_PROFILE,
            actual: commitment_profile,
        });
    }
    let signed_intent: Vec<u8> = frame.required_field(4)?.to_vec();
    if signed_intent.is_empty() || signed_intent.len() > MAX_SIGNED_INTENT_BYTES {
        return Err(PublicationBundleError::InvalidSignedIntentLength {
            actual: signed_intent.len(),
            max: MAX_SIGNED_INTENT_BYTES,
        });
    }
    let certificate: FastCertificate = crate::decode_fast_certificate(frame.required_field(5)?)?;
    let witness: Vec<u8> = frame.required_field(6)?.to_vec();
    if witness.is_empty() || witness.len() > MAX_COMMITMENT_WITNESS_BYTES {
        return Err(PublicationBundleError::InvalidWitnessLength {
            actual: witness.len(),
            max: MAX_COMMITMENT_WITNESS_BYTES,
        });
    }
    let manifest: ArtifactManifest = decode_artifact_manifest(frame.required_field(7)?)?;
    let content_count: usize = usize::try_from(frame.required_u32(8)?)
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
    if content_count != manifest.entries.len() {
        return Err(PublicationBundleError::ContentCountMismatch {
            entries: manifest.entries.len(),
            contents: content_count,
        });
    }
    let expected_field_count: usize = content_count
        .checked_add(8)
        .ok_or(PublicationBundleError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(PublicationBundleError::ContentCountMismatch {
            entries: manifest.entries.len(),
            contents: frame
                .field_count()
                .checked_sub(8)
                .unwrap_or(frame.field_count()),
        });
    }
    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(content_count);
    for index in 0..content_count {
        let field: u16 = u16::try_from(
            index
                .checked_add(9)
                .ok_or(PublicationBundleError::ArithmeticOverflow)?,
        )
        .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
        let content: &[u8] = frame.required_field(field)?;
        if content.len() > MAX_ARTIFACT_CONTENT_BYTES {
            return Err(PublicationBundleError::ArtifactContentTooLarge {
                index,
                actual: content.len(),
                max: MAX_ARTIFACT_CONTENT_BYTES,
            });
        }
        contents.push(content.to_vec());
    }

    let bundle: PublicationBundle = PublicationBundle {
        domain,
        request_id,
        commitment_profile,
        signed_intent,
        certificate,
        witness,
        manifest,
        contents,
    };
    if encode_publication_bundle(&bundle)?.as_slice() != input {
        return Err(PublicationBundleError::NonCanonicalEncoding {
            kind: "publication bundle",
        });
    }
    Ok(bundle)
}

/// Derives the one [`AvailabilityIdentity`] a bundle denotes, **without**
/// verifying signatures, quorum or content.
///
/// The derivation reads only the certificate's header fields, the declared
/// domain/request identity and the supplied manifest digest, so equivalent
/// valid signer subsets over the same operation derive byte-identical
/// identities. Use [`verify_publication_bundle`] for the checked path; this
/// helper exists so a caller can compare a candidate bundle against an
/// already retained identity before doing crypto work, never so it can skip
/// that work.
pub fn derive_availability_identity(
    bundle: &PublicationBundle,
    manifest_digest: Digest32,
) -> Result<AvailabilityIdentity, PublicationBundleError> {
    ensure_chain_id_bound(&bundle.certificate.chain_id)?;
    ensure_request_id_nonzero(&bundle.request_id)?;
    Ok(AvailabilityIdentity {
        chain_id: bundle.certificate.chain_id.clone(),
        protocol_version: bundle.certificate.protocol_version,
        epoch: bundle.certificate.epoch,
        domain: bundle.domain,
        request_id: bundle.request_id,
        signed_intent_digest: bundle.certificate.tx_hash,
        execution_commitment: bundle.certificate.execution_effects_hash,
        semantic_artifacts_digest: manifest_digest,
    })
}

/// Verifies one publication bundle and derives its single logical
/// [`AvailabilityIdentity`].
///
/// In order, and failing closed at the first refusal:
///
/// 1. Structural bounds: supported commitment profile, non-zero request id,
///    bounded non-empty intent and witness, canonical bounded manifest, one
///    content per entry.
/// 2. `resolver` is bound to the same chain and protocol version as
///    `certifier`, so no hash can be produced under a foreign context.
/// 3. The carried certificate carries a real quorum of `certifier`'s
///    registered outgoing set at the bound context
///    ([`FastPathCertifier::verify_certificate`]).
/// 4. The carried witness hashes to that certificate's
///    `execution_effects_hash`.
/// 5. Every artifact's supplied bytes match their declared length and hash to
///    their declared content digest under their kind's hash purpose. Content
///    is verified against the *manifest*, and the manifest digest is what the
///    returned identity binds, so a caller cannot substitute bytes without
///    changing the identity.
///
/// It does **not** check that `signed_intent` hashes to `certificate.tx_hash`
/// (that derivation is `node_core`'s authentication pipeline) and does not
/// check that the manifest is closed with respect to the witness's signed
/// operands (that derivation is `node_core`'s `0x6424/v2` decoder). Both
/// remain mandatory retainer-side obligations; see the module documentation.
pub fn verify_publication_bundle<V: ConsensusVerifier>(
    bundle: &PublicationBundle,
    certifier: &FastPathCertifier,
    verifier: &V,
    resolver: &HashSuiteResolver,
) -> Result<VerifiedPublicationBundle, PublicationBundleError> {
    validate_bundle_shape(bundle)?;

    if resolver.chain_id() != certifier.chain_id() {
        return Err(ConsensusError::HashChainMismatch.into());
    }
    if resolver.protocol_version() != certifier.protocol_version() {
        return Err(ConsensusError::HashProtocolVersionMismatch.into());
    }
    let epoch = certifier.epoch();
    if &bundle.certificate.chain_id != certifier.chain_id()
        || bundle.certificate.protocol_version != certifier.protocol_version()
        || bundle.certificate.epoch != epoch
    {
        return Err(ConsensusError::ContextMismatch.into());
    }

    certifier.verify_certificate(&bundle.certificate, verifier)?;

    let witness_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &bundle.witness)?;
    if witness_digest != bundle.certificate.execution_effects_hash {
        return Err(PublicationBundleError::WitnessCommitmentMismatch);
    }

    for (index, (entry, content)) in bundle
        .manifest
        .entries
        .iter()
        .zip(bundle.contents.iter())
        .enumerate()
    {
        let declared: usize = usize::try_from(entry.content_length)
            .map_err(|_| PublicationBundleError::ArithmeticOverflow)?;
        if declared != content.len() {
            return Err(PublicationBundleError::ArtifactLengthMismatch {
                index,
                declared: entry.content_length,
                actual: content.len(),
            });
        }
        let digest: Digest32 =
            resolver.hash_for_purpose(epoch, entry.kind.hash_purpose(), content)?;
        if digest != entry.content_digest {
            return Err(PublicationBundleError::ArtifactContentDigestMismatch { index });
        }
    }

    let manifest_bytes: Vec<u8> = encode_artifact_manifest(&bundle.manifest)?;
    let manifest_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &manifest_bytes)?;
    let identity: AvailabilityIdentity = derive_availability_identity(bundle, manifest_digest)?;
    ensure_encoded_bound(
        "availability identity chain_id",
        identity.chain_id.as_str().len(),
        super::MAX_CHAIN_ID_BYTES,
    )?;
    Ok(VerifiedPublicationBundle {
        identity,
        manifest_digest,
    })
}

#[cfg(test)]
mod tests;
