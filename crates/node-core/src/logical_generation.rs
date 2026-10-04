//! Authenticated causal execution generations and their durable provenance
//! (DR-0154).
//!
//! This module owns the handoff-capable profile's *logical* admission operand.
//! It is deliberately independent of every physical persistence counter:
//! [`StateRevision`], object head/nonce revisions, writer fence generations and
//! the runtime-owned `DurableObjectVersionRecord::created_checkpoint` remain
//! exactly what they were -- local compare-and-swap and audit inputs. They
//! never become a signed logical observation, and they stop driving semantic
//! monotonicity only on a leg whose authenticated generation dependency this
//! module has actually proven.
//!
//! The operand is [`ExecutionGeneration`]:
//!
//! ```text
//! G = 1 + max(verified predecessor cut floor, every verified input generation)
//! ```
//!
//! derived through [`ExecutionGeneration::successor_of`]'s checked arithmetic,
//! so overflow is a typed refusal before any reservation, mutation or exposed
//! signature rather than a saturating or wrapping increment. Independent
//! operations may legitimately share one generation: this is a causal operand,
//! not a globally serialized counter, and nothing here allocates from a shared
//! sequence.
//!
//! Two kinds of durable row live under [`LOGICAL_STATE_PREFIX`]:
//!
//! * exactly one [`LogicalProfileRecord`] per genesis context, installed only
//!   by a signed version-2 [`crate::genesis::GenesisManifest`] whose
//!   `commitment_profile` field binds the handoff-capable model, and
//!   re-verified byte-for-byte against that signed manifest on every reopen.
//!   Its absence denotes a historical store, which stays readable and
//!   verifiable: absence never grants a new-profile guarantee, and it cannot
//!   become an active legacy fallback for a store whose manifest did bind the
//!   new profile, because that store's reopen verification requires the exact
//!   row. No caller argument anywhere selects the profile;
//! * one [`LogicalProvenanceRecord`] per exact subject identity -- a generic
//!   state key, an object id, or a `(sender, epoch)` sender-nonce row. Each
//!   record is bound to that exact identity *and* to the semantic observation
//!   it describes, so a forged or mismatched pairing fails closed. The
//!   runtime-owned `DurableObjectProvenance` is untouched by this module.
//!
//! Both rows sit under [`local_instance_state::INSTANCE_STATE_PREFIX`], so the
//! existing reserved-namespace enforcement already forbids contract and generic
//! transactional access, and *outside*
//! `local_instance_state::FASTPATH_STATE_PREFIX`, so they are ordinary
//! commitment-covered protocol state. Fast-path business rows are a separate
//! authenticated history, not disposable bookkeeping: a complete handoff cut
//! must enumerate and verify them even though this generic provenance scheme
//! does not assign them a second generation. Each provenance row's exact
//! observed [`StateRevision`] becomes a compare-and-swap fence in the same
//! atomic commit that installs its successor.
use super::*;
use canonical_encoding::{CanonicalFrame, decode_digest32, encode_chain_id, encode_digest32};
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use protocol_types::{ExecutionGeneration, ExecutionGenerationOverflow};
use runtime::VersionedStateReader;

#[cfg(test)]
mod tests;

/// Canonical frame type of an encoded [`LogicalProfileRecord`].
///
/// Allocated from the swept, previously unused `0x6480..=0x648F` node-core
/// block. The repository-wide sweep confirmed `0x6401..=0x6439` and
/// `0x6440..=0x644F` are taken and `0x6460` belongs to `node-wire`; `0x6450`
/// is the local drain-resolution audit, `0x6452` and `0x6453` stay free,
/// and `0x6451` plus `0x6454..=0x645F` remain
/// reserved for the concurrently owned retention/control/cut work.
pub const LOGICAL_PROFILE_RECORD_FRAME_TYPE: u16 = 0x6480;
/// Canonical version of [`LogicalProfileRecord`].
pub const LOGICAL_PROFILE_RECORD_VERSION: u16 = 1;
/// Fresh v3 genesis authorization, with a positive signed Freeze minimum.
pub const LOGICAL_PROFILE_FREEZE_RECORD_VERSION: u16 = 2;

/// Canonical frame type of an encoded [`LogicalProvenanceRecord`].
pub const LOGICAL_PROVENANCE_RECORD_FRAME_TYPE: u16 = 0x6481;
/// Canonical version of [`LogicalProvenanceRecord`].
pub const LOGICAL_PROVENANCE_RECORD_VERSION: u16 = 1;

/// Reserved under [`local_instance_state::INSTANCE_STATE_PREFIX`] and
/// deliberately *not* under `FASTPATH_STATE_PREFIX`: these rows are protocol
/// provenance covered by the logical commitment, not fast-path-owned rows.
pub const LOGICAL_STATE_PREFIX: &[u8] = b"se/instances/v1/logical/";

/// Infix of the single chain-keyed profile row.
const PROFILE_INFIX: &[u8] = b"profile/";
/// Infix of an inline-addressed generic state-key provenance row.
const STATE_INLINE_INFIX: &[u8] = b"state/";
/// Infix of a digest-addressed generic state-key provenance row.
const STATE_DIGEST_INFIX: &[u8] = b"state-digest/";
/// Infix of an object provenance row.
const OBJECT_INFIX: &[u8] = b"object/";
/// Infix of a sender-nonce provenance row.
const NONCE_INFIX: &[u8] = b"nonce/";

/// Maximum provenance subjects one operation may observe or install.
///
/// Derived from the runtime's own `MAX_ATOMIC_STATE_WRITES`: every subject
/// costs at most one provenance read and one provenance write on top of its
/// own row, so half that existing ceiling is the exact admissible count rather
/// than an invented constant.
pub const MAX_LOGICAL_PROVENANCE_SUBJECTS: usize = MAX_ATOMIC_STATE_WRITES / 2;

const SUBJECT_TAG_STATE_KEY: u16 = 1;
const SUBJECT_TAG_OBJECT: u16 = 2;
const SUBJECT_TAG_SENDER_NONCE: u16 = 3;

const OBSERVATION_TAG_STATE_PRESENT: u16 = 1;
const OBSERVATION_TAG_STATE_DELETED: u16 = 2;
const OBSERVATION_TAG_OBJECT_LIVE: u16 = 3;
const OBSERVATION_TAG_OBJECT_DELETED: u16 = 4;
const OBSERVATION_TAG_NONCE_NEXT: u16 = 5;

/// Which commitment and admission model a store's installed genesis binds.
///
/// A signed genesis profile decision: never a client request flag, never
/// inferred from a bare certificate, never a caller argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentProfile {
    /// Historical profile: `0x6424/v1` signs physical state/head/nonce
    /// revisions plus the local creation checkpoint, and semantic monotonicity
    /// is that checkpoint. Retained unchanged for historical verification.
    PhysicalCheckpointV1,
    /// Handoff-capable profile: `0x6424/v2` signs content/pristine/deleted
    /// observations plus an authenticated [`ExecutionGeneration`], and semantic
    /// monotonicity is that generation.
    LogicalGenerationV2,
    /// Fresh signed-v4 genesis: logical generations plus disjoint external
    /// request lanes and certified causal business admission. Historical
    /// logical witnesses keep their exact version-two interpretation.
    CausalAdmission,
}

impl CommitmentProfile {
    /// Returns the stable canonical wire tag.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::PhysicalCheckpointV1 => 1,
            Self::LogicalGenerationV2 => 2,
            Self::CausalAdmission => 3,
        }
    }

    /// True when this profile derives, signs and enforces logical generations.
    #[must_use]
    pub const fn is_logical(self) -> bool {
        matches!(self, Self::LogicalGenerationV2 | Self::CausalAdmission)
    }

    /// Strictly decodes a wire tag; an unknown tag fails closed.
    pub const fn from_wire(value: u16) -> Result<Self, NodeCoreError> {
        if value == 1 {
            return Ok(Self::PhysicalCheckpointV1);
        }
        if value == 2 {
            return Ok(Self::LogicalGenerationV2);
        }
        if value == 3 {
            return Ok(Self::CausalAdmission);
        }
        Err(NodeCoreError::PersistenceInvariant(
            "unknown commitment profile tag",
        ))
    }
}

/// Frame `0x6480/v1`: the authenticated fresh-profile record.
///
/// Carries the explicit authenticated genesis generation floor, so admission
/// never invents one and never reinterprets a historical physical field as a
/// generation. A later verified predecessor-cut floor supersedes it through the
/// concurrently owned cut work; this unit reads exactly this row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalProfileRecord {
    /// Genesis publication context this profile was installed for.
    pub context: PublicationContext,
    /// Commitment/admission model bound by the signed manifest.
    pub profile: CommitmentProfile,
    /// Exact signed manifest commitment that authorized this profile.
    pub manifest_digest: Digest32,
    /// Genesis authority that signed that manifest.
    pub genesis_authority: [u8; 32],
    /// Explicit authenticated genesis generation floor.
    pub genesis_floor: ExecutionGeneration,
    /// Signed-genesis-derived Freeze minimum, zero for the exact v1 profile.
    pub minimum_freeze_block_height: u64,
}

const PROFILE_CONTEXT: &str = "invalid logical profile context";

/// Shorthand for this module's persistence-invariant refusals.
const fn invariant(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// Shorthand for this module's authenticated-provenance refusals.
const fn provenance_error(message: &'static str) -> NodeCoreError {
    NodeCoreError::LogicalProvenance(message)
}

fn profile_fields(frame: &CanonicalFrame<'_>) -> Result<LogicalProfileRecord, NodeCoreError> {
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| invariant(PROFILE_CONTEXT))?;
    let authority: [u8; 32] = frame
        .required_field(4)?
        .try_into()
        .map_err(|_| invariant("logical profile authority length"))?;
    Ok(LogicalProfileRecord {
        context,
        profile: CommitmentProfile::from_wire(frame.required_u16(2)?)?,
        manifest_digest: decode_digest32(frame.required_field(3)?)?,
        genesis_authority: authority,
        genesis_floor: ExecutionGeneration::new(frame.required_u64(5)?),
        minimum_freeze_block_height: if frame.version() == LOGICAL_PROFILE_FREEZE_RECORD_VERSION {
            let minimum: u64 = frame.required_u64(6)?;
            if minimum == 0 {
                return Err(invariant(
                    "Freeze profile requires a positive minimum height",
                ));
            }
            minimum
        } else {
            0
        },
    })
}

/// Everything one operation's logical derivation produced.
pub(crate) struct LogicalDerivation {
    /// Derived causal generation.
    pub(crate) generation: ExecutionGeneration,
    /// Exact observation per generic state read, for the `0x6424/v2` logical
    /// commitment.
    pub(crate) reads: BTreeMap<Vec<u8>, ReadObservation>,
    /// Verified previous generation per observed subject. Every leg that used
    /// to compare a physical creation checkpoint consults this, so physical
    /// monotonicity is replaced only where an authenticated dependency was
    /// actually proven.
    pub(crate) inputs: BTreeMap<LogicalSubject, ExecutionGeneration>,
}

/// One verified read: the row's own closed observation plus its authenticated
/// generation.
///
/// Both fields are `None` only for a never-written subject. A deletion keeps
/// `LogicalObservation::StateDeleted` and its generation, so a tombstone is
/// never encoded as absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadObservation {
    /// Closed semantic observation recorded for this subject.
    pub(crate) observed: Option<LogicalObservation>,
    /// Authenticated generation of that observation.
    pub(crate) generation: Option<ExecutionGeneration>,
}

const NONCANONICAL_PROFILE: &str = "noncanonical logical profile record";

/// One subject whose provenance this operation installs.
pub(crate) struct LogicalWrite {
    /// Exact subject identity.
    pub(crate) subject: LogicalSubject,
    /// Semantic observation of the value this operation writes.
    pub(crate) observation: LogicalObservation,
}

/// Strictly decodes frame `0x6480/v1`.
pub fn decode_logical_profile_record(bytes: &[u8]) -> Result<LogicalProfileRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(LOGICAL_PROFILE_RECORD_FRAME_TYPE)?;
    if frame.version() == LOGICAL_PROFILE_FREEZE_RECORD_VERSION {
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    } else {
        frame.require_version(LOGICAL_PROFILE_RECORD_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    }
    let record: LogicalProfileRecord = profile_fields(&frame)?;
    let canonical: bool = encode_logical_profile_record(&record)? == bytes;
    if canonical {
        Ok(record)
    } else {
        Err(NodeCoreError::PersistenceInvariant(NONCANONICAL_PROFILE))
    }
}

/// The exact protocol identity one provenance row describes.
///
/// Every variant is an exact logical identity, never a physical coordinate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogicalSubject {
    /// One generic transactional state key, carried verbatim.
    StateKey(Vec<u8>),
    /// One object identity, covering its live head or its tombstone.
    Object(ObjectId),
    /// One sender-nonce row.
    SenderNonce {
        /// Sender address bytes.
        sender: [u8; 32],
        /// Epoch the nonce sequence belongs to.
        epoch: Epoch,
    },
}

/// The authenticated semantic observation a provenance row is bound to.
///
/// `Deleted` is never encoded as absence: a tombstoned subject keeps its row
/// and a never-created subject has none, so the two stay distinguishable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalObservation {
    /// Present value, bound by the content digest of its canonical bytes.
    StatePresent {
        /// Content digest of the exact canonical stored value.
        content_digest: Digest32,
    },
    /// Deleted value: a tombstone, never absence.
    StateDeleted,
    /// Live object head at an exact logical version and digest.
    ObjectLive {
        /// Current logical object version.
        object_version: u64,
        /// Current object digest.
        digest: Digest32,
    },
    /// Tombstoned object head, retaining its last logical version.
    ObjectDeleted {
        /// Last logical object version before deletion.
        last_object_version: u64,
    },
    /// Sender-nonce row at its exact next admissible nonce.
    NonceNext {
        /// Next admissible nonce recorded in the row.
        next_nonce: u64,
    },
}

impl LogicalObservation {
    const fn tag(self) -> u16 {
        match self {
            Self::StatePresent { .. } => OBSERVATION_TAG_STATE_PRESENT,
            Self::StateDeleted => OBSERVATION_TAG_STATE_DELETED,
            Self::ObjectLive { .. } => OBSERVATION_TAG_OBJECT_LIVE,
            Self::ObjectDeleted { .. } => OBSERVATION_TAG_OBJECT_DELETED,
            Self::NonceNext { .. } => OBSERVATION_TAG_NONCE_NEXT,
        }
    }
}

/// Frame `0x6481/v1`: one subject's authenticated causal generation.
///
/// The subject identity and the observation ride in this one frame rather than
/// nested frames, so no extra canonical type identifier is consumed and the
/// closed per-variant field set is checked in one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalProvenanceRecord {
    /// Exact subject identity this row describes.
    pub subject: LogicalSubject,
    /// Epoch whose committed suite produced any digest in `observation`.
    pub observed_epoch: Epoch,
    /// Authenticated causal generation of this subject's current value.
    pub generation: ExecutionGeneration,
    /// Semantic observation this generation is bound to.
    pub observation: LogicalObservation,
}

const SUBJECT_KEY_LENGTH: &str = "logical provenance subject key length";
const SUBJECT_PAIRING: &str = "logical provenance subject and observation disagree";
const NONCANONICAL_PROVENANCE: &str = "noncanonical logical provenance record";
const FOREIGN_SUBJECT: &str = "logical provenance row describes another subject";
const MISSING_PROVENANCE: &str = "read has no authenticated logical provenance";
const MISMATCHED_PROVENANCE: &str = "observed value disagrees with its logical provenance";
const SUBJECT_COUNT: &str = "logical provenance subject count";

/// Rejects any subject/observation pairing outside the closed schema.
fn require_pairing(
    subject: &LogicalSubject,
    observation: LogicalObservation,
) -> Result<(), NodeCoreError> {
    let paired: bool = matches!(
        (subject, observation),
        (
            LogicalSubject::StateKey(_),
            LogicalObservation::StatePresent { .. } | LogicalObservation::StateDeleted
        ) | (
            LogicalSubject::Object(_),
            LogicalObservation::ObjectLive { .. } | LogicalObservation::ObjectDeleted { .. }
        ) | (
            LogicalSubject::SenderNonce { .. },
            LogicalObservation::NonceNext { .. }
        )
    );
    if paired {
        Ok(())
    } else {
        Err(invariant(SUBJECT_PAIRING))
    }
}

fn push_subject(
    frame: &mut CanonicalStruct,
    subject: &LogicalSubject,
) -> Result<(), NodeCoreError> {
    match subject {
        LogicalSubject::StateKey(key) => {
            if key.is_empty() || key.len() > MAX_STATE_KEY_BYTES {
                return Err(invariant(SUBJECT_KEY_LENGTH));
            }
            frame.field_u16(1, SUBJECT_TAG_STATE_KEY)?;
            frame.field_bytes(2, key.clone())?;
        }
        LogicalSubject::Object(object_id) => {
            frame.field_u16(1, SUBJECT_TAG_OBJECT)?;
            frame.field_bytes(2, object_id.as_bytes().to_vec())?;
        }
        LogicalSubject::SenderNonce { sender, epoch } => {
            frame.field_u16(1, SUBJECT_TAG_SENDER_NONCE)?;
            frame.field_bytes(2, sender.to_vec())?;
            frame.field_u64(3, epoch.get())?;
        }
    }
    Ok(())
}

fn push_observation(
    frame: &mut CanonicalStruct,
    observation: LogicalObservation,
) -> Result<(), NodeCoreError> {
    frame.field_u16(6, observation.tag())?;
    match observation {
        LogicalObservation::StatePresent { content_digest } => {
            frame.field_bytes(7, encode_digest32(&content_digest)?)?;
        }
        LogicalObservation::StateDeleted => {}
        LogicalObservation::ObjectLive {
            object_version,
            digest,
        } => {
            frame.field_bytes(7, encode_digest32(&digest)?)?;
            frame.field_u64(8, object_version)?;
        }
        LogicalObservation::ObjectDeleted {
            last_object_version,
        } => {
            frame.field_u64(8, last_object_version)?;
        }
        LogicalObservation::NonceNext { next_nonce } => {
            frame.field_u64(8, next_nonce)?;
        }
    }
    Ok(())
}

/// Encodes frame `0x6481/v1`.
pub fn encode_logical_provenance_record(
    record: &LogicalProvenanceRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    require_pairing(&record.subject, record.observation)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        LOGICAL_PROVENANCE_RECORD_FRAME_TYPE,
        LOGICAL_PROVENANCE_RECORD_VERSION,
    );
    push_subject(&mut frame, &record.subject)?;
    frame.field_u64(4, record.observed_epoch.get())?;
    frame.field_u64(5, record.generation.get())?;
    push_observation(&mut frame, record.observation)?;
    Ok(frame.finish()?)
}

fn decode_subject(
    frame: &CanonicalFrame<'_>,
    allowed: &mut Vec<u16>,
) -> Result<LogicalSubject, NodeCoreError> {
    let identity: &[u8] = frame.required_field(2)?;
    match frame.required_u16(1)? {
        SUBJECT_TAG_STATE_KEY => {
            if identity.is_empty() || identity.len() > MAX_STATE_KEY_BYTES {
                return Err(invariant(SUBJECT_KEY_LENGTH));
            }
            Ok(LogicalSubject::StateKey(identity.to_vec()))
        }
        SUBJECT_TAG_OBJECT => {
            let bytes: [u8; 32] = identity
                .try_into()
                .map_err(|_| invariant("logical provenance object id length"))?;
            Ok(LogicalSubject::Object(ObjectId::new(bytes)))
        }
        SUBJECT_TAG_SENDER_NONCE => {
            allowed.push(3);
            let sender: [u8; 32] = identity
                .try_into()
                .map_err(|_| invariant("logical provenance sender length"))?;
            Ok(LogicalSubject::SenderNonce {
                sender,
                epoch: Epoch::new(frame.required_u64(3)?),
            })
        }
        _ => Err(invariant("unknown logical provenance subject tag")),
    }
}

fn decode_observation(
    frame: &CanonicalFrame<'_>,
    allowed: &mut Vec<u16>,
) -> Result<LogicalObservation, NodeCoreError> {
    match frame.required_u16(6)? {
        OBSERVATION_TAG_STATE_PRESENT => {
            allowed.push(7);
            Ok(LogicalObservation::StatePresent {
                content_digest: decode_digest32(frame.required_field(7)?)?,
            })
        }
        OBSERVATION_TAG_STATE_DELETED => Ok(LogicalObservation::StateDeleted),
        OBSERVATION_TAG_OBJECT_LIVE => {
            allowed.push(7);
            allowed.push(8);
            Ok(LogicalObservation::ObjectLive {
                digest: decode_digest32(frame.required_field(7)?)?,
                object_version: frame.required_u64(8)?,
            })
        }
        OBSERVATION_TAG_OBJECT_DELETED => {
            allowed.push(8);
            Ok(LogicalObservation::ObjectDeleted {
                last_object_version: frame.required_u64(8)?,
            })
        }
        OBSERVATION_TAG_NONCE_NEXT => {
            allowed.push(8);
            Ok(LogicalObservation::NonceNext {
                next_nonce: frame.required_u64(8)?,
            })
        }
        _ => Err(invariant("unknown logical provenance observation tag")),
    }
}

/// Strictly decodes frame `0x6481/v1`.
pub fn decode_logical_provenance_record(
    bytes: &[u8],
) -> Result<LogicalProvenanceRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(LOGICAL_PROVENANCE_RECORD_FRAME_TYPE)?;
    frame.require_version(LOGICAL_PROVENANCE_RECORD_VERSION)?;
    let mut allowed: Vec<u16> = vec![1, 2, 4, 5, 6];
    let subject: LogicalSubject = decode_subject(&frame, &mut allowed)?;
    let observation: LogicalObservation = decode_observation(&frame, &mut allowed)?;
    frame.require_only_fields(&allowed)?;
    require_pairing(&subject, observation)?;
    let record: LogicalProvenanceRecord = LogicalProvenanceRecord {
        subject,
        observed_epoch: Epoch::new(frame.required_u64(4)?),
        generation: ExecutionGeneration::new(frame.required_u64(5)?),
        observation,
    };
    let canonical: bool = encode_logical_provenance_record(&record)? == bytes;
    if canonical {
        Ok(record)
    } else {
        Err(invariant(NONCANONICAL_PROVENANCE))
    }
}

/// State key of the authenticated fresh-profile record.
///
/// Keyed by chain alone, never by a full publication context: the row is
/// installed once at genesis and must stay visible at every later epoch, so an
/// epoch transition can never make a handoff-capable store look historical.
pub fn logical_profile_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    let encoded: Vec<u8> = encode_chain_id(chain)?;
    let mut key: Vec<u8> = LOGICAL_STATE_PREFIX.to_vec();
    key.extend_from_slice(PROFILE_INFIX);
    key.extend(encoded);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Hashes one exact canonical stored value under `epoch`'s committed suite.
///
/// Reuses the existing `ExecutionEffects` purpose the `0x6424` staged
/// commitment already uses; no new primitive, suite or hash domain is added.
pub(crate) fn content_digest(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    value: &[u8],
) -> Result<Digest32, NodeCoreError> {
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, value)?)
}

/// True for the one chain-keyed profile row, whose content is installed once at
/// genesis and never changes.
///
/// Every honest node observes identical bytes for it, and its durable revision
/// is a per-node, per-attempt artifact rather than transaction content, so the
/// signed fast-path commitment excludes it for exactly the reason it already
/// excludes the committed epoch record. The per-subject provenance rows, which
/// do vary per transaction, stay covered. A handoff-capable ([`Logical`])
/// admission still compare-and-swap fences this row inside its own commit; a
/// historical admission installs no fence on it at all, by design -- see
/// [`fence_commitment_profile`].
///
/// [`Logical`]: InstalledCommitmentProfile::Logical
#[must_use]
pub fn is_logical_profile_key(key: &[u8]) -> bool {
    let mut prefix: Vec<u8> = LOGICAL_STATE_PREFIX.to_vec();
    prefix.extend_from_slice(PROFILE_INFIX);
    key.starts_with(&prefix)
}

/// True for a key holding this module's own metadata rather than a subject.
///
/// Provenance writes are covered by the logical commitment. A provenance read
/// is represented by its verified subject observation and generation instead
/// of by the metadata row's physical revision; that revision remains a CAS
/// fence. These rows are never subjects of further provenance, which would
/// recurse without bound.
#[must_use]
pub fn is_logical_provenance_key(key: &[u8]) -> bool {
    key.starts_with(LOGICAL_STATE_PREFIX)
}

/// Fast-path rows have three distinct handoff treatments. Reservations and
/// exposed-signature safety records are replica-local; authenticated-history
/// rows, including publication, settlements, claims, bonds, evidence, policy
/// and epoch transitions, are mandatory proof-checked cut collections. None
/// is a generic application causal subject: each is owned and CAS-fenced by
/// its separate certified or signed history path.
/// This classifier recognizes only the currently defined keys; an unknown
/// future fast-path prefix cannot silently inherit this exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastpathRowClass {
    /// Uncertified preparation and local lock state, never imported as a
    /// global business fact.
    LocalReservation,
    /// Replica-local exposed availability vote identity. It survives local
    /// restart but is not a transferable reservation or global cut fact.
    LocalSigningSafety,
    /// Protocol business/control history that a complete cut must enumerate
    /// and verify independently before activation.
    AuthenticatedHistory,
}

/// Classifies the currently defined fast-path key families without treating
/// the entire reserved namespace as harmless bookkeeping.
#[must_use]
pub fn classify_fastpath_row(key: &[u8]) -> Option<FastpathRowClass> {
    let suffix: &[u8] = key.strip_prefix(local_instance_state::FASTPATH_STATE_PREFIX)?;
    // Prepare-side witness/artifacts are replica-local backing for a vote,
    // not a certified publication or a transferable business fact.
    const LOCAL: [&[u8]; 6] = [
        b"prepared/",
        b"lock/",
        b"nonce-lock/",
        b"prepared-witness/",
        b"prepared-artifact/",
        b"drain-lock-resolution/",
    ];
    // A signed ACK is local safety state, not a mutable prepare reservation
    // and not an imported business fact.
    const SIGNING_SAFETY: [&[u8]; 1] = [b"availability-ack/"];
    // DR-0154 (2026-09-28): `publication/` embeds exactly a verified
    // `certificate/`+`commitment-witness/` pair plus the manifest that closes
    // over them, and `publication-artifact/` is the content-addressed,
    // digest-verified replay bytes that manifest requires -- both portable
    // business history a cut must enumerate, not disposable local cache.
    const HISTORY: [&[u8]; 17] = [
        b"certificate/",
        b"commitment-witness/",
        b"settlement/",
        b"fee-claim/",
        b"bond/",
        b"bond-transition/",
        b"validators/",
        b"transition/",
        b"epoch/",
        b"equivocation/",
        b"economics-policy/",
        b"evidence-consumed/",
        b"publication/",
        b"publication-artifact/",
        b"drain-publication/",
        b"drain-publication-artifact/",
        b"availability-certificate/",
    ];
    if LOCAL
        .iter()
        .any(|prefix: &&[u8]| suffix.starts_with(prefix))
    {
        return Some(FastpathRowClass::LocalReservation);
    }
    if HISTORY
        .iter()
        .any(|prefix: &&[u8]| suffix.starts_with(prefix))
    {
        return Some(FastpathRowClass::AuthenticatedHistory);
    }
    if SIGNING_SAFETY
        .iter()
        .any(|prefix: &&[u8]| suffix.starts_with(prefix))
    {
        return Some(FastpathRowClass::LocalSigningSafety);
    }
    None
}

/// Ordered-economics retained outcomes and request headers are global history,
/// not disposable consensus cache. The engine owns their signed/QC-linked
/// replay checks rather than this generic provenance scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedRowClass {
    /// Consensus state, applied height and retained candidate material needed
    /// to prove the committed prefix and safe inherited suffix.
    ConsensusControl,
    /// Immutable request/outcome history and committed epoch-control markers.
    AuthenticatedOutcomeHistory,
    /// CAS-fenced local progress and local final signatures. Neither is a
    /// transferable business fact or an authority to activate the next epoch.
    LocalProgress,
}

/// Closed classifier for the ordered-economics families defined by its engine.
#[must_use]
pub fn classify_ordered_row(key: &[u8]) -> Option<OrderedRowClass> {
    let suffix: &[u8] =
        key.strip_prefix(ordered_economics::engine::ORDERED_ECONOMICS_STATE_PREFIX)?;
    // DR-0189 appends exactly the five epoch-scoped live signing-safety
    // families. The existing lists and every chain-only identity family stay
    // exactly as before.
    const CONTROL: [&[u8]; 8] = [
        b"state/",
        b"applied-height/",
        b"candidate/",
        b"epoch-state/",
        b"epoch-applied-height/",
        b"epoch-vote-high/",
        b"epoch-leader-proposal/",
        b"epoch-vote/",
    ];
    const HISTORY: [&[u8]; 4] = [b"header/", b"outcome/", b"freeze/", b"drain-set/"];
    const LOCAL_PROGRESS: [&[u8]; 7] = [
        b"frontier-progress/",
        b"frontier/",
        b"drain-possession/",
        b"drain-signer-progress/",
        b"drain-signer-entry/",
        b"drain-union-progress/",
        b"drain-union-ready/",
    ];
    if CONTROL
        .iter()
        .any(|prefix: &&[u8]| suffix.starts_with(prefix))
    {
        return Some(OrderedRowClass::ConsensusControl);
    }
    if HISTORY
        .iter()
        .any(|prefix: &&[u8]| suffix.starts_with(prefix))
    {
        return Some(OrderedRowClass::AuthenticatedOutcomeHistory);
    }
    if LOCAL_PROGRESS
        .iter()
        .any(|prefix: &&[u8]| suffix.starts_with(prefix))
    {
        return Some(OrderedRowClass::LocalProgress);
    }
    None
}

/// True only for rows deliberately outside this generic causal-subject
/// model. Provenance rows cannot recursively become subjects; known ordered
/// and fast-path families have the explicit treatments above. A complete cut
/// still has to carry and verify their authenticated business/history families.
#[must_use]
pub fn is_excluded_subject(key: &[u8]) -> bool {
    is_logical_provenance_key(key)
        || classify_fastpath_row(key).is_some()
        || classify_ordered_row(key).is_some()
}

/// The stable authenticated addressing scheme for provenance rows.
///
/// A generic state key is carried inline whenever the exact derived key still
/// satisfies the runtime's own existing [`MAX_STATE_KEY_BYTES`] bound, which
/// every key this crate builds does by a wide margin. A legal but very long
/// subject key is *not* rejected and *not* truncated: it is addressed by the
/// content digest of its exact bytes under the committed suite of the profile's
/// own fixed genesis epoch, which never rotates, and the row still carries the
/// exact subject key so every lookup is confirmed by exact equality. No legal
/// key is untrackable and no arbitrary shortened ceiling is introduced.
pub(crate) struct LogicalKeySpace<'a> {
    chain: &'a ChainId,
    genesis_epoch: Epoch,
    resolver: &'a HashSuiteResolver,
}

impl<'a> LogicalKeySpace<'a> {
    /// Builds the key space from the authenticated profile record.
    pub(crate) fn new(profile: &'a LogicalProfileRecord, resolver: &'a HashSuiteResolver) -> Self {
        Self {
            chain: profile.context.chain_id(),
            genesis_epoch: profile.context.epoch(),
            resolver,
        }
    }

    fn state_subject_key(&self, state_key: &[u8], chain: &[u8]) -> Result<Vec<u8>, NodeCoreError> {
        if state_key.is_empty() || state_key.len() > MAX_STATE_KEY_BYTES {
            return Err(invariant(SUBJECT_KEY_LENGTH));
        }
        let inline: usize = LOGICAL_STATE_PREFIX
            .len()
            .saturating_add(STATE_INLINE_INFIX.len())
            .saturating_add(chain.len())
            .saturating_add(4)
            .saturating_add(state_key.len());
        let mut key: Vec<u8> = LOGICAL_STATE_PREFIX.to_vec();
        if inline <= MAX_STATE_KEY_BYTES {
            let length: u32 =
                u32::try_from(state_key.len()).map_err(|_| invariant(SUBJECT_KEY_LENGTH))?;
            key.extend_from_slice(STATE_INLINE_INFIX);
            key.extend_from_slice(chain);
            key.extend_from_slice(&length.to_be_bytes());
            key.extend_from_slice(state_key);
        } else {
            let digest: Digest32 = content_digest(self.resolver, self.genesis_epoch, state_key)?;
            key.extend_from_slice(STATE_DIGEST_INFIX);
            key.extend_from_slice(chain);
            key.extend_from_slice(&digest.bytes());
        }
        Ok(key)
    }

    /// Returns the exact state key of one subject's provenance row.
    pub(crate) fn provenance_key(
        &self,
        subject: &LogicalSubject,
    ) -> Result<Vec<u8>, NodeCoreError> {
        let chain: Vec<u8> = encode_chain_id(self.chain)?;
        let key: Vec<u8> = match subject {
            LogicalSubject::StateKey(state_key) => self.state_subject_key(state_key, &chain)?,
            LogicalSubject::Object(object_id) => {
                let mut key: Vec<u8> = LOGICAL_STATE_PREFIX.to_vec();
                key.extend_from_slice(OBJECT_INFIX);
                key.extend_from_slice(&chain);
                key.extend_from_slice(object_id.as_bytes());
                key
            }
            LogicalSubject::SenderNonce { sender, epoch } => {
                let mut key: Vec<u8> = LOGICAL_STATE_PREFIX.to_vec();
                key.extend_from_slice(NONCE_INFIX);
                key.extend_from_slice(&chain);
                key.extend_from_slice(sender);
                key.extend_from_slice(&epoch.get().to_be_bytes());
                key
            }
        };
        validate_transactional_state_key(&key)?;
        Ok(key)
    }
}

fn decode_installed_profile(
    bytes: &[u8],
    chain: &ChainId,
) -> Result<LogicalProfileRecord, NodeCoreError> {
    let record: LogicalProfileRecord = decode_logical_profile_record(bytes)?;
    if record.context.chain_id() != chain {
        return Err(provenance_error("logical profile context mismatch"));
    }
    if record.profile.is_logical() {
        Ok(record)
    } else {
        Err(provenance_error("logical profile does not bind the model"))
    }
}

/// DR-0189 opaque generation-floor scope.
///
/// The original namespace derives every generation above the installed
/// profile genesis floor, unchanged. A verified first successor derives
/// above the verified cut binding floor instead. No module outside this one
/// can name the inner representation or build a successor variant: the only
/// successor constructors take a warrant, whose floor comes only from the
/// verified cut binding of successor evidence. The floor is the only
/// accessor. Provenance observation epochs stay the owning row context
/// epochs, exactly as for the original namespace, so an imported epoch-e row
/// (for example a fee escrow settlement) keeps its own hash epoch.
/// The successor anchor binding deliberately does not go through this scope:
/// activation asserts the scoped epoch-state root and every live successor
/// commit rechecks the exact protected serving record carrying the anchor.
pub(crate) struct GenerationScope(Scope);

enum Scope {
    Original { floor: ExecutionGeneration },
    Successor { floor: ExecutionGeneration },
}

impl GenerationScope {
    /// Original-namespace scope: the authenticated profile genesis floor.
    pub(crate) const fn from_profile(profile: &LogicalProfileRecord) -> Self {
        Self(Scope::Original {
            floor: profile.genesis_floor,
        })
    }

    /// Successor scope of one activation or private reconstruction-base
    /// bootstrap, from verified evidence inputs only (no public constructor
    /// of the inputs exists).
    pub(crate) fn for_evidence(inputs: &crate::serving_authority::SuccessorPolicyInputs) -> Self {
        Self::successor(inputs)
    }

    /// Successor scope of one live invocation, from verified evidence only.
    pub(crate) fn for_live(warrant: &crate::serving_authority::LiveWarrant<'_>) -> Self {
        Self::successor(warrant.policy_inputs())
    }

    /// DR-0191 replay scope: the floor of the link that activated the
    /// replayed epoch, from the private reconstruction base only.
    pub(crate) const fn for_replay(floor: ExecutionGeneration) -> Self {
        Self(Scope::Successor { floor })
    }

    fn successor(inputs: &crate::serving_authority::SuccessorPolicyInputs) -> Self {
        Self(Scope::Successor {
            floor: inputs.generation_floor(),
        })
    }

    /// The generation floor every derivation under this scope must exceed.
    pub(crate) const fn floor(&self) -> ExecutionGeneration {
        match self.0 {
            Scope::Original { floor } | Scope::Successor { floor } => floor,
        }
    }
}

/// Folds one key's exact observed revision into `reads` as a CAS fence.
/// Derives `G = 1 + max(floor, every verified input generation)` from already
/// verified, already CAS-fenced observations.
///
/// Callers must declare a tracked subject's previous semantic value as a
/// verified input when overwriting it. Folding does not invent dependencies
/// from blind writes; a nonadvancing provenance write refuses rather than
/// silently repairing the generation.
///
/// A present input without matching authenticated provenance fails closed, and
/// overflow is a typed refusal before any signature or commit.
///
/// The floor is the invocation scope floor: the profile genesis floor for
/// the original namespace (byte-identical to the historical derivation) or
/// the verified cut binding floor for a successor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_scoped<S: VersionedStateReader + ?Sized>(
    scope: &GenerationScope,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    profile: &LogicalProfileRecord,
    head_reads: &[DurableObjectHeadRead],
    nonce: Option<&PendingSenderNonceWrite>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<LogicalDerivation, NodeCoreError> {
    if head_reads.len() > MAX_LOGICAL_PROVENANCE_SUBJECTS {
        return Err(invariant(SUBJECT_COUNT));
    }
    let keys: LogicalKeySpace<'_> = LogicalKeySpace::new(profile, resolver);
    let floor: ExecutionGeneration = scope.floor();
    let subjects: Vec<(Vec<u8>, StateRevision)> =
        logical_subjects(reads, nonce.map(|pending| pending.key.as_slice()))?;
    let mut folded: Folded = Folded {
        dependencies: Vec::new(),
        inputs: BTreeMap::new(),
        reads: BTreeMap::new(),
    };
    fold_state_reads(
        store,
        context,
        domain,
        resolver,
        &keys,
        subjects,
        reads,
        &mut folded,
    )?;
    fold_object_reads(
        store,
        context,
        domain,
        &keys,
        head_reads,
        reads,
        &mut folded,
    )?;
    fold_nonce_read(store, context, domain, &keys, nonce, reads, &mut folded)?;
    let generation: ExecutionGeneration =
        ExecutionGeneration::successor_of(floor, &folded.dependencies).map_err(
            |ExecutionGenerationOverflow| NodeCoreError::ExecutionGenerationOverflow {
                floor: floor.get(),
            },
        )?;
    Ok(LogicalDerivation {
        generation,
        reads: folded.reads,
        inputs: folded.inputs,
    })
}

#[allow(clippy::too_many_arguments)]
impl LogicalDerivation {
    /// Returns the verified previous generation of one subject, if this
    /// operation actually observed it as an authenticated input.
    ///
    /// A leg may replace its physical creation-checkpoint comparison with the
    /// authenticated generation ordering only when this returns `Some`.
    pub(crate) fn input(&self, subject: &LogicalSubject) -> Option<ExecutionGeneration> {
        self.inputs.get(subject).copied()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn provenance_mutations<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    profile: &LogicalProfileRecord,
    epoch: Epoch,
    derived: &LogicalDerivation,
    writes: &[LogicalWrite],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Vec<StateMutationEntry>, NodeCoreError> {
    if writes.len() > MAX_LOGICAL_PROVENANCE_SUBJECTS {
        return Err(invariant(SUBJECT_COUNT));
    }
    let generation: ExecutionGeneration = derived.generation;
    let keys: LogicalKeySpace<'_> = LogicalKeySpace::new(profile, resolver);
    let mut seen: BTreeSet<LogicalSubject> = BTreeSet::new();
    let mut out: Vec<StateMutationEntry> = Vec::with_capacity(writes.len());
    for write in writes {
        let fresh: bool = seen.insert(write.subject.clone());
        if !fresh {
            return Err(invariant("duplicate logical provenance write"));
        }
        require_advancing_input(derived, write, generation)?;
        let entry: StateMutationEntry = provenance_mutation(
            store, context, domain, &keys, epoch, generation, write, reads,
        )?;
        out.push(entry);
    }
    Ok(out)
}

/// [`provenance_mutations`] for a derivation made under `scope`: the derived
/// generation must strictly exceed the scope floor. The rows are written at
/// the derived generation, exactly like the original path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn provenance_mutations_scoped<S: VersionedStateReader + ?Sized>(
    scope: &GenerationScope,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    profile: &LogicalProfileRecord,
    epoch: Epoch,
    derived: &LogicalDerivation,
    writes: &[LogicalWrite],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Vec<StateMutationEntry>, NodeCoreError> {
    if derived.generation <= scope.floor() {
        return Err(NodeCoreError::ExecutionGenerationRegression {
            previous: scope.floor().get(),
            attempted: derived.generation.get(),
        });
    }
    provenance_mutations(
        store, context, domain, resolver, profile, epoch, derived, writes, reads,
    )
}

#[allow(clippy::too_many_arguments)]
fn provenance_mutation<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    keys: &LogicalKeySpace<'_>,
    epoch: Epoch,
    generation: ExecutionGeneration,
    write: &LogicalWrite,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<StateMutationEntry, NodeCoreError> {
    let previous: Option<LogicalProvenanceRecord> =
        fence_provenance(store, context, domain, keys, &write.subject, reads)?;
    if let Some(row) = previous
        && row.generation >= generation
    {
        return Err(NodeCoreError::ExecutionGenerationRegression {
            previous: row.generation.get(),
            attempted: generation.get(),
        });
    }
    let record: LogicalProvenanceRecord = LogicalProvenanceRecord {
        subject: write.subject.clone(),
        observed_epoch: epoch,
        generation,
        observation: write.observation,
    };
    let key: Vec<u8> = keys.provenance_key(&write.subject)?;
    let bytes: Vec<u8> = encode_logical_provenance_record(&record)?;
    Ok(StateMutationEntry::new(key, StateMutation::Put(bytes))?)
}

/// Derives the provenance writes one staged admission must install.
///
/// Every non-excluded staged state mutation, every object mutation and the
/// sender-nonce write become exactly one subject each. A deletion keeps its
/// tombstone observation, taken from the exact observed head, so a tombstone is
/// never recorded as absence. Every caller stages the sender-nonce row's own
/// `Put` into `state_mutations` *and* passes it again as `nonce`, exactly like
/// every other staged mutation; the nonce key is skipped in the
/// `state_mutations` loop below for the same reason [`logical_subjects`]
/// skips it on the read side: it is one subject with one closed `NonceNext`
/// observation, never also a generic state key, so this operation installs
/// exactly one provenance row for it instead of two disagreeing rows for the
/// same physical value. If the nonce key is already staged, its bytes must
/// match the reserved canonical next-nonce write before it is skipped.
fn object_write_observation(
    entry: &DurableObjectMutationEntry,
    head_reads: &[DurableObjectHeadRead],
) -> Result<LogicalObservation, NodeCoreError> {
    if let DurableObjectMutation::Create { version, .. }
    | DurableObjectMutation::Update { version, .. } = entry.mutation()
    {
        return Ok(LogicalObservation::ObjectLive {
            object_version: version.object_version().get(),
            digest: version.digest(),
        });
    }
    let found = head_reads
        .iter()
        .find(|read| read.object_id() == entry.object_id());
    let head: &DurableObjectHeadRead =
        found.ok_or(provenance_error("deletion without an observed head"))?;
    if let DurableObjectHead::Current { object_version, .. } = head.expected() {
        return Ok(LogicalObservation::ObjectDeleted {
            last_object_version: object_version.get(),
        });
    }
    Err(provenance_error("deletion of a non-live object head"))
}

pub(crate) fn staged_writes(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    state_mutations: &[StateMutationEntry],
    object_mutations: &[DurableObjectMutationEntry],
    head_reads: &[DurableObjectHeadRead],
    nonce: Option<&PendingSenderNonceWrite>,
) -> Result<Vec<LogicalWrite>, NodeCoreError> {
    let nonce_key: Option<&[u8]> = nonce.map(|pending| pending.key.as_slice());
    let nonce_value: Option<Vec<u8>> = nonce.map(|pending| pending.record.encode()).transpose()?;
    let mut writes: Vec<LogicalWrite> = Vec::new();
    for entry in state_mutations {
        if nonce_key == Some(entry.key()) {
            match (entry.mutation(), nonce_value.as_deref()) {
                (StateMutation::Put(actual), Some(expected)) if actual.as_slice() == expected => {}
                _ => {
                    return Err(provenance_error(
                        "sender nonce mutation differs from reservation",
                    ));
                }
            }
            continue;
        }
        if is_excluded_subject(entry.key()) {
            continue;
        }
        let observation: LogicalObservation = match entry.mutation() {
            StateMutation::Assert => continue,
            StateMutation::Put(value) => LogicalObservation::StatePresent {
                content_digest: content_digest(resolver, epoch, value)?,
            },
            StateMutation::Delete => LogicalObservation::StateDeleted,
        };
        writes.push(LogicalWrite {
            subject: LogicalSubject::StateKey(entry.key().to_vec()),
            observation,
        });
    }
    for entry in object_mutations {
        writes.push(LogicalWrite {
            subject: LogicalSubject::Object(entry.object_id()),
            observation: object_write_observation(entry, head_reads)?,
        });
    }
    if let Some(pending) = nonce {
        writes.push(LogicalWrite {
            subject: LogicalSubject::SenderNonce {
                sender: pending.record.sender,
                epoch: pending.record.epoch,
            },
            observation: LogicalObservation::NonceNext {
                next_nonce: pending.record.next_nonce,
            },
        });
    }
    Ok(writes)
}

/// Deterministic signed operand bytes for one exact subject identity.
///
/// Used by the `0x6424/v2` commitment envelope, which signs the complete
/// verified dependency set. Tagged and length-free per variant because every
/// identity component is fixed width or terminates the operand, so two distinct
/// subjects can never share operand bytes.
pub(crate) fn subject_operand(subject: &LogicalSubject) -> Vec<u8> {
    match subject {
        LogicalSubject::StateKey(key) => {
            let mut out: Vec<u8> = vec![1u8];
            out.extend_from_slice(&(key.len() as u32).to_be_bytes());
            out.extend_from_slice(key);
            out
        }
        LogicalSubject::Object(object_id) => {
            let mut out: Vec<u8> = vec![2u8];
            out.extend_from_slice(object_id.as_bytes());
            out
        }
        LogicalSubject::SenderNonce { sender, epoch } => {
            let mut out: Vec<u8> = vec![3u8];
            out.extend_from_slice(sender);
            out.extend_from_slice(&epoch.get().to_be_bytes());
            out
        }
    }
}

/// Deterministic signed operand bytes for one closed semantic observation.
///
/// A never-written subject is tag `0`, distinct from `StateDeleted`'s tag, so
/// the `0x6424/v2` envelope signs the absent/tombstoned distinction rather than
/// collapsing it.
pub(crate) fn observation_operand(observation: Option<LogicalObservation>) -> Vec<u8> {
    let Some(observed) = observation else {
        return vec![0u8];
    };
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&observed.tag().to_be_bytes());
    match observed {
        LogicalObservation::StatePresent { content_digest } => {
            out.extend_from_slice(&content_digest.bytes());
        }
        LogicalObservation::StateDeleted => {}
        LogicalObservation::ObjectLive {
            object_version,
            digest,
        } => {
            out.extend_from_slice(&digest.bytes());
            out.extend_from_slice(&object_version.to_be_bytes());
        }
        LogicalObservation::ObjectDeleted {
            last_object_version,
        } => out.extend_from_slice(&last_object_version.to_be_bytes()),
        LogicalObservation::NonceNext { next_nonce } => {
            out.extend_from_slice(&next_nonce.to_be_bytes());
        }
    }
    out
}

/// Requires each written subject's own verified input generation to precede the
/// derived generation, and each never-written subject to stay unwritten.
///
/// `successor_of` already guarantees the first property; this keeps the exact
/// authenticated per-subject evidence available at the point of persistence, so
/// a physical-minimum replacement is only ever backed by a proven subject `G`.
fn require_advancing_input(
    derived: &LogicalDerivation,
    write: &LogicalWrite,
    generation: ExecutionGeneration,
) -> Result<(), NodeCoreError> {
    if let Some(previous) = derived.input(&write.subject)
        && previous >= generation
    {
        return Err(NodeCoreError::ExecutionGenerationRegression {
            previous: previous.get(),
            attempted: generation.get(),
        });
    }
    if let LogicalSubject::StateKey(key) = &write.subject
        && derived
            .reads
            .get(key)
            .is_some_and(|seen| seen.observed.is_none())
        && derived.input(&write.subject).is_some()
    {
        return Err(provenance_error(
            "an unwritten subject cannot carry an input generation",
        ));
    }
    Ok(())
}

/// Derives the authenticated provenance a handoff-capable genesis installs for
/// everything it creates.
///
/// A fresh store's first operation observes genesis-installed state and objects
/// as ordinary verified inputs, so each needs its own authenticated row at the
/// profile's explicit genesis floor. Without them the new profile would be
/// fail-closed but unusable: every later derivation would refuse for missing
/// provenance on rows genesis itself wrote. Rows this module owns and the
/// separately authenticated fast-path families are never generic subjects.
///
/// Every row is written at exactly `profile.genesis_floor`, so the first
/// operation over any of them derives `1 + floor` and strictly advances.
pub(crate) fn genesis_provenance(
    profile: &LogicalProfileRecord,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    state_mutations: &[StateMutationEntry],
    object_mutations: &[DurableObjectMutationEntry],
) -> Result<Vec<StateMutationEntry>, NodeCoreError> {
    let writes: Vec<LogicalWrite> = staged_writes(
        resolver,
        epoch,
        state_mutations,
        object_mutations,
        &[],
        None,
    )?;
    if writes.len() > MAX_LOGICAL_PROVENANCE_SUBJECTS {
        return Err(invariant(SUBJECT_COUNT));
    }
    let keys: LogicalKeySpace<'_> = LogicalKeySpace::new(profile, resolver);
    let mut seen: BTreeSet<LogicalSubject> = BTreeSet::new();
    let mut rows: Vec<StateMutationEntry> = Vec::with_capacity(writes.len());
    for write in &writes {
        if !seen.insert(write.subject.clone()) {
            return Err(invariant("duplicate genesis provenance subject"));
        }
        let record: LogicalProvenanceRecord = LogicalProvenanceRecord {
            subject: write.subject.clone(),
            observed_epoch: epoch,
            generation: profile.genesis_floor,
            observation: write.observation,
        };
        rows.push(StateMutationEntry::new(
            keys.provenance_key(&write.subject)?,
            StateMutation::Put(encode_logical_provenance_record(&record)?),
        )?);
    }
    Ok(rows)
}

fn logical_subjects(
    reads: &BTreeMap<Vec<u8>, StateRevision>,
    nonce_key: Option<&[u8]>,
) -> Result<Vec<(Vec<u8>, StateRevision)>, NodeCoreError> {
    let subjects: Vec<(Vec<u8>, StateRevision)> = reads
        .iter()
        // The sender-nonce row is a `LogicalSubject::SenderNonce` subject with
        // its own closed `NonceNext` observation. Folding it a second time as a
        // generic state key would demand two provenance rows for one row and
        // fail closed on the very next operation, so it is excluded here and
        // observed exactly once by `fold_nonce_read`.
        .filter(|(key, _)| {
            !is_excluded_subject(key) && nonce_key.is_none_or(|nonce| key.as_slice() != nonce)
        })
        .map(|(key, revision)| (key.clone(), *revision))
        .collect();
    if subjects.len() > MAX_LOGICAL_PROVENANCE_SUBJECTS {
        return Err(invariant(SUBJECT_COUNT));
    }
    Ok(subjects)
}

/// Verifies the exact sender-nonce row this operation advances against its own
/// authenticated provenance, and folds that row's generation in as a real
/// causal dependency.
///
/// The row is re-read under the exact revision the reservation already fenced,
/// so a concurrent advance refuses here instead of producing a generation
/// derived from a nonce state this operation never actually observed. A row that
/// exists without matching authenticated provenance fails closed; a pristine
/// row carries no provenance and contributes no dependency.
fn fold_nonce_read<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    keys: &LogicalKeySpace<'_>,
    nonce: Option<&PendingSenderNonceWrite>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    folded: &mut Folded,
) -> Result<(), NodeCoreError> {
    let Some(pending) = nonce else {
        return Ok(());
    };
    let sender: [u8; 32] = pending.record.sender;
    let epoch: Epoch = pending.record.epoch;
    let observed: query::SenderNextNonceObservation =
        query::read_sender_next_nonce(store, context, domain, &pending.key, sender, epoch)?;
    if observed.revision != pending.read_revision {
        return Err(NodeCoreError::StateConflict);
    }
    let subject: LogicalSubject = LogicalSubject::SenderNonce { sender, epoch };
    let row: Option<LogicalProvenanceRecord> =
        fence_provenance(store, context, domain, keys, &subject, reads)?;
    if observed.revision == StateRevision::INITIAL {
        if row.is_some() {
            return Err(provenance_error(MISMATCHED_PROVENANCE));
        }
        return Ok(());
    }
    let Some(record) = row else {
        return Err(provenance_error(MISSING_PROVENANCE));
    };
    if record.observation
        != (LogicalObservation::NonceNext {
            next_nonce: observed.next_nonce,
        })
    {
        return Err(provenance_error(MISMATCHED_PROVENANCE));
    }
    folded.dependencies.push(record.generation);
    folded.inputs.insert(subject, record.generation);
    Ok(())
}

fn fold_object_reads<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    keys: &LogicalKeySpace<'_>,
    head_reads: &[DurableObjectHeadRead],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    folded: &mut Folded,
) -> Result<(), NodeCoreError> {
    for head_read in head_reads {
        let found: Option<ExecutionGeneration> =
            observe_object_subject(store, context, domain, keys, head_read, reads)?;
        if let Some(generation) = found {
            folded.dependencies.push(generation);
            folded
                .inputs
                .insert(LogicalSubject::Object(head_read.object_id()), generation);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fold_state_reads<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    keys: &LogicalKeySpace<'_>,
    subjects: Vec<(Vec<u8>, StateRevision)>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    folded: &mut Folded,
) -> Result<(), NodeCoreError> {
    for (key, fenced) in subjects {
        let seen: ReadObservation =
            observe_state_subject(store, context, domain, resolver, keys, &key, fenced, reads)?;
        if let Some(generation) = seen.generation {
            folded.dependencies.push(generation);
            folded
                .inputs
                .insert(LogicalSubject::StateKey(key.clone()), generation);
        }
        folded.reads.insert(key, seen);
    }
    Ok(())
}

/// Accumulators one derivation fills while folding verified inputs.
struct Folded {
    dependencies: Vec<ExecutionGeneration>,
    inputs: BTreeMap<LogicalSubject, ExecutionGeneration>,
    reads: BTreeMap<Vec<u8>, ReadObservation>,
}

/// Verifies one object head against its authenticated provenance row.
///
/// Absence carries no row at all; a tombstone carries one and is never treated
/// as never-created.
fn observe_object_subject<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    keys: &LogicalKeySpace<'_>,
    head_read: &DurableObjectHeadRead,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Option<ExecutionGeneration>, NodeCoreError> {
    let subject: LogicalSubject = LogicalSubject::Object(head_read.object_id());
    let row: Option<LogicalProvenanceRecord> =
        fence_provenance(store, context, domain, keys, &subject, reads)?;
    let Some(expected) = expected_head_observation(head_read.expected()) else {
        if row.is_none() {
            return Ok(None);
        }
        return Err(provenance_error(MISMATCHED_PROVENANCE));
    };
    let Some(record) = row else {
        return Err(provenance_error(MISSING_PROVENANCE));
    };
    if record.observation != expected {
        return Err(provenance_error(MISMATCHED_PROVENANCE));
    }
    Ok(Some(record.generation))
}

fn expected_head_observation(head: &DurableObjectHead) -> Option<LogicalObservation> {
    match head {
        DurableObjectHead::Absent => None,
        DurableObjectHead::Tombstoned {
            last_object_version,
            ..
        } => Some(LogicalObservation::ObjectDeleted {
            last_object_version: last_object_version.get(),
        }),
        DurableObjectHead::Current {
            object_version,
            digest,
            ..
        } => Some(LogicalObservation::ObjectLive {
            object_version: object_version.get(),
            digest: *digest,
        }),
    }
}

/// Verifies one generic state read against its authenticated provenance row.
///
/// The value is re-read under the revision admission already fenced, so a
/// concurrent physical CAS conflict refuses instead of silently observing a
/// newer value beneath an older fence.
#[allow(clippy::too_many_arguments)]
fn observe_state_subject<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    keys: &LogicalKeySpace<'_>,
    key: &[u8],
    fenced: StateRevision,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<ReadObservation, NodeCoreError> {
    let seen: VersionedStateValue = store.read_versioned_state(context, domain, key)?;
    if seen.revision() != fenced {
        return Err(NodeCoreError::StateConflict);
    }
    let subject: LogicalSubject = LogicalSubject::StateKey(key.to_vec());
    let row: Option<LogicalProvenanceRecord> =
        fence_provenance(store, context, domain, keys, &subject, reads)?;
    let Some(record) = row else {
        if seen.value().is_none() && seen.revision() == StateRevision::INITIAL {
            return Ok(ReadObservation {
                observed: None,
                generation: None,
            });
        }
        return Err(provenance_error(MISSING_PROVENANCE));
    };
    let expected: LogicalObservation = match seen.value() {
        Some(value) => LogicalObservation::StatePresent {
            content_digest: content_digest(resolver, record.observed_epoch, value)?,
        },
        None => LogicalObservation::StateDeleted,
    };
    if record.observation != expected {
        return Err(provenance_error(MISMATCHED_PROVENANCE));
    }
    Ok(ReadObservation {
        observed: Some(record.observation),
        generation: Some(record.generation),
    })
}

fn fence_provenance<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    keys: &LogicalKeySpace<'_>,
    subject: &LogicalSubject,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Option<LogicalProvenanceRecord>, NodeCoreError> {
    let key: Vec<u8> = keys.provenance_key(subject)?;
    let seen: VersionedStateValue = fence_read(store, context, domain, key, reads)?;
    if let Some(bytes) = seen.value() {
        let record: LogicalProvenanceRecord = decode_logical_provenance_record(bytes)?;
        if &record.subject != subject {
            return Err(provenance_error(FOREIGN_SUBJECT));
        }
        return Ok(Some(record));
    }
    if seen.revision() == StateRevision::INITIAL {
        return Ok(None);
    }
    Err(provenance_error("logical provenance row was removed"))
}

/// Requires every live application path to carry exactly the evidence its own
/// store's signed genesis binding demands.
///
/// [`admit_resolved`] calls this for every application path that applies
/// effects, a receipt, a nonce advance or a settlement against an
/// *already-installed* profile -- paid execution, local execution,
/// publication, bond lifecycle, fee-claim settlement and the generic
/// durable-event path all reach it through [`admit_application`] or
/// [`admit_generic_transition`]. It is deliberately not satisfiable by a bare
/// profile argument:
///
/// * a [`InstalledCommitmentProfile::Logical`] store with no derivation is
///   refused. Absence of evidence is never an active legacy fallback for a
///   store whose signed genesis bound the new profile: such a store applies
///   only with an authenticated [`ExecutionGeneration`] it actually derived
///   from verified inputs;
/// * a derived generation that does not strictly exceed the profile's own
///   authenticated genesis floor is refused, so a caller cannot present a
///   replayed or fabricated floor-level generation as evidence;
/// * a [`InstalledCommitmentProfile::Historical`] store keeps its exact
///   existing physical behavior and must carry no logical evidence at all, so
///   the two models can never be mixed inside one commit.
///
/// Exact original completed replay stays receipt-first ahead of this refusal,
/// and historical verification paths never call it at all: they read and verify
/// recorded bytes without applying anything. A handoff-capable genesis is the
/// one exception by construction, not an oversight: [`genesis_provenance`]
/// installs a fresh store's first provenance rows directly, because no
/// profile is installed yet for this gate to resolve against.
pub(crate) fn require_application_admissible(
    installed: &InstalledCommitmentProfile,
    derived: Option<&LogicalDerivation>,
) -> Result<(), NodeCoreError> {
    match installed {
        InstalledCommitmentProfile::Logical(record) => require_application_admissible_scoped(
            &GenerationScope::from_profile(record),
            installed,
            derived,
        ),
        InstalledCommitmentProfile::Historical => {
            require_application_admissible_scoped_historical(derived)
        }
    }
}

fn require_application_admissible_scoped_historical(
    derived: Option<&LogicalDerivation>,
) -> Result<(), NodeCoreError> {
    match derived {
        None => Ok(()),
        Some(_) => Err(NodeCoreError::LogicalProfileApplicationUnsupported),
    }
}

/// [`require_application_admissible`] under one invocation gate.
pub(crate) fn require_application_admissible_gated(
    gate: crate::serving_authority::ServingGate<'_>,
    installed: &InstalledCommitmentProfile,
    derived: Option<&LogicalDerivation>,
) -> Result<(), NodeCoreError> {
    match installed {
        InstalledCommitmentProfile::Logical(record) => require_application_admissible_scoped(
            &gate.generation_scope(record),
            installed,
            derived,
        ),
        InstalledCommitmentProfile::Historical => {
            require_application_admissible_scoped_historical(derived)
        }
    }
}

/// [`require_application_admissible`] under an explicit [`GenerationScope`]:
/// a logical store must carry a derivation strictly above the scope floor
/// (the genesis floor for the original namespace, the verified cut binding
/// floor for a first successor).
pub(crate) fn require_application_admissible_scoped(
    scope: &GenerationScope,
    installed: &InstalledCommitmentProfile,
    derived: Option<&LogicalDerivation>,
) -> Result<(), NodeCoreError> {
    match (installed, derived) {
        (InstalledCommitmentProfile::Historical, None) => Ok(()),
        (InstalledCommitmentProfile::Logical(_), Some(derivation)) => {
            if derivation.generation > scope.floor() {
                Ok(())
            } else {
                Err(NodeCoreError::ExecutionGenerationRegression {
                    previous: scope.floor().get(),
                    attempted: derivation.generation.get(),
                })
            }
        }
        _ => Err(NodeCoreError::LogicalProfileApplicationUnsupported),
    }
}

/// [`admit_application`] for a caller whose read set is already a list of exact
/// revision assertions rather than a working map.
///
/// The caller's existing assertions are converted for derivation and only the
/// reads this derivation newly fenced are appended, so the caller's own
/// duplicate-key strictness is untouched: nothing here merges, rewrites or
/// silently drops one of its assertions.
///
/// A historical store appends nothing at all. Its binding was already read and
/// found absent, and asserting that row would consume one slot of this
/// operation's bounded read set -- enough to stop a maximal application plan
/// fitting -- while protecting against nothing: the row can only ever be
/// written by a fresh `install_genesis`, which refuses outright once a marker
/// exists, and a row that appears under a historical manifest is refused by that
/// manifest's own reopen verification.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_generic_transition<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    installed: InstalledCommitmentProfile,
    epoch: Epoch,
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    nonce: Option<&PendingSenderNonceWrite>,
    fenced: &BTreeMap<Vec<u8>, StateRevision>,
    state_mutations: &mut Vec<StateMutationEntry>,
    reads: &mut Vec<StateReadAssertion>,
) -> Result<(), NodeCoreError> {
    let mut working: BTreeMap<Vec<u8>, StateRevision> = reads
        .iter()
        .map(|assertion| (assertion.key().to_vec(), assertion.expected_revision()))
        .collect();
    let existing: BTreeSet<Vec<u8>> = working.keys().cloned().collect();
    if installed.logical().is_some() {
        // A handoff-capable store commits under a real compare-and-swap fence on
        // the exact binding revision the caller already observed.
        for (key, revision) in fenced {
            working.insert(key.clone(), *revision);
        }
    }
    let admitted: LogicalAdmission = admit_resolved(
        store,
        context,
        domain,
        resolver,
        installed,
        epoch,
        head_reads,
        object_mutations,
        nonce,
        state_mutations,
        &mut working,
    )?;
    if admitted.derived.is_none() {
        return Ok(());
    }
    for (key, revision) in working {
        if !existing.contains(&key) {
            reads.push(StateReadAssertion::new(key, revision)?);
        }
    }
    Ok(())
}

/// Which rule bounds one observed object's semantic monotonicity.
///
/// The historical profile's rule is the immutable local creation checkpoint.
/// The handoff-capable profile's rule is the subject's authenticated
/// generation, which [`provenance_mutations`] enforces for every object this
/// operation observed before the commit; the local creation checkpoint is then
/// a persistence and audit input only, and must not gate admission, because a
/// node serving a later epoch legitimately holds its own local checkpoint
/// sequence and the physical comparison would otherwise reject every valid
/// operation after a quorum handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectMinimum {
    /// Historical: this operation's own local checkpoint may not precede the
    /// observed version's creation checkpoint.
    CreationCheckpoint(u64),
    /// Handoff-capable: the authenticated generation ordering bounds this
    /// subject instead, proven per subject by the same admission.
    AuthenticatedGeneration,
}

impl ObjectMinimum {
    /// The same monotonicity rule under the owning invocation capability.
    /// A missing logical profile in successor/replay is corruption, never a
    /// reason to reinstate a physical checkpoint comparison.
    pub(crate) fn for_gate(
        installed: &InstalledCommitmentProfile,
        local_checkpoint: u64,
        gate: crate::serving_authority::ServingGate<'_>,
    ) -> Result<Self, NodeCoreError> {
        match installed {
            InstalledCommitmentProfile::Logical(profile) => {
                Self::for_scope(installed, local_checkpoint, &gate.generation_scope(profile))
            }
            InstalledCommitmentProfile::Historical => match gate {
                crate::serving_authority::ServingGate::Original => {
                    Ok(Self::CreationCheckpoint(local_checkpoint))
                }
                crate::serving_authority::ServingGate::Successor(_)
                | crate::serving_authority::ServingGate::Replay(_) => Err(invariant(
                    "successor object admission has no logical profile",
                )),
            },
        }
    }

    /// Uses the invocation's authenticated generation scope. A successor or
    /// replay cannot fall back to physical creation checkpoints.
    pub(crate) fn for_scope(
        installed: &InstalledCommitmentProfile,
        local_checkpoint: u64,
        scope: &GenerationScope,
    ) -> Result<Self, NodeCoreError> {
        match (installed, &scope.0) {
            (InstalledCommitmentProfile::Historical, Scope::Successor { .. }) => Err(invariant(
                "successor object admission has no logical profile",
            )),
            _ => Ok(Self::for_profile(installed, local_checkpoint)),
        }
    }
    /// Resolves the rule this store's own signed binding actually implies.
    pub(crate) const fn for_profile(
        installed: &InstalledCommitmentProfile,
        local_checkpoint: u64,
    ) -> Self {
        match installed {
            InstalledCommitmentProfile::Historical => Self::CreationCheckpoint(local_checkpoint),
            InstalledCommitmentProfile::Logical(_) => Self::AuthenticatedGeneration,
        }
    }

    /// True when the observed version's creation checkpoint is admissible.
    pub(crate) const fn admits(self, created_checkpoint: u64) -> bool {
        match self {
            Self::CreationCheckpoint(checkpoint) => checkpoint >= created_checkpoint,
            Self::AuthenticatedGeneration => true,
        }
    }
}

/// One application path's complete DR-0154 admission result.
///
/// Produced only by [`admit_application`]. The derivation is `Some` exactly
/// when the store's signed genesis bound the handoff-capable profile, so a
/// caller cannot hold this value and still be unsure which rules apply.
pub(crate) struct LogicalAdmission {
    /// The store's resolved, authenticated binding.
    pub(crate) profile: InstalledCommitmentProfile,
    /// The authenticated generation and verified dependency set, when the
    /// binding is handoff-capable.
    pub(crate) derived: Option<LogicalDerivation>,
}

impl LogicalDerivation {
    /// Returns the authenticated generation this operation derived.
    pub(crate) const fn generation(&self) -> ExecutionGeneration {
        self.generation
    }

    /// Returns the exact per-key read observations the `0x6424/v2` envelope
    /// signs in place of physical state revisions.
    pub(crate) const fn read_observations(&self) -> &BTreeMap<Vec<u8>, ReadObservation> {
        &self.reads
    }

    /// Returns the complete verified dependency set the `0x6424/v2` envelope
    /// signs: every input subject, including the sender nonce, with the exact
    /// authenticated generation this derivation depended on.
    pub(crate) const fn dependencies(&self) -> &BTreeMap<LogicalSubject, ExecutionGeneration> {
        &self.inputs
    }
}

/// Performs every DR-0154 obligation one application path owes, in one place.
///
/// Resolves the store's signed binding, derives the authenticated generation
/// from the complete verified input set, appends the provenance rows the same
/// atomic commit must install, and refuses unless this path carries exactly the
/// evidence its binding demands. Call it once, after the path has staged every
/// state mutation it intends to write and before it reserves, commits or
/// exposes a signature: the derived provenance rows join `state_mutations`, so
/// an earlier call would authenticate an incomplete write set.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_application<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    epoch: Epoch,
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    nonce: Option<&PendingSenderNonceWrite>,
    state_mutations: &mut Vec<StateMutationEntry>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<LogicalAdmission, NodeCoreError> {
    let installed: InstalledCommitmentProfile =
        fence_commitment_profile(store, context, domain, chain, reads)?;
    admit_resolved_gated(
        crate::serving_authority::ServingGate::Original,
        store,
        context,
        domain,
        resolver,
        installed,
        epoch,
        head_reads,
        object_mutations,
        nonce,
        state_mutations,
        reads,
    )
}

/// [`admit_application`] under one invocation gate: a successor derives and
/// admits above its verified cut floor and writes provenance only at its
/// verified epoch. The original gate is exactly [`admit_application`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_application_gated<S: VersionedStateReader + ?Sized>(
    gate: crate::serving_authority::ServingGate<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    chain: &ChainId,
    epoch: Epoch,
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    nonce: Option<&PendingSenderNonceWrite>,
    state_mutations: &mut Vec<StateMutationEntry>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<LogicalAdmission, NodeCoreError> {
    let installed: InstalledCommitmentProfile =
        fence_commitment_profile(store, context, domain, chain, reads)?;
    admit_resolved_gated(
        gate,
        store,
        context,
        domain,
        resolver,
        installed,
        epoch,
        head_reads,
        object_mutations,
        nonce,
        state_mutations,
        reads,
    )
}

/// [`admit_application`] for a caller that already resolved this store's signed
/// binding earlier in the same operation.
///
/// Separate so such a caller performs exactly one profile read rather than two:
/// the generic durable-event path must resolve the binding before it translates
/// object effects, and re-reading it here would both duplicate that read and
/// consume a second slot in the operation's bounded read set.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_resolved<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    installed: InstalledCommitmentProfile,
    epoch: Epoch,
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    nonce: Option<&PendingSenderNonceWrite>,
    state_mutations: &mut Vec<StateMutationEntry>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<LogicalAdmission, NodeCoreError> {
    admit_resolved_gated(
        crate::serving_authority::ServingGate::Original,
        store,
        context,
        domain,
        resolver,
        installed,
        epoch,
        head_reads,
        object_mutations,
        nonce,
        state_mutations,
        reads,
    )
}

/// [`admit_resolved`] under one invocation gate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_resolved_gated<S: VersionedStateReader + ?Sized>(
    gate: crate::serving_authority::ServingGate<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    installed: InstalledCommitmentProfile,
    epoch: Epoch,
    head_reads: &[DurableObjectHeadRead],
    object_mutations: &[DurableObjectMutationEntry],
    nonce: Option<&PendingSenderNonceWrite>,
    state_mutations: &mut Vec<StateMutationEntry>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<LogicalAdmission, NodeCoreError> {
    let Some(record) = installed.logical().cloned() else {
        require_application_admissible(&installed, None)?;
        return Ok(LogicalAdmission {
            profile: installed,
            derived: None,
        });
    };
    let scope: GenerationScope = gate.generation_scope(&record);
    let derived: LogicalDerivation = derive_scoped(
        &scope, store, context, domain, resolver, &record, head_reads, nonce, reads,
    )?;
    let writes: Vec<LogicalWrite> = staged_writes(
        resolver,
        epoch,
        state_mutations,
        object_mutations,
        head_reads,
        nonce,
    )?;
    let rows: Vec<StateMutationEntry> = provenance_mutations_scoped(
        &scope, store, context, domain, resolver, &record, epoch, &derived, &writes, reads,
    )?;
    state_mutations.extend(rows);
    require_application_admissible_scoped(&scope, &installed, Some(&derived))?;
    Ok(LogicalAdmission {
        profile: installed,
        derived: Some(derived),
    })
}

/// Which commitment model a store's own installed genesis actually bound.
///
/// This is the resolved, authenticated answer, not a caller preference: it is
/// produced only by [`fence_commitment_profile`] from the exact durable row the
/// signed [`crate::genesis::GenesisManifest`] installed and which genesis
/// reopen re-verifies byte for byte.
pub(crate) enum InstalledCommitmentProfile {
    /// The store carries no profile row and its slot is pristine: a store whose
    /// signed genesis is historical. It keeps exactly its existing physical
    /// admission, commitment and monotonicity rules.
    Historical,
    /// The store carries exactly one authenticated handoff-capable row.
    Logical(LogicalProfileRecord),
}

impl InstalledCommitmentProfile {
    /// Returns the authenticated record when this store is handoff-capable.
    pub(crate) const fn logical(&self) -> Option<&LogicalProfileRecord> {
        match self {
            Self::Historical => None,
            Self::Logical(record) => Some(record),
        }
    }
}

/// Resolves a store's installed commitment profile.
///
/// Fails closed rather than degrading: a removed row (absent value at a
/// non-initial revision) and a row binding the historical model are both
/// refusals, so no handoff-capable store can be talked back into physical
/// admission by deleting or downgrading its own binding.
///
/// A [`InstalledCommitmentProfile::Logical`] result fences the exact observed
/// revision of the row into `reads`, so its successor is written under a real
/// compare-and-swap fence. A [`InstalledCommitmentProfile::Historical`]
/// result installs no fence at all: that row can only ever be written once,
/// by a fresh `install_genesis` that refuses outright once any marker
/// exists, so it can never regress from absent to present inside one
/// already-serving store's lifetime, and asserting it would only cost one
/// slot of the caller's bounded read set for zero protective value -- the
/// same reasoning [`admit_generic_transition`] already documents for its own
/// historical case, now uniform for every caller of this function.
pub(crate) fn fence_commitment_profile<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<InstalledCommitmentProfile, NodeCoreError> {
    let key: Vec<u8> = logical_profile_key(chain)?;
    let seen: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
    if let Some(previous) = reads.get(&key)
        && *previous != seen.revision()
    {
        return Err(NodeCoreError::StateConflict);
    }
    if let Some(bytes) = seen.value() {
        let record: LogicalProfileRecord = decode_installed_profile(bytes, chain)?;
        verify_installed_genesis_binding(store, context, domain, &record, bytes)?;
        reads.insert(key, seen.revision());
        return Ok(InstalledCommitmentProfile::Logical(record));
    }
    if seen.revision() == StateRevision::INITIAL {
        return Ok(InstalledCommitmentProfile::Historical);
    }
    Err(provenance_error("logical profile row was removed"))
}

/// Reconciles a real installed profile with its immutable signed genesis.
/// Legacy in-process fixtures may carry a v1 profile without a manifest;
/// a Freeze-authorized profile never permits that absence or a tombstone.
fn verify_installed_genesis_binding<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    record: &LogicalProfileRecord,
    profile_bytes: &[u8],
) -> Result<(), NodeCoreError> {
    let key: Vec<u8> = crate::genesis::genesis_manifest_key(&record.context)
        .map_err(|_| provenance_error("logical profile genesis key"))?;
    let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
    let Some(bytes) = observed.value() else {
        if record.minimum_freeze_block_height == 0 && observed.revision() == StateRevision::INITIAL
        {
            return Ok(());
        }
        return Err(provenance_error(
            "logical profile signed genesis is missing",
        ));
    };
    let manifest: crate::genesis::GenesisManifest = crate::genesis::decode_genesis_manifest(bytes)
        .map_err(|_| provenance_error("logical profile signed genesis is malformed"))?;
    if manifest.context() != &record.context
        || manifest.commitment_profile != record.profile
        || manifest.genesis_authority != record.genesis_authority
        || !hashing::verify_digest(
            &record.manifest_digest,
            HashPurpose::ProtocolConfig,
            record.context.protocol_version(),
            record.context.chain_id(),
            bytes,
        )?
    {
        return Err(provenance_error(
            "logical profile signed genesis binding differs",
        ));
    }
    // Shares the installer/root's own strict nonzero canonical prime-order
    // Ed25519 authority and signature check, so this installed-row verifier
    // can never accept a weaker authority shape than either (DR-0182).
    crate::genesis::verify_manifest_authority(&manifest).map_err(|_| {
        provenance_error("logical profile genesis authority or signature is invalid")
    })?;
    let expected: LogicalProfileRecord = LogicalProfileRecord {
        context: record.context.clone(),
        profile: manifest.commitment_profile,
        manifest_digest: record.manifest_digest,
        genesis_authority: manifest.genesis_authority,
        genesis_floor: ExecutionGeneration::genesis_floor(),
        minimum_freeze_block_height: manifest.minimum_freeze_block_height,
    };
    if encode_logical_profile_record(&expected)? != profile_bytes {
        return Err(provenance_error(
            "logical profile bytes differ from signed genesis",
        ));
    }
    if record.profile == CommitmentProfile::CausalAdmission {
        let marker_key: Vec<u8> = crate::genesis::genesis_marker_key(&record.context)
            .map_err(|_| provenance_error("causal profile genesis marker key"))?;
        let marker_row: VersionedStateValue =
            store.read_versioned_state(context, domain, &marker_key)?;
        let marker: crate::genesis::GenesisInstallMarker =
            crate::genesis::decode_genesis_install_marker(
                marker_row
                    .value()
                    .ok_or(provenance_error("causal profile genesis marker is missing"))?,
            )
            .map_err(|_| provenance_error("causal profile genesis marker is malformed"))?;
        if marker.context != record.context
            || marker.manifest_digest != record.manifest_digest
            || marker.genesis_authority != record.genesis_authority
        {
            return Err(provenance_error(
                "causal profile genesis marker binding differs",
            ));
        }
    }
    Ok(())
}

fn fence_read<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: Vec<u8>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<VersionedStateValue, NodeCoreError> {
    let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
    if let Some(previous) = reads.insert(key, observed.revision())
        && previous != observed.revision()
    {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(observed)
}

/// Encodes frame `0x6480/v1`.
pub fn encode_logical_profile_record(
    record: &LogicalProfileRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    if record.minimum_freeze_block_height != 0 && !record.profile.is_logical() {
        return Err(invariant("Freeze profile requires LogicalGenerationV2"));
    }
    if record.profile == CommitmentProfile::CausalAdmission
        && record.minimum_freeze_block_height == 0
    {
        return Err(invariant(
            "causal admission requires a positive Freeze height",
        ));
    }
    let context: Vec<u8> = encode_publication_context(&record.context)
        .map_err(|_| NodeCoreError::PersistenceInvariant(PROFILE_CONTEXT))?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        LOGICAL_PROFILE_RECORD_FRAME_TYPE,
        if record.minimum_freeze_block_height == 0 {
            LOGICAL_PROFILE_RECORD_VERSION
        } else {
            LOGICAL_PROFILE_FREEZE_RECORD_VERSION
        },
    );
    frame.field_bytes(1, context)?;
    frame.field_u16(2, record.profile.to_wire())?;
    frame.field_bytes(3, encode_digest32(&record.manifest_digest)?)?;
    frame.field_bytes(4, record.genesis_authority.to_vec())?;
    frame.field_u64(5, record.genesis_floor.get())?;
    if record.minimum_freeze_block_height != 0 {
        frame.field_u64(6, record.minimum_freeze_block_height)?;
    }
    Ok(frame.finish()?)
}
