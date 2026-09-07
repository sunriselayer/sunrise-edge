#![forbid(unsafe_code)]

//! ABI-driven concurrency protocol for Sunrise Edge.
//!
//! The ABI is not merely a function signature registry – it is a
//! protocol-level manifest that declares:
//!
//! * which objects a transaction touches,
//! * the access mode for each object ([`AccessMode::Read`],
//!   [`AccessMode::Write`], or [`AccessMode::Consume`]),
//! * capability requirements and execution limits.
//!
//! Validators use the [`AccessManifest`] to perform conflict detection and
//! enable fine-grained parallel execution of non-conflicting transactions
//! without global ordering (fast path).
//!
//! # Typed ABI foundation
//!
//! [`AccessManifest`] answers *which exact objects* and *which access mode*
//! a transaction touches; it says nothing about what constructor, type
//! argument, or schema a resolved object must have. The typed-ABI types
//! below — [`TypeArg`], [`TypeTag`], [`ConstructorDeclaration`],
//! [`ConstructorRegistry`], [`EntrypointSignature`], and
//! [`verify_entrypoint_inputs`] — answer that second question, deliberately
//! kept separate from access declaration.
//!
//! As of DR-0106, `node-core` has both the canonical wire codecs to commit a
//! typed entrypoint signature/owner-transition capability inside a governance
//! `PreinstalledModuleSemanticsEnvelope`
//! (`PreinstalledTypedEntrypointPolicy`/`PreinstalledOwnerTransitionPolicy`)
//! and the pre-execution verification wiring itself: when a committed
//! envelope declares a typed-entrypoint policy for the invoked entrypoint,
//! `PreinstalledWasmMachine::transition` calls this crate's
//! [`verify_entrypoint_inputs`] against every engine-visible input, strictly
//! before the WASM engine ever runs, and a committed owner-transition policy
//! authorizes node-core to independently synthesize one owner-only mutation
//! after a successful call. No current [`PreinstalledModuleCatalog`
//! ](../node_core/struct.PreinstalledModuleCatalog.html) entry commits either
//! policy, so this capability commits and verifies correctly but activates no
//! catalog module, `Create`, transfer, or mint end-to-end yet — see
//! `docs/architecture/decisions/0106-typed-entrypoint-owner-transition.md`.
//! `abi` itself still stays independent of `standard-assets`, `execution`,
//! `node-core`, runtimes, and adapters: `node-core` depends on `abi`, never
//! the other way around, so this foundation cannot accidentally acquire an
//! execution-engine or storage dependency of its own.
//!
//! **Canonical type IDs defined by this crate.** This lists only the exact
//! IDs this crate defines; it is not a claim that `abi` exclusively owns the
//! entire `0x50xx`/`0x51xx` numeric ranges.
//! - `0x5001` — [`AccessEntry`] (pre-existing).
//! - `0x5002` — [`AccessManifest`] (pre-existing).
//! - `0x5101` — [`TypeArg`] (new in this slice; the `0x51xx` band was
//!   audited unused before this allocation).
//! - `0x5102` — [`TypeTag`] (new in this slice, same audit).
//! - `0x5103` — [`ProjectionStep`] (added in DR-0106; the `0x51xx` band was
//!   re-audited unused above `0x5102` before this allocation).
//! - `0x5104` — [`ConstructorDeclaration`] (added in DR-0106).
//! - `0x5105` — [`ParamDeclaration`] (added in DR-0106).
//! - `0x5106` — [`EntrypointSignature`] (added in DR-0106).
//! - `0x5201` — [`package_types::PackageOrigin`] (DR-0113, unverified reference).
//! - `0x5202` — [`package_types::ScopedTypeArg`] (DR-0113).
//! - `0x5203` — [`package_types::ScopedTypeTag`] (DR-0113).
//!
//! The numeric value `0x5001` is also used by `protocol-config`'s
//! `PROTOCOL_CONFIG_TYPE_ID`. This is a pre-existing overlap between two
//! separate canonical struct namespaces — each crate's decoder calls
//! [`CanonicalFrame::require_type`] with its own expected constant and
//! rejects anything else, so no ambiguity exists in practice — not a claim
//! that `abi` reserves `0x5001` exclusively, and this slice does not
//! renumber it.
//!
//! **DR-0106: persisting the typed-ABI policy components.** DR-0105
//! deliberately left [`ConstructorDeclaration`], [`ConstructorRegistry`],
//! [`EntrypointSignature`], and [`ParamDeclaration`] as deterministic
//! in-memory-only protocol configuration with no canonical type ID, because
//! nothing needed to persist or hash them yet. `node-core`'s governance-
//! committed [`PreinstalledModuleSemanticsEnvelope`](../node_core/struct.PreinstalledModuleSemanticsEnvelope.html)
//! now needs to commit an exact typed entrypoint signature (and the
//! constructors it references) into its hashed bytes, so this slice adds
//! [`encode_projection_step`]/[`decode_projection_step`],
//! [`encode_constructor_declaration`]/[`decode_constructor_declaration`],
//! [`encode_param_declaration`]/[`decode_param_declaration`], and
//! [`encode_entrypoint_signature`]/[`decode_entrypoint_signature`] as bounded
//! canonical wire framings of the exact same Rust types. This does not turn
//! `ConstructorRegistry` itself into a wire type (it stays an in-memory,
//! `BTreeMap`-backed index the caller builds by decoding and registering one
//! [`ConstructorDeclaration`] at a time — see `node-core`'s
//! `PreinstalledTypedEntrypointPolicy`); nor does it change how
//! [`verify_entrypoint_inputs`] is called. [`ConstructorId`] `0` is reserved
//! and rejected by both [`ConstructorRegistry::register`] and
//! [`decode_constructor_declaration`]/[`decode_param_declaration`]; see their
//! docs.
//!
//! Every new decoder rejects a zero/unknown discriminant or identifier,
//! a bad or unknown arity tag, an out-of-bound count, an unexpected/missing/
//! trailing field, and — because [`decode_constructor_declaration`] builds a
//! real [`ConstructorDeclaration`] and calls its existing private
//! `validate()` — every structural rule [`ConstructorRegistry::register`]
//! already enforces (arity/projection shape, first-step self-agreement,
//! zero body/projection ids). The one exception is [`decode_projection_step`]
//! itself: it is a structural decoder and intentionally defers zero
//! `expected_type_id`/`field_id` rejection to the enclosing
//! [`ConstructorDeclaration::validate`] call in
//! [`decode_constructor_declaration`]; see [`decode_projection_step`]'s own
//! docs. Cross-declaration duplicate rejection
//! (duplicate [`ConstructorId`] or `body_type_id`) is still exactly
//! [`ConstructorRegistry::register`]'s job: a bare `Vec<ConstructorDeclaration>`
//! is not itself a wire type here, so a caller decoding several declarations
//! registers each one in turn and gets duplicate rejection for free, without
//! `abi` inventing a second registry wire format.
//!
//! **`type_hash` is a commitment, not the logical identity.** An object's
//! `type_hash` (e.g. [`objects::Object::type_hash`]) is an algorithm-tagged
//! *commitment* to a canonical [`TypeTag`], not itself the sole logical type
//! identity. After a hash-suite rotation, two objects that share the exact
//! same logical `TypeTag`/`AssetId` may legitimately carry `type_hash`
//! values computed under different algorithms, and therefore different raw
//! bytes. [`verify_type_id`] and [`verify_entrypoint_inputs`] always verify
//! by recomputing under the digest's own recorded algorithm and comparing
//! projected [`TypeArg`] values (not raw digest bytes) for nominal equality
//! across parameters. Any future typed policy must do the same: comparing
//! two `type_hash` values directly for byte equality is not a valid nominal
//! type-equality check.
//!
//! **Deferred reconciliation.** [`objects::apply_lazy_migration`] already
//! compares an object's `type_hash` against a migration descriptor's
//! `object_type` with plain `Digest32` equality
//! ([`objects::MigrationError::ObjectTypeMismatch`]). That comparison predates this
//! typed-ABI foundation and is not itself changed by this slice, but it is
//! exactly the raw-digest comparison the previous paragraph warns against:
//! it can only be correct today because no migration descriptor has yet
//! been committed across a `HashPurpose::ObjectType` hash-suite rotation.
//! Before this typed-ABI foundation is activated for any object whose
//! lazy-migration descriptors might span a rotation, that comparison must
//! be reconciled to a [`verify_type_id`]-style check (or an explicit
//! argument for why raw equality remains sufficient there). This is
//! deferred work, not a defect fixed by this slice.
//!
//! **Epoch authenticity.** Every `epoch` accepted by [`verify_type_id`],
//! [`verify_entrypoint_inputs`], and the underlying
//! `hashing::verify_type_identity_digest` gates which algorithms are
//! trusted for [`protocol_types::HashPurpose::ObjectType`]. It must always
//! be the authenticated execution epoch supplied by consensus/execution
//! context, never a value read from unauthenticated request input:
//! accepting a caller-controlled epoch would let an attacker pick an epoch
//! at which an algorithm the schedule has not really reached yet (or has
//! since retired) is nonetheless considered trusted, defeating the
//! fail-closed schedule check entirely.
//!
//! **Generic hashing footgun.** [`hashing::HashSuiteResolver::hash_for_purpose`]
//! and [`hashing::frame_hash_input`] reject
//! [`protocol_types::HashPurpose::ObjectType`] outright
//! (`hashing::HashingError::ObjectTypeRequiresDedicatedFrame`): that
//! general-purpose frame binds `protocol_version` and hashes an opaque
//! caller payload, so a value hashed through it would neither exclude
//! `protocol_version` nor be a canonical [`TypeTag`] encoding, and would
//! silently fail to interoperate with [`derive_type_id`]/[`verify_type_id`].
//! Always use [`derive_type_id`]/[`verify_type_id`] (which call
//! `hashing::hash_type_identity`/`hashing::verify_type_identity_digest`) for
//! nominal object-type identity.

/// Package-scoped nominal references for the public-contract boundary.
/// These values do not authenticate publishers or grant object authority.
pub mod package_types;
/// Unverified package-scoped object-signature declarations and canonical codecs.
pub mod public_abi;

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use hashing::{HashSuiteResolver, HashingError};
use objects::{
    AccessMode, Object, ObjectId, ObjectRef, decode_access_mode, decode_object_ref,
    encode_access_mode, encode_object_ref,
};
use protocol_types::{Digest32, Epoch};
use std::collections::BTreeMap;
use std::error::Error;

// ── type-id constants ──────────────────────────────────────────────────────
const ACCESS_ENTRY_TYPE_ID: u16 = 0x5001;
const ACCESS_MANIFEST_TYPE_ID: u16 = 0x5002;
const TYPE_ARG_TYPE_ID: u16 = 0x5101;
const TYPE_TAG_TYPE_ID: u16 = 0x5102;
const PROJECTION_STEP_TYPE_ID: u16 = 0x5103;
const CONSTRUCTOR_DECLARATION_TYPE_ID: u16 = 0x5104;
const PARAM_DECLARATION_TYPE_ID: u16 = 0x5105;
const ENTRYPOINT_SIGNATURE_TYPE_ID: u16 = 0x5106;
const ENCODING_VERSION: u16 = 1;

/// Maximum number of type arguments a [`TypeTag`] may carry.
///
/// Bounded typed-ABI foundation: at most one type argument, and at most one
/// type variable, exists anywhere in this slice. Unlike [`MAX_CONSTRUCTORS`]
/// and [`MAX_PARAMS`], this bound is not enforced by a runtime length check
/// against a collection: it is enforced structurally by
/// [`TypeTag::type_arg`]'s `Option<TypeArg>` representation, which can hold
/// at most one value by construction. If `type_arg` is ever generalized
/// beyond `Option` (or [`TypeArg`] grows a variant that itself carries more
/// than one nominal argument), this constant must be kept synchronized with
/// whatever explicit runtime check replaces that structural guarantee.
pub const MAX_TYPE_ARGS: usize = 1;
/// Maximum number of constructors one [`ConstructorRegistry`] may hold.
pub const MAX_CONSTRUCTORS: usize = 32;
/// Maximum number of parameters one [`EntrypointSignature`] may declare.
pub const MAX_PARAMS: usize = 8;
/// Maximum fixed-depth canonical body-projection steps one constructor may
/// declare.
pub const MAX_PROJECTION_DEPTH: usize = 4;
/// Maximum entrypoint name length in bytes.
///
/// This restates `execution::MAX_TRANSACTION_ENTRYPOINT_BYTES` (256) as a
/// dependency-safe identical bound: `abi` must not depend on `execution`, so
/// the value is duplicated here rather than imported. Changing one bound
/// without the other is a compatibility break and must be reviewed as such.
/// This is the protocol-level transaction entrypoint bound; it is
/// deliberately not `signing-view`'s narrower, optional hardware
/// clear-signing bound (`DeviceSigningProfile::V1.max_entrypoint_bytes()` =
/// 64), which exists only to keep one signed field within a device display
/// line and is not itself a protocol invariant.
pub const MAX_ENTRYPOINT_BYTES: usize = 256;

// ── error type ────────────────────────────────────────────────────────────

/// Errors produced by the ABI crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// An object encoding or decoding error occurred.
    Object(objects::ObjectError),
    /// The manifest contains more entries than can be encoded, or more
    /// entries than the caller's bound allows while decoding.
    ManifestTooLarge(usize),
    /// The manifest's declared entry count does not match its actual field
    /// layout.
    NonCanonicalManifestLayout {
        /// The entry count declared in field 1.
        declared_count: usize,
        /// The total number of fields actually present in the frame.
        field_count: usize,
    },
    /// The manifest declares the same object more than once.
    DuplicateObjectId(ObjectId),
    /// A [`TypeArg`] frame named an unknown discriminant tag.
    UnknownTypeArgTag(u16),
    /// A [`TypeArg`] value had the wrong byte length.
    InvalidTypeArgLength(usize),
    /// A canonical [`ConstructorDeclaration`] frame declared an arity tag
    /// other than `0` ([`TypeArity::Fixed`]) or `1` ([`TypeArity::Variable`]).
    UnknownTypeArityTag(u16),
    /// A [`TypeArity::Variable`] constructor declared an empty projection.
    EmptyProjectionForVariableArity(ConstructorId),
    /// A [`TypeArity::Fixed`] constructor declared a non-empty projection.
    UnexpectedProjectionForFixedArity(ConstructorId),
    /// A constructor's projection exceeded [`MAX_PROJECTION_DEPTH`].
    ProjectionTooDeep(usize),
    /// A projection step decoded a canonical frame of the wrong type.
    ProjectionTypeMismatch {
        /// The type id the step required.
        expected: u16,
        /// The type id actually decoded.
        actual: u16,
    },
    /// A projection step decoded a canonical frame of the wrong version.
    ProjectionVersionMismatch {
        /// The version the step required.
        expected: u16,
        /// The version actually decoded.
        actual: u16,
    },
    /// A projection's final extracted bytes were not exactly 32 bytes.
    ProjectionLength {
        /// The required byte length.
        expected: usize,
        /// The actual byte length.
        actual: usize,
    },
    /// A constructor declared the reserved zero [`ConstructorId`].
    ZeroConstructorId,
    /// A constructor declared a zero canonical body type id.
    ZeroBodyTypeId(ConstructorId),
    /// A constructor declared a projection step with a zero canonical type
    /// id.
    ZeroProjectionTypeId(ConstructorId),
    /// A constructor declared a projection step with a zero field id.
    ZeroProjectionFieldId(ConstructorId),
    /// A [`TypeArity::Variable`] constructor's first projection step did not
    /// exactly match its own `body_type_id`/`body_version`.
    ProjectionFirstStepMismatch {
        /// The constructor the mismatch was found on.
        constructor: ConstructorId,
        /// The constructor's declared `body_type_id`.
        body_type_id: u16,
        /// The constructor's declared `body_version`.
        body_version: u16,
        /// The first projection step's declared type id.
        first_type_id: u16,
        /// The first projection step's declared version.
        first_version: u16,
    },
    /// A registry already contains this [`ConstructorId`].
    DuplicateConstructorId(ConstructorId),
    /// A registry already binds this canonical body type id to a different
    /// constructor.
    DuplicateBodyTypeId {
        /// The colliding body type id.
        body_type_id: u16,
        /// The constructor already bound to it.
        existing: ConstructorId,
    },
    /// A registry already holds [`MAX_CONSTRUCTORS`] entries.
    RegistryFull(usize),
    /// A [`TypeTag`] or [`ParamDeclaration`] named a constructor absent from
    /// the registry.
    UnknownConstructor(ConstructorId),
    /// An entrypoint name was empty.
    EmptyEntrypointName,
    /// An entrypoint name exceeded [`MAX_ENTRYPOINT_BYTES`].
    EntrypointNameTooLong(usize),
    /// An [`EntrypointSignature`] declared more than [`MAX_PARAMS`] parameters.
    TooManyParams(usize),
    /// A parameter's declared schema version did not match the registry's
    /// constructor schema version.
    ParamSchemaVersionMismatch {
        /// The constructor the mismatch was found on.
        constructor: ConstructorId,
        /// The schema version recorded by the constructor's registry entry.
        expected: u32,
        /// The schema version recorded by the parameter declaration.
        actual: u32,
    },
    /// The number of resolved inputs did not match the signature's declared
    /// parameter count.
    ArityMismatch {
        /// The number of parameters the signature declares.
        expected: usize,
        /// The number of resolved inputs supplied.
        actual: usize,
    },
    /// A resolved input's access mode did not match its parameter's declared
    /// mode.
    AccessModeMismatch {
        /// The zero-based parameter index.
        index: usize,
        /// The mode the parameter declares.
        expected: AccessMode,
        /// The mode the resolved input actually carries.
        actual: AccessMode,
    },
    /// A resolved object's schema version did not match its parameter's
    /// declared schema version.
    ObjectSchemaVersionMismatch {
        /// The zero-based parameter index.
        index: usize,
        /// The schema version the parameter declares.
        expected: u32,
        /// The schema version the resolved object actually carries.
        actual: u32,
    },
    /// A resolved object's stored `type_hash` did not verify against the
    /// nominal type identity derived from its constructor and projected
    /// type argument.
    ///
    /// `type_hash` is an algorithm-tagged commitment to a canonical
    /// [`TypeTag`], not the sole logical type identity (see the crate-level
    /// docs and [`verify_type_id`]), so this reports the projected
    /// [`TypeTag`] rather than a digest recomputed under whatever algorithm
    /// happens to be currently active, which would be misleading after a
    /// hash-suite rotation.
    TypeIdentityMismatch {
        /// The zero-based parameter index.
        index: usize,
        /// The nominal type tag projected from the constructor and object
        /// body.
        type_tag: TypeTag,
        /// The digest actually stored on the resolved object.
        actual: Digest32,
    },
    /// Two [`TypeArity::Variable`] parameters in the same entrypoint
    /// resolved to different type arguments; this foundation binds every
    /// variable-arity parameter in one signature to the same shared type
    /// variable.
    TypeVariableMismatch {
        /// The zero-based parameter index that broke unification.
        index: usize,
        /// The type argument bound by an earlier parameter.
        expected: TypeArg,
        /// The type argument this parameter resolved to.
        actual: TypeArg,
    },
    /// Type-identity hashing failed.
    Hashing(HashingError),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::CanonicalDecoding(e) => write!(f, "canonical decoding error: {e}"),
            Self::Object(e) => write!(f, "object error: {e}"),
            Self::ManifestTooLarge(n) => write!(f, "manifest has {n} entries, exceeds maximum"),
            Self::NonCanonicalManifestLayout {
                declared_count,
                field_count,
            } => write!(
                f,
                "manifest declares {declared_count} entries but frame has {field_count} fields"
            ),
            Self::DuplicateObjectId(id) => {
                write!(f, "access manifest declares object {id} more than once")
            }
            Self::UnknownTypeArgTag(tag) => write!(f, "unknown type-arg tag: {tag}"),
            Self::InvalidTypeArgLength(length) => {
                write!(f, "type-arg values must be 32 bytes, got {length}")
            }
            Self::UnknownTypeArityTag(tag) => write!(f, "unknown type-arity tag: {tag}"),
            Self::EmptyProjectionForVariableArity(id) => write!(
                f,
                "constructor {id} has variable arity but an empty projection"
            ),
            Self::UnexpectedProjectionForFixedArity(id) => write!(
                f,
                "constructor {id} has fixed arity but a non-empty projection"
            ),
            Self::ProjectionTooDeep(depth) => write!(
                f,
                "projection has {depth} steps, exceeds maximum {MAX_PROJECTION_DEPTH}"
            ),
            Self::ProjectionTypeMismatch { expected, actual } => write!(
                f,
                "projection step expected canonical type {expected:#06x}, got {actual:#06x}"
            ),
            Self::ProjectionVersionMismatch { expected, actual } => write!(
                f,
                "projection step expected canonical version {expected}, got {actual}"
            ),
            Self::ProjectionLength { expected, actual } => write!(
                f,
                "projection extracted {actual} bytes, expected {expected}"
            ),
            Self::ZeroConstructorId => write!(f, "constructor id 0 is reserved"),
            Self::ZeroBodyTypeId(id) => {
                write!(f, "constructor {id} declares a zero body type id")
            }
            Self::ZeroProjectionTypeId(id) => write!(
                f,
                "constructor {id} declares a projection step with a zero type id"
            ),
            Self::ZeroProjectionFieldId(id) => write!(
                f,
                "constructor {id} declares a projection step with a zero field id"
            ),
            Self::ProjectionFirstStepMismatch {
                constructor,
                body_type_id,
                body_version,
                first_type_id,
                first_version,
            } => write!(
                f,
                "constructor {constructor} body is {body_type_id:#06x}/{body_version} but its first projection step declares {first_type_id:#06x}/{first_version}"
            ),
            Self::DuplicateConstructorId(id) => {
                write!(f, "registry already contains constructor {id}")
            }
            Self::DuplicateBodyTypeId {
                body_type_id,
                existing,
            } => write!(
                f,
                "body type {body_type_id:#06x} is already bound to constructor {existing}"
            ),
            Self::RegistryFull(count) => write!(
                f,
                "constructor registry has {count} entries, exceeds maximum {MAX_CONSTRUCTORS}"
            ),
            Self::UnknownConstructor(id) => write!(f, "unknown constructor: {id}"),
            Self::EmptyEntrypointName => write!(f, "entrypoint name must not be empty"),
            Self::EntrypointNameTooLong(length) => write!(
                f,
                "entrypoint name is {length} bytes, exceeds maximum {MAX_ENTRYPOINT_BYTES}"
            ),
            Self::TooManyParams(count) => write!(
                f,
                "entrypoint signature has {count} parameters, exceeds maximum {MAX_PARAMS}"
            ),
            Self::ParamSchemaVersionMismatch {
                constructor,
                expected,
                actual,
            } => write!(
                f,
                "constructor {constructor} registry schema version {expected} does not match parameter schema version {actual}"
            ),
            Self::ArityMismatch { expected, actual } => {
                write!(f, "entrypoint expects {expected} inputs, got {actual}")
            }
            Self::AccessModeMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "input {index} expected access mode {expected:?}, got {actual:?}"
            ),
            Self::ObjectSchemaVersionMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "input {index} expected schema version {expected}, got {actual}"
            ),
            Self::TypeIdentityMismatch {
                index,
                type_tag,
                actual,
            } => write!(
                f,
                "input {index} stored type_hash {actual} does not verify against projected type tag {type_tag:?}"
            ),
            Self::TypeVariableMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "input {index} breaks type-variable unification: expected {expected:?}, got {actual:?}"
            ),
            Self::Hashing(error) => error.fmt(f),
        }
    }
}

impl Error for AbiError {}

impl From<CanonicalEncodingError> for AbiError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for AbiError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<objects::ObjectError> for AbiError {
    fn from(value: objects::ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<HashingError> for AbiError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

// ── AccessEntry ───────────────────────────────────────────────────────────

/// A single entry in an [`AccessManifest`]: one object and the requested
/// access mode.
///
/// Transactions must declare every object they access in their manifest
/// before execution begins.  Contracts that attempt to read or write an
/// object absent from the manifest trigger an execution trap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEntry {
    /// The versioned, digest-authenticated reference to the object.
    pub object_ref: ObjectRef,
    /// The access mode requested for this object.
    pub mode: AccessMode,
}

/// Encodes an [`AccessEntry`] in the canonical wire format.
pub fn encode_access_entry(entry: &AccessEntry) -> Result<Vec<u8>, AbiError> {
    let mut canonical = CanonicalStruct::new(ACCESS_ENTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_object_ref(&entry.object_ref)?)?;
    canonical.field_bytes(2, encode_access_mode(entry.mode)?)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`AccessEntry`] without changing its stable encoding.
pub fn decode_access_entry(input: &[u8]) -> Result<AccessEntry, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_ENTRY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    Ok(AccessEntry {
        object_ref: decode_object_ref(frame.required_field(1)?)?,
        mode: decode_access_mode(frame.required_field(2)?)?,
    })
}

// ── AccessManifest ────────────────────────────────────────────────────────

/// The complete set of object accesses declared by a transaction.
///
/// The manifest is used by validators to:
///
/// 1. Verify that every object a contract accesses is explicitly declared.
/// 2. Detect write–write and write–consume conflicts between concurrent
///    transactions.
/// 3. Schedule non-conflicting transactions for parallel execution.
///
/// Entry order is preserved so that canonical encoding is deterministic.
/// Construction through [`AccessManifest::push`] does not itself enforce
/// uniqueness; [`decode_access_manifest`] rejects a wire manifest that
/// declares the same [`objects::ObjectId`] more than once, since duplicate
/// entries are a protocol error that validators must reject.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AccessManifest {
    /// Ordered list of object accesses.
    pub entries: Vec<AccessEntry>,
}

impl AccessManifest {
    /// Creates an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry to the manifest.
    pub fn push(&mut self, entry: AccessEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the manifest has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Encodes an [`AccessManifest`] in the canonical wire format.
///
/// Each entry is encoded with [`encode_access_entry`] and stored as a
/// length-prefixed blob under a sequential field id (starting at 1).
pub fn encode_access_manifest(manifest: &AccessManifest) -> Result<Vec<u8>, AbiError> {
    // Field ids for entries start at 2 and go up to u16::MAX, so at most
    // u16::MAX - 1 = 65534 entries are encodable.
    const MAX_ENTRIES: usize = u16::MAX as usize - 1;
    if manifest.entries.len() > MAX_ENTRIES {
        return Err(AbiError::ManifestTooLarge(manifest.entries.len()));
    }
    let mut canonical = CanonicalStruct::new(ACCESS_MANIFEST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(1, manifest.entries.len() as u32)?;
    for (index, entry) in manifest.entries.iter().enumerate() {
        // field ids 2, 3, 4, … for entries 0, 1, 2, …
        let field_id = (index + 2) as u16;
        canonical.field_bytes(field_id, encode_access_entry(entry)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`AccessManifest`] without changing its stable
/// encoding.
///
/// `max_entries` bounds the declared entry count *before* any entry is
/// decoded or copied, so a caller can apply a tighter, context-specific
/// ceiling than the shared canonical frame bound. The declared count in
/// field 1 must exactly match the number of remaining fields in the frame;
/// any other layout is rejected as non-canonical. The decoded entries must
/// not repeat the same [`objects::ObjectId`].
pub fn decode_access_manifest(
    input: &[u8],
    max_entries: usize,
) -> Result<AccessManifest, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_MANIFEST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let declared_count = frame.required_u32(1)?;
    let declared_count =
        usize::try_from(declared_count).map_err(|_| AbiError::ManifestTooLarge(usize::MAX))?;
    if declared_count > max_entries {
        return Err(AbiError::ManifestTooLarge(declared_count));
    }

    let expected_field_count = declared_count
        .checked_add(1)
        .ok_or(AbiError::ManifestTooLarge(usize::MAX))?;
    if frame.field_count() != expected_field_count {
        return Err(AbiError::NonCanonicalManifestLayout {
            declared_count,
            field_count: frame.field_count(),
        });
    }

    let mut entries = Vec::with_capacity(declared_count);
    for index in 0..declared_count {
        let field_id =
            u16::try_from(index + 2).map_err(|_| AbiError::ManifestTooLarge(declared_count))?;
        entries.push(decode_access_entry(frame.required_field(field_id)?)?);
    }

    let mut object_ids: Vec<ObjectId> = entries.iter().map(|entry| entry.object_ref.id).collect();
    object_ids.sort_unstable();
    if let Some(window) = object_ids.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(AbiError::DuplicateObjectId(window[0]));
    }

    Ok(AccessManifest { entries })
}

// ── TypeArg ───────────────────────────────────────────────────────────────

/// The sole admitted nominal type-argument kind in this foundation slice.
///
/// Bound: exactly one type-argument kind exists structurally — a 32-byte
/// Standard Asset v1 `AssetId`-shaped identifier. `abi` does not depend on
/// `standard-assets`, so this wraps a raw 32-byte value rather than
/// `standard_assets::AssetId`; the defining crate converts at its own
/// boundary. Adding a second variant is a protocol-critical change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeArg {
    /// A 32-byte Standard Asset v1 `AssetId`-shaped value.
    AssetId([u8; 32]),
}

impl TypeArg {
    const fn tag(self) -> u16 {
        match self {
            Self::AssetId(_) => 1,
        }
    }
}

/// Encodes a [`TypeArg`] in the canonical wire format.
pub fn encode_type_arg(arg: &TypeArg) -> Result<Vec<u8>, AbiError> {
    let mut canonical = CanonicalStruct::new(TYPE_ARG_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, arg.tag())?;
    match arg {
        TypeArg::AssetId(bytes) => canonical.field_bytes(2, bytes.as_slice())?,
    }
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`TypeArg`] without changing its stable encoding.
/// Rejects an unknown tag, a malformed length, unknown fields, and trailing
/// bytes.
pub fn decode_type_arg(input: &[u8]) -> Result<TypeArg, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(TYPE_ARG_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let tag = frame.required_u16(1)?;
    match tag {
        1 => {
            frame.require_only_fields(&[1, 2])?;
            let bytes = frame.required_field(2)?;
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| AbiError::InvalidTypeArgLength(bytes.len()))?;
            Ok(TypeArg::AssetId(array))
        }
        other => Err(AbiError::UnknownTypeArgTag(other)),
    }
}

// ── ConstructorId and TypeTag ────────────────────────────────────────────

/// A stable identifier for one registered constructor.
///
/// This is `abi`'s own namespace: distinct from any canonical object-body
/// wire type id, even when a defining crate deliberately mirrors the numeric
/// value (see [`ConstructorDeclaration::body_type_id`]). `0` is reserved:
/// [`Self::new`] itself stays a total `const fn` (it cannot fail without
/// panicking, which library code must not do), so the reservation is
/// enforced later, by [`ConstructorDeclaration::validate`]
/// (`AbiError::ZeroConstructorId`) and therefore by
/// [`ConstructorRegistry::register`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConstructorId(u16);

impl ConstructorId {
    /// Creates a constructor identifier.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the wire identifier.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ConstructorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

/// A canonical nominal type identity: one constructor plus an optional type
/// argument.
///
/// [`Some`] iff the constructor's declared [`TypeArity`] is
/// [`TypeArity::Variable`]; consumers should not construct a [`TypeTag`]
/// directly against a registry without also checking arity via
/// [`ConstructorRegistry::get`] (see [`project_type_arg`] and
/// [`verify_entrypoint_inputs`], which do this automatically).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeTag {
    /// The constructor this type instantiates.
    pub constructor: ConstructorId,
    /// The type argument, if the constructor's template is generic.
    pub type_arg: Option<TypeArg>,
}

/// Encodes a [`TypeTag`] in the canonical wire format. This is the payload
/// hashed by [`derive_type_id`]/[`verify_type_id`].
pub fn encode_type_tag(tag: &TypeTag) -> Result<Vec<u8>, AbiError> {
    let mut canonical = CanonicalStruct::new(TYPE_TAG_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, tag.constructor.get())?;
    if let Some(arg) = &tag.type_arg {
        canonical.field_bytes(2, encode_type_arg(arg)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`TypeTag`] without changing its stable encoding.
pub fn decode_type_tag(input: &[u8]) -> Result<TypeTag, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(TYPE_TAG_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let constructor = ConstructorId::new(frame.required_u16(1)?);
    let type_arg = match frame.field(2) {
        Some(bytes) => Some(decode_type_arg(bytes)?),
        None => None,
    };
    Ok(TypeTag {
        constructor,
        type_arg,
    })
}

// ── Constructor declarations and registry ────────────────────────────────

/// Whether a constructor's type template carries a type variable.
///
/// Bounded to at most one type variable per template ([`MAX_TYPE_ARGS`]):
/// [`Self::Fixed`] templates carry none, [`Self::Variable`] templates carry
/// exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeArity {
    /// No type argument; the nominal type is closed.
    Fixed,
    /// Exactly one type argument, extracted from the object body by
    /// [`ConstructorDeclaration::projection`].
    Variable,
}

/// One step of a fixed-depth canonical body projection.
///
/// A projection walks nested canonical frames inside an object's raw body
/// bytes: at each step, the current byte slice must decode as a canonical
/// frame matching `expected_type_id`/`expected_version`, and `field_id`'s raw
/// bytes become the input to the next step, or the final type-argument bytes
/// if this is the last step. Each step's [`decode_canonical_frame`] call
/// independently rejects truncation, bad magic, and trailing bytes for that
/// step's slice, so malformed bodies fail closed at the step that first
/// disagrees with the declared shape. `expected_type_id` and `field_id` must
/// both be non-zero ([`ConstructorRegistry::register`] rejects a zero
/// value), and the projection's first step must exactly match the owning
/// [`ConstructorDeclaration`]'s own `body_type_id`/`body_version`, since the
/// first step always decodes the object's outer body. Only the *last* step's
/// decoded frame is required to contain nothing but its declared
/// `field_id`; earlier steps (including the outer body) may carry other
/// legitimate value fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionStep {
    /// The canonical type id the current slice must decode as. Must be
    /// non-zero.
    pub expected_type_id: u16,
    /// The canonical encoding version the current slice must decode as.
    pub expected_version: u16,
    /// The field id to extract for the next step. Must be non-zero.
    pub field_id: u16,
}

/// Encodes one [`ProjectionStep`] in the canonical wire format.
///
/// This is a purely structural encoding: it does not check `expected_type_id`
/// or `field_id` for zero, since those are semantic rules owned by the
/// enclosing [`ConstructorDeclaration::validate`] (see
/// [`decode_constructor_declaration`]).
pub fn encode_projection_step(step: &ProjectionStep) -> Result<Vec<u8>, AbiError> {
    let mut canonical = CanonicalStruct::new(PROJECTION_STEP_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, step.expected_type_id)?;
    canonical.field_u16(2, step.expected_version)?;
    canonical.field_u16(3, step.field_id)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`ProjectionStep`] without changing its stable
/// encoding. Rejects unknown/trailing fields; defers zero-id and arity
/// semantics to the enclosing [`ConstructorDeclaration::validate`].
pub fn decode_projection_step(input: &[u8]) -> Result<ProjectionStep, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(PROJECTION_STEP_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    Ok(ProjectionStep {
        expected_type_id: frame.required_u16(1)?,
        expected_version: frame.required_u16(2)?,
        field_id: frame.required_u16(3)?,
    })
}

/// A registered constructor's declared shape.
///
/// Binds one [`ConstructorId`] (`abi`'s own namespace) to exactly one
/// canonical object-body wire type (`body_type_id`, owned by the defining
/// crate's canonical-encoding namespace, e.g. `standard-assets`'s `0x71xx`
/// range). The two namespaces are deliberately distinct:
/// [`ConstructorRegistry::register`] rejects any attempt to bind two
/// different constructors to the same `body_type_id`, so the binding stays
/// unambiguous even when a constructor id is chosen to numerically mirror
/// its body type id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstructorDeclaration {
    /// The constructor's stable identifier.
    pub id: ConstructorId,
    /// The canonical wire type id of the object body this constructor
    /// describes. Must be non-zero.
    pub body_type_id: u16,
    /// The canonical encoding version of that body.
    pub body_version: u16,
    /// The object schema version associated with this constructor.
    pub schema_version: u32,
    /// Whether this constructor's type template carries a type variable.
    pub arity: TypeArity,
    /// The fixed-depth body projection used to extract the type argument.
    /// Must be empty iff `arity` is [`TypeArity::Fixed`]. Iff `arity` is
    /// [`TypeArity::Variable`], must be non-empty (length at most
    /// [`MAX_PROJECTION_DEPTH`]) and its first step must exactly match
    /// `body_type_id`/`body_version`, since [`project_type_arg`] always
    /// decodes the outer body as the first step.
    pub projection: Vec<ProjectionStep>,
}

impl ConstructorDeclaration {
    fn validate(&self) -> Result<(), AbiError> {
        if self.id.get() == 0 {
            return Err(AbiError::ZeroConstructorId);
        }
        if self.body_type_id == 0 {
            return Err(AbiError::ZeroBodyTypeId(self.id));
        }
        match self.arity {
            TypeArity::Fixed => {
                if !self.projection.is_empty() {
                    return Err(AbiError::UnexpectedProjectionForFixedArity(self.id));
                }
            }
            TypeArity::Variable => {
                if self.projection.is_empty() {
                    return Err(AbiError::EmptyProjectionForVariableArity(self.id));
                }
                if self.projection.len() > MAX_PROJECTION_DEPTH {
                    return Err(AbiError::ProjectionTooDeep(self.projection.len()));
                }
                let first = self.projection[0];
                if first.expected_type_id != self.body_type_id
                    || first.expected_version != self.body_version
                {
                    return Err(AbiError::ProjectionFirstStepMismatch {
                        constructor: self.id,
                        body_type_id: self.body_type_id,
                        body_version: self.body_version,
                        first_type_id: first.expected_type_id,
                        first_version: first.expected_version,
                    });
                }
                for step in &self.projection {
                    if step.expected_type_id == 0 {
                        return Err(AbiError::ZeroProjectionTypeId(self.id));
                    }
                    if step.field_id == 0 {
                        return Err(AbiError::ZeroProjectionFieldId(self.id));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Encodes one [`ConstructorDeclaration`] in the canonical wire format.
///
/// This is a purely structural encoding: it does not call
/// [`ConstructorDeclaration::validate`], matching this crate's existing
/// pure-encode style ([`encode_type_arg`], [`encode_type_tag`]); validity is
/// enforced by [`decode_constructor_declaration`] and by
/// [`ConstructorRegistry::register`].
pub fn encode_constructor_declaration(
    declaration: &ConstructorDeclaration,
) -> Result<Vec<u8>, AbiError> {
    if declaration.projection.len() > MAX_PROJECTION_DEPTH {
        return Err(AbiError::ProjectionTooDeep(declaration.projection.len()));
    }
    let mut canonical = CanonicalStruct::new(CONSTRUCTOR_DECLARATION_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, declaration.id.get())?;
    canonical.field_u16(2, declaration.body_type_id)?;
    canonical.field_u16(3, declaration.body_version)?;
    canonical.field_u32(4, declaration.schema_version)?;
    let arity_tag: u16 = match declaration.arity {
        TypeArity::Fixed => 0,
        TypeArity::Variable => 1,
    };
    canonical.field_u16(5, arity_tag)?;
    let count = u32::try_from(declaration.projection.len())
        .map_err(|_| AbiError::ProjectionTooDeep(declaration.projection.len()))?;
    canonical.field_u32(6, count)?;
    for (index, step) in declaration.projection.iter().enumerate() {
        let field_id = u16::try_from(7 + index)
            .map_err(|_| AbiError::ProjectionTooDeep(declaration.projection.len()))?;
        canonical.field_bytes(field_id, encode_projection_step(step)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`ConstructorDeclaration`] without changing its
/// stable encoding.
///
/// Rejects an out-of-bound projection count, an unknown arity tag, and an
/// unexpected/missing/trailing field before ever constructing the value, and
/// then calls the same private [`ConstructorDeclaration::validate`]
/// [`ConstructorRegistry::register`] uses — the reserved zero
/// [`ConstructorId`], a zero `body_type_id`, an arity/projection shape
/// mismatch, a zero projection type/field id, and a first projection step
/// that disagrees with this declaration's own `body_type_id`/`body_version`
/// are therefore all rejected here too, not only at registration time.
pub fn decode_constructor_declaration(input: &[u8]) -> Result<ConstructorDeclaration, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(CONSTRUCTOR_DECLARATION_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let id = frame.required_u16(1)?;
    let body_type_id = frame.required_u16(2)?;
    let body_version = frame.required_u16(3)?;
    let schema_version = frame.required_u32(4)?;
    let arity_tag = frame.required_u16(5)?;
    let arity = match arity_tag {
        0 => TypeArity::Fixed,
        1 => TypeArity::Variable,
        other => return Err(AbiError::UnknownTypeArityTag(other)),
    };
    let count = usize::try_from(frame.required_u32(6)?)
        .map_err(|_| AbiError::ProjectionTooDeep(usize::MAX))?;
    if count > MAX_PROJECTION_DEPTH {
        return Err(AbiError::ProjectionTooDeep(count));
    }
    let mut allowed: Vec<u16> = vec![1, 2, 3, 4, 5, 6];
    for index in 0..count {
        allowed.push(u16::try_from(7 + index).map_err(|_| AbiError::ProjectionTooDeep(count))?);
    }
    frame.require_only_fields(&allowed)?;
    let mut projection = Vec::with_capacity(count);
    for index in 0..count {
        let field_id = allowed[6 + index];
        projection.push(decode_projection_step(frame.required_field(field_id)?)?);
    }
    let declaration = ConstructorDeclaration {
        id: ConstructorId::new(id),
        body_type_id,
        body_version,
        schema_version,
        arity,
        projection,
    };
    declaration.validate()?;
    Ok(declaration)
}

/// A deterministic registry of bounded [`ConstructorDeclaration`]s.
///
/// Iteration order is always the sorted [`ConstructorId`] order, independent
/// of registration order, so two registries built by registering the same
/// declarations in different orders are structurally identical.
#[derive(Clone, Debug, Default)]
pub struct ConstructorRegistry {
    by_id: BTreeMap<ConstructorId, ConstructorDeclaration>,
    body_type_ids: BTreeMap<u16, ConstructorId>,
}

impl ConstructorRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one constructor declaration.
    ///
    /// Rejects an internally inconsistent declaration (the reserved zero
    /// [`ConstructorId`], a zero `body_type_id`, arity/projection mismatch,
    /// a projection deeper than [`MAX_PROJECTION_DEPTH`], a zero projection
    /// type id or field id, or a first projection step that does not
    /// exactly match the declaration's own `body_type_id`/`body_version`),
    /// a duplicate [`ConstructorId`], a `body_type_id` already bound to a
    /// different constructor, and registering beyond [`MAX_CONSTRUCTORS`]
    /// entries.
    pub fn register(&mut self, declaration: ConstructorDeclaration) -> Result<(), AbiError> {
        declaration.validate()?;
        if self.by_id.contains_key(&declaration.id) {
            return Err(AbiError::DuplicateConstructorId(declaration.id));
        }
        if let Some(existing) = self.body_type_ids.get(&declaration.body_type_id) {
            return Err(AbiError::DuplicateBodyTypeId {
                body_type_id: declaration.body_type_id,
                existing: *existing,
            });
        }
        if self.by_id.len() >= MAX_CONSTRUCTORS {
            return Err(AbiError::RegistryFull(self.by_id.len()));
        }
        self.body_type_ids
            .insert(declaration.body_type_id, declaration.id);
        self.by_id.insert(declaration.id, declaration);
        Ok(())
    }

    /// Looks up a constructor by its [`ConstructorId`].
    #[must_use]
    pub fn get(&self, id: ConstructorId) -> Option<&ConstructorDeclaration> {
        self.by_id.get(&id)
    }

    /// Looks up a constructor by its bound canonical body type id.
    #[must_use]
    pub fn get_by_body_type(&self, body_type_id: u16) -> Option<&ConstructorDeclaration> {
        self.body_type_ids
            .get(&body_type_id)
            .and_then(|id| self.by_id.get(id))
    }

    /// Returns the number of registered constructors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Returns `true` if the registry has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Iterates registered constructors in deterministic [`ConstructorId`]
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = &ConstructorDeclaration> {
        self.by_id.values()
    }
}

// ── Body projection ───────────────────────────────────────────────────────

/// Projects the type argument out of one canonical object body using
/// `declaration`'s fixed-depth body projection.
///
/// For a [`TypeArity::Fixed`] constructor, still decodes `body` as a
/// canonical frame and requires it to exactly match `declaration`'s own
/// `body_type_id`/`body_version` — an arbitrary or wrongly-typed body is
/// rejected outright — but returns `Ok(None)`, since a fixed-arity template
/// carries no type argument. For a [`TypeArity::Variable`] constructor,
/// walks `declaration.projection` against `body` (whose first step is
/// guaranteed by [`ConstructorDeclaration::validate`] to match
/// `body_type_id`/`body_version`) and interprets the final step's extracted
/// bytes as a 32-byte [`TypeArg::AssetId`], rejecting malformed, mismatched,
/// or non-32-byte results. Only the *last* step's decoded frame is required
/// to contain nothing but its declared terminal field; earlier steps
/// (including the outer body) may carry other legitimate value fields (an
/// amount, creation metadata, and so on) that this projection does not
/// otherwise inspect.
pub fn project_type_arg(
    declaration: &ConstructorDeclaration,
    body: &[u8],
) -> Result<Option<TypeArg>, AbiError> {
    match declaration.arity {
        TypeArity::Fixed => {
            let frame: CanonicalFrame<'_> = decode_canonical_frame(body)?;
            if frame.type_id() != declaration.body_type_id {
                return Err(AbiError::ProjectionTypeMismatch {
                    expected: declaration.body_type_id,
                    actual: frame.type_id(),
                });
            }
            if frame.version() != declaration.body_version {
                return Err(AbiError::ProjectionVersionMismatch {
                    expected: declaration.body_version,
                    actual: frame.version(),
                });
            }
            Ok(None)
        }
        TypeArity::Variable => {
            let mut current = body;
            let last_index = declaration.projection.len().saturating_sub(1);
            for (index, step) in declaration.projection.iter().enumerate() {
                let frame: CanonicalFrame<'_> = decode_canonical_frame(current)?;
                if frame.type_id() != step.expected_type_id {
                    return Err(AbiError::ProjectionTypeMismatch {
                        expected: step.expected_type_id,
                        actual: frame.type_id(),
                    });
                }
                if frame.version() != step.expected_version {
                    return Err(AbiError::ProjectionVersionMismatch {
                        expected: step.expected_version,
                        actual: frame.version(),
                    });
                }
                if index == last_index {
                    frame.require_only_fields(&[step.field_id])?;
                }
                current = frame.required_field(step.field_id)?;
            }
            let array: [u8; 32] = current.try_into().map_err(|_| AbiError::ProjectionLength {
                expected: 32,
                actual: current.len(),
            })?;
            Ok(Some(TypeArg::AssetId(array)))
        }
    }
}

// ── Type-id derivation and verification ──────────────────────────────────

/// Derives the nominal object-type identity digest for `tag`.
///
/// This binds only the constructor and type argument, never an object's
/// value fields, `protocol_version`, or `schema_version` (see
/// [`hashing::frame_type_identity_input`]), so an object's nominal type
/// survives protocol upgrades and schema migrations.
pub fn derive_type_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    tag: &TypeTag,
) -> Result<Digest32, AbiError> {
    let payload = encode_type_tag(tag)?;
    Ok(hashing::hash_type_identity(resolver, epoch, &payload)?)
}

/// Verifies that `digest` is a valid nominal object-type identity commitment
/// to `tag`, using the digest's own recorded algorithm and failing closed
/// per [`hashing::verify_type_identity_digest`].
///
/// `digest` (typically an [`objects::Object::type_hash`]) is an
/// algorithm-tagged *commitment* to `tag`, not itself the logical type
/// identity: an object created before a hash-suite rotation and one created
/// after may both legitimately verify against the exact same `tag` while
/// carrying different digest bytes, because each was committed under the
/// algorithm active at its own creation time. Callers must always compare
/// nominal types by calling this function (or [`verify_entrypoint_inputs`]),
/// never by comparing two `type_hash` values for byte equality.
pub fn verify_type_id(
    resolver: &HashSuiteResolver,
    digest: &Digest32,
    epoch: Epoch,
    tag: &TypeTag,
) -> Result<bool, AbiError> {
    let payload = encode_type_tag(tag)?;
    Ok(hashing::verify_type_identity_digest(
        resolver, digest, epoch, &payload,
    )?)
}

// ── Entrypoint signatures ─────────────────────────────────────────────────

/// One declared entrypoint parameter: an exact [`AccessMode`], a
/// constructor, and the exact object schema version expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamDeclaration {
    /// The exact access mode required for this parameter.
    pub mode: AccessMode,
    /// The constructor this parameter's object must satisfy.
    pub constructor: ConstructorId,
    /// The exact object schema version this parameter requires.
    pub schema_version: u32,
}

/// Encodes one [`ParamDeclaration`] in the canonical wire format.
pub fn encode_param_declaration(declaration: &ParamDeclaration) -> Result<Vec<u8>, AbiError> {
    if declaration.constructor.get() == 0 {
        return Err(AbiError::ZeroConstructorId);
    }
    let mut canonical = CanonicalStruct::new(PARAM_DECLARATION_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_access_mode(declaration.mode)?)?;
    canonical.field_u16(2, declaration.constructor.get())?;
    canonical.field_u32(3, declaration.schema_version)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`ParamDeclaration`] without changing its stable
/// encoding. Rejects the reserved zero [`ConstructorId`] and an
/// unexpected/missing/trailing field; [`AbiError::UnknownConstructor`]
/// remains [`verify_entrypoint_inputs`]'s job, since only a
/// [`ConstructorRegistry`] can know whether a non-zero id is registered.
pub fn decode_param_declaration(input: &[u8]) -> Result<ParamDeclaration, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(PARAM_DECLARATION_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let mode = decode_access_mode(frame.required_field(1)?)?;
    let constructor = frame.required_u16(2)?;
    if constructor == 0 {
        return Err(AbiError::ZeroConstructorId);
    }
    let schema_version = frame.required_u32(3)?;
    Ok(ParamDeclaration {
        mode,
        constructor: ConstructorId::new(constructor),
        schema_version,
    })
}

/// A bounded, protocol-level declaration of one entrypoint's expected typed
/// inputs.
///
/// This is deterministic in-memory configuration (like [`ConstructorRegistry`]),
/// not a wire-transmitted frame: the wire-level entrypoint name already
/// travels inside a signed transaction (see `signing-view`); this type
/// declares what a validator or execution engine should *require* for that
/// name, before this foundation is wired into any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrypointSignature {
    entrypoint: String,
    params: Vec<ParamDeclaration>,
}

impl EntrypointSignature {
    /// Creates a validated entrypoint signature.
    ///
    /// Rejects an empty name, a name longer than [`MAX_ENTRYPOINT_BYTES`],
    /// and more than [`MAX_PARAMS`] parameters.
    pub fn new(
        entrypoint: impl Into<String>,
        params: Vec<ParamDeclaration>,
    ) -> Result<Self, AbiError> {
        let entrypoint = entrypoint.into();
        if entrypoint.is_empty() {
            return Err(AbiError::EmptyEntrypointName);
        }
        if entrypoint.len() > MAX_ENTRYPOINT_BYTES {
            return Err(AbiError::EntrypointNameTooLong(entrypoint.len()));
        }
        if params.len() > MAX_PARAMS {
            return Err(AbiError::TooManyParams(params.len()));
        }
        Ok(Self { entrypoint, params })
    }

    /// Returns the entrypoint name.
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Returns the declared parameters, in order.
    #[must_use]
    pub fn params(&self) -> &[ParamDeclaration] {
        &self.params
    }
}

/// Encodes one [`EntrypointSignature`] in the canonical wire format.
pub fn encode_entrypoint_signature(signature: &EntrypointSignature) -> Result<Vec<u8>, AbiError> {
    if signature.params.len() > MAX_PARAMS {
        return Err(AbiError::TooManyParams(signature.params.len()));
    }
    let mut canonical = CanonicalStruct::new(ENTRYPOINT_SIGNATURE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, &signature.entrypoint)?;
    let count = u32::try_from(signature.params.len())
        .map_err(|_| AbiError::TooManyParams(signature.params.len()))?;
    canonical.field_u32(2, count)?;
    for (index, param) in signature.params.iter().enumerate() {
        let field_id = u16::try_from(3 + index)
            .map_err(|_| AbiError::TooManyParams(signature.params.len()))?;
        canonical.field_bytes(field_id, encode_param_declaration(param)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`EntrypointSignature`] without changing its stable
/// encoding.
///
/// Rejects an out-of-bound parameter count and an unexpected/missing/
/// trailing field before ever constructing the value, then calls the same
/// [`EntrypointSignature::new`] every in-memory caller uses, so an empty or
/// oversized entrypoint name is rejected identically either way.
pub fn decode_entrypoint_signature(input: &[u8]) -> Result<EntrypointSignature, AbiError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ENTRYPOINT_SIGNATURE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let entrypoint = frame.required_str(1)?.to_string();
    let count =
        usize::try_from(frame.required_u32(2)?).map_err(|_| AbiError::TooManyParams(usize::MAX))?;
    if count > MAX_PARAMS {
        return Err(AbiError::TooManyParams(count));
    }
    let mut allowed: Vec<u16> = vec![1, 2];
    for index in 0..count {
        allowed.push(u16::try_from(3 + index).map_err(|_| AbiError::TooManyParams(count))?);
    }
    frame.require_only_fields(&allowed)?;
    let mut params = Vec::with_capacity(count);
    for index in 0..count {
        let field_id = allowed[2 + index];
        params.push(decode_param_declaration(frame.required_field(field_id)?)?);
    }
    EntrypointSignature::new(entrypoint, params)
}

// ── TypedInput adapter and single-pass verification ──────────────────────

/// One input a caller supplies for [`verify_entrypoint_inputs`]: the access
/// mode and object a caller already resolved via a transaction's
/// [`AccessManifest`] and object store.
///
/// `abi` deliberately does not resolve objects itself, and this is not a
/// second access-control mechanism: typed-ABI verification only answers
/// what constructor/type-argument/schema an already access-checked object
/// has, per the module-level design note.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedInput<'a> {
    /// The access mode resolved for this object.
    pub mode: AccessMode,
    /// The resolved object.
    pub object: &'a Object,
}

/// One verified typed input: a [`ParamDeclaration`], its resolved object,
/// and the object's derived nominal [`TypeTag`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedInput<'a> {
    /// The entrypoint parameter this input satisfies.
    pub declaration: &'a ParamDeclaration,
    /// The resolved object bound to that parameter.
    pub object: &'a Object,
    /// The object's derived nominal type tag.
    pub type_tag: TypeTag,
}

/// The complete set of typed inputs verified for one entrypoint call, in
/// declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrypointBindings<'a> {
    /// Verified inputs, in declaration order.
    pub inputs: Vec<TypedInput<'a>>,
}

/// Performs single-pass pre-execution verification of `inputs` against
/// `signature`.
///
/// For each declared parameter, in order, this checks (fail-closed, no
/// partial success): the resolved input's access mode matches exactly; its
/// constructor is registered and its registry schema version matches the
/// parameter's declared schema version; the resolved object's own
/// `schema_version` matches; the object's body projects to a type argument
/// whose projected tag [`verify_type_id`]s against the object's stored
/// `type_hash` (catching a body/header disagreement, and correctly
/// accepting a `type_hash` committed under any algorithm that was trusted
/// at or before `epoch`, not only the algorithm currently active); and
/// every [`TypeArity::Variable`] parameter in the signature resolves to the
/// same type argument (this foundation's single shared type variable per
/// signature), compared by projected [`TypeArg`] value, never by raw
/// `type_hash` bytes. The pass is single-pass: each input is visited
/// exactly once, left to right.
pub fn verify_entrypoint_inputs<'a>(
    signature: &'a EntrypointSignature,
    registry: &ConstructorRegistry,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    inputs: &'a [ResolvedInput<'a>],
) -> Result<EntrypointBindings<'a>, AbiError> {
    if inputs.len() != signature.params.len() {
        return Err(AbiError::ArityMismatch {
            expected: signature.params.len(),
            actual: inputs.len(),
        });
    }

    let mut shared_type_arg: Option<TypeArg> = None;
    let mut bindings = Vec::with_capacity(inputs.len());

    for (index, (declaration, input)) in signature.params.iter().zip(inputs.iter()).enumerate() {
        if input.mode != declaration.mode {
            return Err(AbiError::AccessModeMismatch {
                index,
                expected: declaration.mode,
                actual: input.mode,
            });
        }
        let constructor_decl = registry
            .get(declaration.constructor)
            .ok_or(AbiError::UnknownConstructor(declaration.constructor))?;
        if constructor_decl.schema_version != declaration.schema_version {
            return Err(AbiError::ParamSchemaVersionMismatch {
                constructor: declaration.constructor,
                expected: constructor_decl.schema_version,
                actual: declaration.schema_version,
            });
        }
        if input.object.schema_version != declaration.schema_version {
            return Err(AbiError::ObjectSchemaVersionMismatch {
                index,
                expected: declaration.schema_version,
                actual: input.object.schema_version,
            });
        }

        let type_arg = project_type_arg(constructor_decl, &input.object.data)?;
        let type_tag = TypeTag {
            constructor: declaration.constructor,
            type_arg,
        };
        // Verify the object's own stored commitment against the projected
        // tag using the digest's own recorded algorithm, rather than
        // deriving a digest under whichever algorithm happens to be active
        // at `epoch` and comparing raw bytes: an object committed under an
        // algorithm that was trusted at an earlier epoch must remain valid
        // after a later hash-suite rotation (see `verify_type_id`).
        if !verify_type_id(resolver, &input.object.type_hash, epoch, &type_tag)? {
            return Err(AbiError::TypeIdentityMismatch {
                index,
                type_tag,
                actual: input.object.type_hash,
            });
        }

        if let Some(arg) = type_arg {
            match shared_type_arg {
                None => shared_type_arg = Some(arg),
                Some(existing) if existing == arg => {}
                Some(existing) => {
                    return Err(AbiError::TypeVariableMismatch {
                        index,
                        expected: existing,
                        actual: arg,
                    });
                }
            }
        }

        bindings.push(TypedInput {
            declaration,
            object: input.object,
            type_tag,
        });
    }

    Ok(EntrypointBindings { inputs: bindings })
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use objects::{ObjectId, ObjectRef};
    use protocol_types::{Digest32, HashAlgorithmId};

    fn sample_object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([id_byte; 32]),
            version,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
        }
    }

    #[test]
    fn access_entry_encodes_deterministically() {
        let entry = AccessEntry {
            object_ref: sample_object_ref(0x11, 1, 0x22),
            mode: AccessMode::Read,
        };

        let left = encode_access_entry(&entry).unwrap();
        let right = encode_access_entry(&entry).unwrap();
        assert_eq!(left, right);
        assert!(!left.is_empty());
    }

    #[test]
    fn different_access_modes_produce_different_encodings() {
        let make = |mode| AccessEntry {
            object_ref: sample_object_ref(0xAA, 3, 0xBB),
            mode,
        };

        let read = encode_access_entry(&make(AccessMode::Read)).unwrap();
        let write = encode_access_entry(&make(AccessMode::Write)).unwrap();
        let consume = encode_access_entry(&make(AccessMode::Consume)).unwrap();

        assert_ne!(read, write);
        assert_ne!(write, consume);
        assert_ne!(read, consume);
    }

    #[test]
    fn access_manifest_encodes_deterministically() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x01, 1, 0x10),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x02, 2, 0x20),
            mode: AccessMode::Write,
        });

        let left = encode_access_manifest(&manifest).unwrap();
        let right = encode_access_manifest(&manifest).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn empty_manifest_encodes_without_error() {
        let manifest = AccessManifest::new();
        let encoded = encode_access_manifest(&manifest).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn manifest_entry_order_affects_encoding() {
        let e1 = AccessEntry {
            object_ref: sample_object_ref(0x01, 1, 0x11),
            mode: AccessMode::Read,
        };
        let e2 = AccessEntry {
            object_ref: sample_object_ref(0x02, 2, 0x22),
            mode: AccessMode::Write,
        };

        let mut m1 = AccessManifest::new();
        m1.push(e1.clone());
        m1.push(e2.clone());

        let mut m2 = AccessManifest::new();
        m2.push(e2.clone());
        m2.push(e1.clone());

        assert_ne!(
            encode_access_manifest(&m1).unwrap(),
            encode_access_manifest(&m2).unwrap()
        );
    }

    #[test]
    fn manifest_len_and_is_empty() {
        let mut manifest = AccessManifest::new();
        assert!(manifest.is_empty());
        assert_eq!(manifest.len(), 0);

        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0xFF, 0, 0xFF),
            mode: AccessMode::Consume,
        });

        assert!(!manifest.is_empty());
        assert_eq!(manifest.len(), 1);
    }

    #[test]
    fn access_entry_decoder_round_trips_existing_canonical_bytes() {
        let entry = AccessEntry {
            object_ref: sample_object_ref(0x61, 4, 0x62),
            mode: AccessMode::Consume,
        };
        let canonical: Vec<u8> = encode_access_entry(&entry).unwrap();
        assert_eq!(decode_access_entry(&canonical), Ok(entry));
    }

    #[test]
    fn access_entry_decoder_rejects_wrong_type() {
        let entry = AccessEntry {
            object_ref: sample_object_ref(0x63, 1, 0x64),
            mode: AccessMode::Read,
        };
        let mut wrong_type: Vec<u8> = encode_access_entry(&entry).unwrap();
        wrong_type[4..6].copy_from_slice(&0x5999_u16.to_le_bytes());
        assert!(matches!(
            decode_access_entry(&wrong_type),
            Err(AbiError::CanonicalDecoding(
                canonical_encoding::CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));
    }

    #[test]
    fn access_manifest_decoder_round_trips_existing_canonical_bytes() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x01, 1, 0x10),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x02, 2, 0x20),
            mode: AccessMode::Write,
        });

        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();
        assert_eq!(decode_access_manifest(&canonical, 64), Ok(manifest));
    }

    #[test]
    fn access_manifest_decoder_round_trips_empty_manifest() {
        let manifest = AccessManifest::new();
        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();
        assert_eq!(decode_access_manifest(&canonical, 64), Ok(manifest));
    }

    #[test]
    fn access_manifest_decoder_rejects_entries_above_caller_bound() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x71, 1, 0x72),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x73, 2, 0x74),
            mode: AccessMode::Write,
        });
        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();

        assert_eq!(
            decode_access_manifest(&canonical, 1),
            Err(AbiError::ManifestTooLarge(2))
        );
    }

    #[test]
    fn access_manifest_decoder_rejects_declared_count_mismatch() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x75, 1, 0x76),
            mode: AccessMode::Read,
        });
        let mut encoded: Vec<u8> = encode_access_manifest(&manifest).unwrap();
        // Field 1 (`declared_count`) is a fixed-width little-endian `u32`
        // located right after the 10-byte frame header and 6-byte field
        // header; overwrite it so it no longer matches the actual field
        // count.
        encoded[16..20].copy_from_slice(&2_u32.to_le_bytes());

        assert_eq!(
            decode_access_manifest(&encoded, 64),
            Err(AbiError::NonCanonicalManifestLayout {
                declared_count: 2,
                field_count: 2,
            })
        );
    }

    #[test]
    fn access_manifest_decoder_rejects_duplicate_object_ids() {
        let object_ref = sample_object_ref(0x77, 1, 0x78);
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: object_ref.clone(),
            mode: AccessMode::Read,
        });
        manifest.push(AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        });
        let canonical: Vec<u8> = encode_access_manifest(&manifest).unwrap();

        assert_eq!(
            decode_access_manifest(&canonical, 64),
            Err(AbiError::DuplicateObjectId(ObjectId::new([0x77; 32])))
        );
    }

    /// Regression test: a stable hex vector for the canonical encoding of a
    /// one-entry manifest so that accidental encoding changes are caught.
    #[test]
    fn manifest_stable_encoding_vector() {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x11, 7, 0x22),
            mode: AccessMode::Write,
        });

        let encoded = encode_access_manifest(&manifest).unwrap();
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();

        // This vector must remain stable across versions.
        assert_eq!(
            hex,
            "534e5245025001000200010004000000010000000200b3000000534e524501500100020001008c000000534e5245044001000300010030000000534e524501400100010001002000000011111111111111111111111111111111111111111111111111111111111111110200080000000700000000000000030038000000534e524503010100020001000200000001000200200000002222222222222222222222222222222222222222222222222222222222222222020011000000534e524506400100010001000100000002"
        );
    }

    // ── typed-ABI foundation tests ──────────────────────────────────────

    use hashing::HashingError;
    use protocol_types::{ChainId, Epoch, HashSuite, HashSuiteId, HashSuiteSchedule};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sample_resolver(chain: &str) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new(chain).unwrap(),
            protocol_types::ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    const BODY_TYPE_ID: u16 = 0x7102;
    const ASSET_ID_BODY_TYPE_ID: u16 = 0x7001;
    const COIN_CONSTRUCTOR: ConstructorId = ConstructorId::new(0x7102);
    const CAP_CONSTRUCTOR: ConstructorId = ConstructorId::new(0x7103);
    const CAP_BODY_TYPE_ID: u16 = 0x7103;

    fn coin_projection() -> Vec<ProjectionStep> {
        vec![
            ProjectionStep {
                expected_type_id: BODY_TYPE_ID,
                expected_version: 1,
                field_id: 1,
            },
            ProjectionStep {
                expected_type_id: ASSET_ID_BODY_TYPE_ID,
                expected_version: 1,
                field_id: 1,
            },
        ]
    }

    fn coin_constructor_decl() -> ConstructorDeclaration {
        ConstructorDeclaration {
            id: COIN_CONSTRUCTOR,
            body_type_id: BODY_TYPE_ID,
            body_version: 1,
            schema_version: 1,
            arity: TypeArity::Variable,
            projection: coin_projection(),
        }
    }

    fn cap_constructor_decl() -> ConstructorDeclaration {
        ConstructorDeclaration {
            id: CAP_CONSTRUCTOR,
            body_type_id: CAP_BODY_TYPE_ID,
            body_version: 1,
            schema_version: 1,
            arity: TypeArity::Variable,
            projection: vec![
                ProjectionStep {
                    expected_type_id: CAP_BODY_TYPE_ID,
                    expected_version: 1,
                    field_id: 1,
                },
                ProjectionStep {
                    expected_type_id: ASSET_ID_BODY_TYPE_ID,
                    expected_version: 1,
                    field_id: 1,
                },
            ],
        }
    }

    fn encode_asset_id_body(asset_id_byte: u8) -> Vec<u8> {
        let mut inner = CanonicalStruct::new(ASSET_ID_BODY_TYPE_ID, 1);
        inner.field_bytes(1, [asset_id_byte; 32]).unwrap();
        inner.finish().unwrap()
    }

    fn encode_coin_body(asset_id_byte: u8, amount: u64) -> Vec<u8> {
        let mut outer = CanonicalStruct::new(BODY_TYPE_ID, 1);
        outer
            .field_bytes(1, encode_asset_id_body(asset_id_byte))
            .unwrap();
        outer.field_u64(2, amount).unwrap();
        outer.finish().unwrap()
    }

    fn encode_cap_body(asset_id_byte: u8) -> Vec<u8> {
        let mut outer = CanonicalStruct::new(CAP_BODY_TYPE_ID, 1);
        outer
            .field_bytes(1, encode_asset_id_body(asset_id_byte))
            .unwrap();
        outer.finish().unwrap()
    }

    fn asset_type_arg(byte: u8) -> TypeArg {
        TypeArg::AssetId([byte; 32])
    }

    fn coin_object(
        id_byte: u8,
        asset_id_byte: u8,
        amount: u64,
        resolver: &HashSuiteResolver,
    ) -> Object {
        let data = encode_coin_body(asset_id_byte, amount);
        let tag = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(asset_id_byte)),
        };
        let type_hash = derive_type_id(resolver, Epoch::new(0), &tag).unwrap();
        Object {
            id: ObjectId::new([id_byte; 32]),
            version: 1,
            owner: objects::Owner::Shared,
            type_hash,
            schema_version: 1,
            data,
        }
    }

    fn cap_object(id_byte: u8, asset_id_byte: u8, resolver: &HashSuiteResolver) -> Object {
        let data = encode_cap_body(asset_id_byte);
        let tag = TypeTag {
            constructor: CAP_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(asset_id_byte)),
        };
        let type_hash = derive_type_id(resolver, Epoch::new(0), &tag).unwrap();
        Object {
            id: ObjectId::new([id_byte; 32]),
            version: 1,
            owner: objects::Owner::Shared,
            type_hash,
            schema_version: 1,
            data,
        }
    }

    // -- TypeArg --

    #[test]
    fn type_arg_round_trips_and_encoding_is_stable() {
        let arg = asset_type_arg(0xAB);
        let bytes = encode_type_arg(&arg).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450151010002000100020000000100020020000000abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(decode_type_arg(&bytes), Ok(arg));
    }

    #[test]
    fn type_arg_decoder_rejects_unknown_tag_and_wrong_length() {
        let mut unknown = CanonicalStruct::new(TYPE_ARG_TYPE_ID, ENCODING_VERSION);
        unknown.field_u16(1, 9).unwrap();
        assert_eq!(
            decode_type_arg(&unknown.finish().unwrap()),
            Err(AbiError::UnknownTypeArgTag(9))
        );

        let mut short = CanonicalStruct::new(TYPE_ARG_TYPE_ID, ENCODING_VERSION);
        short.field_u16(1, 1).unwrap();
        short.field_bytes(2, [0x01; 31]).unwrap();
        assert_eq!(
            decode_type_arg(&short.finish().unwrap()),
            Err(AbiError::InvalidTypeArgLength(31))
        );
    }

    #[test]
    fn type_arg_decoder_rejects_trailing_and_unknown_fields() {
        let mut trailing = encode_type_arg(&asset_type_arg(0x01)).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_type_arg(&trailing),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));

        let mut extra = CanonicalStruct::new(TYPE_ARG_TYPE_ID, ENCODING_VERSION);
        extra.field_u16(1, 1).unwrap();
        extra.field_bytes(2, [0x01; 32]).unwrap();
        extra.field_bytes(3, [0x02]).unwrap();
        assert!(matches!(
            decode_type_arg(&extra.finish().unwrap()),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }

    // -- TypeTag --

    #[test]
    fn type_tag_round_trips_with_and_without_type_arg() {
        let with_arg = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0x02)),
        };
        let without_arg = TypeTag {
            constructor: CAP_CONSTRUCTOR,
            type_arg: None,
        };

        assert_eq!(
            decode_type_tag(&encode_type_tag(&with_arg).unwrap()),
            Ok(with_arg)
        );
        assert_eq!(
            decode_type_tag(&encode_type_tag(&without_arg).unwrap()),
            Ok(without_arg)
        );
    }

    /// Regression test: a stable hex vector for a `TypeTag` with no type
    /// argument (a [`TypeArity::Fixed`] constructor's nominal type).
    #[test]
    fn type_tag_encoding_vector_without_type_arg_is_stable() {
        let tag = TypeTag {
            constructor: CAP_CONSTRUCTOR,
            type_arg: None,
        };
        let bytes = encode_type_tag(&tag).unwrap();

        assert_eq!(hex(&bytes), "534e52450251010001000100020000000371");
        assert_eq!(decode_type_tag(&bytes), Ok(tag));
    }

    /// Regression test: a stable hex vector for a `TypeTag` carrying an
    /// `AssetId` type argument (a [`TypeArity::Variable`] constructor's
    /// nominal type).
    #[test]
    fn type_tag_encoding_vector_with_type_arg_is_stable() {
        let tag = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0x77)),
        };
        let bytes = encode_type_tag(&tag).unwrap();

        assert_eq!(
            hex(&bytes),
            "534e52450251010002000100020000000271020038000000534e524501510100020001000200000001000200200000007777777777777777777777777777777777777777777777777777777777777777"
        );
        assert_eq!(decode_type_tag(&bytes), Ok(tag));
    }

    #[test]
    fn type_tag_decoder_rejects_wrong_type_and_trailing_bytes() {
        let tag = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: None,
        };
        let mut wrong_type = encode_type_tag(&tag).unwrap();
        wrong_type[4..6].copy_from_slice(&0x5199_u16.to_le_bytes());
        assert!(matches!(
            decode_type_tag(&wrong_type),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut trailing = encode_type_tag(&tag).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_type_tag(&trailing),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    // -- ConstructorRegistry --

    fn full_registry() -> ConstructorRegistry {
        let mut registry = ConstructorRegistry::new();
        registry.register(coin_constructor_decl()).unwrap();
        registry.register(cap_constructor_decl()).unwrap();
        registry
    }

    #[test]
    fn registry_lookup_by_id_and_body_type() {
        let registry = full_registry();
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get(COIN_CONSTRUCTOR).unwrap().id, COIN_CONSTRUCTOR);
        assert_eq!(
            registry.get_by_body_type(BODY_TYPE_ID).unwrap().id,
            COIN_CONSTRUCTOR
        );
        assert!(registry.get(ConstructorId::new(0x9999)).is_none());
    }

    #[test]
    fn registry_iteration_order_is_independent_of_registration_order() {
        let mut forward = ConstructorRegistry::new();
        forward.register(coin_constructor_decl()).unwrap();
        forward.register(cap_constructor_decl()).unwrap();

        let mut backward = ConstructorRegistry::new();
        backward.register(cap_constructor_decl()).unwrap();
        backward.register(coin_constructor_decl()).unwrap();

        let forward_ids: Vec<ConstructorId> = forward.iter().map(|decl| decl.id).collect();
        let backward_ids: Vec<ConstructorId> = backward.iter().map(|decl| decl.id).collect();
        assert_eq!(forward_ids, backward_ids);
        assert_eq!(forward_ids, vec![COIN_CONSTRUCTOR, CAP_CONSTRUCTOR]);
    }

    #[test]
    fn registry_rejects_duplicate_constructor_id() {
        let mut registry = ConstructorRegistry::new();
        registry.register(coin_constructor_decl()).unwrap();
        assert_eq!(
            registry.register(coin_constructor_decl()),
            Err(AbiError::DuplicateConstructorId(COIN_CONSTRUCTOR))
        );
    }

    #[test]
    fn registry_rejects_ambiguous_body_type_binding() {
        let mut registry = ConstructorRegistry::new();
        registry.register(coin_constructor_decl()).unwrap();

        // Otherwise self-consistent (its own first projection step still
        // matches its own overridden `body_type_id`), but its `body_type_id`
        // now genuinely collides with the already-registered coin
        // constructor's.
        let mut colliding = cap_constructor_decl();
        colliding.body_type_id = BODY_TYPE_ID;
        colliding.projection[0].expected_type_id = BODY_TYPE_ID;
        assert_eq!(
            registry.register(colliding),
            Err(AbiError::DuplicateBodyTypeId {
                body_type_id: BODY_TYPE_ID,
                existing: COIN_CONSTRUCTOR,
            })
        );
    }

    #[test]
    fn registry_rejects_registration_beyond_max_constructors() {
        let mut registry = ConstructorRegistry::new();
        for index in 0..MAX_CONSTRUCTORS {
            // Both `id` and `body_type_id` are offset by 1: `ConstructorId`
            // 0 is reserved, and `body_type_id` 0 is likewise rejected.
            let id = ConstructorId::new(u16::try_from(index + 1).unwrap());
            registry
                .register(ConstructorDeclaration {
                    id,
                    // Non-zero and distinct from the overflow entry below.
                    body_type_id: u16::try_from(index + 1).unwrap(),
                    body_version: 1,
                    schema_version: 1,
                    arity: TypeArity::Fixed,
                    projection: vec![],
                })
                .unwrap();
        }
        assert_eq!(registry.len(), MAX_CONSTRUCTORS);

        let overflow_id = ConstructorId::new(u16::try_from(MAX_CONSTRUCTORS + 1).unwrap());
        let result = registry.register(ConstructorDeclaration {
            id: overflow_id,
            body_type_id: u16::try_from(MAX_CONSTRUCTORS + 1).unwrap(),
            body_version: 1,
            schema_version: 1,
            arity: TypeArity::Fixed,
            projection: vec![],
        });
        assert_eq!(result, Err(AbiError::RegistryFull(MAX_CONSTRUCTORS)));
    }

    #[test]
    fn declaration_rejects_zero_constructor_id() {
        let mut zero_id = coin_constructor_decl();
        zero_id.id = ConstructorId::new(0);
        assert_eq!(
            ConstructorRegistry::new().register(zero_id),
            Err(AbiError::ZeroConstructorId)
        );
    }

    #[test]
    fn declaration_rejects_variable_first_step_body_mismatch() {
        let mut wrong_type = coin_constructor_decl();
        wrong_type.projection[0].expected_type_id = CAP_BODY_TYPE_ID;
        assert_eq!(
            ConstructorRegistry::new().register(wrong_type),
            Err(AbiError::ProjectionFirstStepMismatch {
                constructor: COIN_CONSTRUCTOR,
                body_type_id: BODY_TYPE_ID,
                body_version: 1,
                first_type_id: CAP_BODY_TYPE_ID,
                first_version: 1,
            })
        );

        let mut wrong_version = coin_constructor_decl();
        wrong_version.projection[0].expected_version = 2;
        assert_eq!(
            ConstructorRegistry::new().register(wrong_version),
            Err(AbiError::ProjectionFirstStepMismatch {
                constructor: COIN_CONSTRUCTOR,
                body_type_id: BODY_TYPE_ID,
                body_version: 1,
                first_type_id: BODY_TYPE_ID,
                first_version: 2,
            })
        );
    }

    #[test]
    fn declaration_rejects_zero_body_type_id() {
        let mut zero_body = coin_constructor_decl();
        zero_body.body_type_id = 0;
        assert_eq!(
            ConstructorRegistry::new().register(zero_body),
            Err(AbiError::ZeroBodyTypeId(COIN_CONSTRUCTOR))
        );
    }

    #[test]
    fn declaration_rejects_zero_projection_type_id() {
        let mut zero_step_type = coin_constructor_decl();
        zero_step_type.projection[1].expected_type_id = 0;
        assert_eq!(
            ConstructorRegistry::new().register(zero_step_type),
            Err(AbiError::ZeroProjectionTypeId(COIN_CONSTRUCTOR))
        );
    }

    #[test]
    fn declaration_rejects_zero_projection_field_id() {
        let mut zero_field = coin_constructor_decl();
        zero_field.projection[0].field_id = 0;
        assert_eq!(
            ConstructorRegistry::new().register(zero_field),
            Err(AbiError::ZeroProjectionFieldId(COIN_CONSTRUCTOR))
        );
    }

    #[test]
    fn declaration_rejects_arity_projection_mismatch() {
        let mut fixed_with_projection = coin_constructor_decl();
        fixed_with_projection.arity = TypeArity::Fixed;
        assert_eq!(
            ConstructorRegistry::new().register(fixed_with_projection),
            Err(AbiError::UnexpectedProjectionForFixedArity(
                COIN_CONSTRUCTOR
            ))
        );

        let mut variable_without_projection = coin_constructor_decl();
        variable_without_projection.projection = vec![];
        assert_eq!(
            ConstructorRegistry::new().register(variable_without_projection),
            Err(AbiError::EmptyProjectionForVariableArity(COIN_CONSTRUCTOR))
        );

        let mut too_deep = coin_constructor_decl();
        too_deep.projection = (0..=MAX_PROJECTION_DEPTH)
            .map(|_| ProjectionStep {
                expected_type_id: BODY_TYPE_ID,
                expected_version: 1,
                field_id: 1,
            })
            .collect();
        assert_eq!(
            ConstructorRegistry::new().register(too_deep),
            Err(AbiError::ProjectionTooDeep(MAX_PROJECTION_DEPTH + 1))
        );
    }

    // -- body projection --

    #[test]
    fn projection_extracts_asset_id_from_field_one() {
        let decl = coin_constructor_decl();
        let body = encode_coin_body(0x42, 100);
        assert_eq!(
            project_type_arg(&decl, &body).unwrap(),
            Some(asset_type_arg(0x42))
        );
    }

    #[test]
    fn projection_is_insensitive_to_amount_mutation() {
        let decl = coin_constructor_decl();
        let body_a = encode_coin_body(0x42, 1);
        let body_b = encode_coin_body(0x42, 999_999);
        assert_eq!(
            project_type_arg(&decl, &body_a).unwrap(),
            project_type_arg(&decl, &body_b).unwrap()
        );
    }

    #[test]
    fn projection_changes_with_asset_id_mutation() {
        let decl = coin_constructor_decl();
        let body_a = encode_coin_body(0x42, 1);
        let body_b = encode_coin_body(0x43, 1);
        assert_ne!(
            project_type_arg(&decl, &body_a).unwrap(),
            project_type_arg(&decl, &body_b).unwrap()
        );
    }

    #[test]
    fn projection_rejects_malformed_and_trailing_and_wrong_type_bodies() {
        let decl = coin_constructor_decl();

        let mut truncated = encode_coin_body(0x11, 1);
        truncated.truncate(5);
        assert!(matches!(
            project_type_arg(&decl, &truncated),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::Truncated { .. }
            ))
        ));

        let mut wrong_type = CanonicalStruct::new(0x9999, 1);
        wrong_type
            .field_bytes(1, encode_asset_id_body(0x11))
            .unwrap();
        wrong_type.field_u64(2, 1).unwrap();
        assert_eq!(
            project_type_arg(&decl, &wrong_type.finish().unwrap()),
            Err(AbiError::ProjectionTypeMismatch {
                expected: BODY_TYPE_ID,
                actual: 0x9999,
            })
        );

        let mut trailing_inner = encode_asset_id_body(0x11);
        trailing_inner.push(0xFF);
        let mut outer_with_trailing_inner = CanonicalStruct::new(BODY_TYPE_ID, 1);
        outer_with_trailing_inner
            .field_bytes(1, trailing_inner)
            .unwrap();
        outer_with_trailing_inner.field_u64(2, 1).unwrap();
        assert!(matches!(
            project_type_arg(&decl, &outer_with_trailing_inner.finish().unwrap()),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));

        let mut short_asset_id = CanonicalStruct::new(ASSET_ID_BODY_TYPE_ID, 1);
        short_asset_id.field_bytes(1, [0x11; 31]).unwrap();
        let mut outer_short = CanonicalStruct::new(BODY_TYPE_ID, 1);
        outer_short
            .field_bytes(1, short_asset_id.finish().unwrap())
            .unwrap();
        outer_short.field_u64(2, 1).unwrap();
        assert_eq!(
            project_type_arg(&decl, &outer_short.finish().unwrap()),
            Err(AbiError::ProjectionLength {
                expected: 32,
                actual: 31,
            })
        );
    }

    #[test]
    fn projection_rejects_extra_field_in_terminal_inner_frame() {
        // The outer Coin body legitimately carries an unrelated `amount`
        // field (not the terminal step, so it is not restricted), but the
        // terminal inner `AssetId` frame must contain nothing besides its
        // declared field.
        let decl = coin_constructor_decl();
        let mut inner_with_extra_field = CanonicalStruct::new(ASSET_ID_BODY_TYPE_ID, 1);
        inner_with_extra_field.field_bytes(1, [0x11; 32]).unwrap();
        inner_with_extra_field.field_bytes(2, [0xAA]).unwrap();
        let mut outer = CanonicalStruct::new(BODY_TYPE_ID, 1);
        outer
            .field_bytes(1, inner_with_extra_field.finish().unwrap())
            .unwrap();
        outer.field_u64(2, 1).unwrap();

        assert_eq!(
            project_type_arg(&decl, &outer.finish().unwrap()),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(2)
            ))
        );
    }

    #[test]
    fn fixed_arity_projection_validates_body_type_and_version_but_returns_no_type_arg() {
        let decl = ConstructorDeclaration {
            id: ConstructorId::new(0x7101),
            body_type_id: 0x7101,
            body_version: 1,
            schema_version: 1,
            arity: TypeArity::Fixed,
            projection: vec![],
        };

        let mut well_formed = CanonicalStruct::new(0x7101, 1);
        well_formed.field_bytes(1, [0x01; 32]).unwrap();
        assert_eq!(
            project_type_arg(&decl, &well_formed.finish().unwrap()),
            Ok(None)
        );

        assert!(matches!(
            project_type_arg(&decl, b"not canonical at all"),
            Err(AbiError::CanonicalDecoding(_))
        ));

        let mut wrong_type = CanonicalStruct::new(0x9999, 1);
        wrong_type.field_bytes(1, [0x01; 32]).unwrap();
        assert_eq!(
            project_type_arg(&decl, &wrong_type.finish().unwrap()),
            Err(AbiError::ProjectionTypeMismatch {
                expected: 0x7101,
                actual: 0x9999,
            })
        );

        let mut wrong_version = CanonicalStruct::new(0x7101, 2);
        wrong_version.field_bytes(1, [0x01; 32]).unwrap();
        assert_eq!(
            project_type_arg(&decl, &wrong_version.finish().unwrap()),
            Err(AbiError::ProjectionVersionMismatch {
                expected: 1,
                actual: 2,
            })
        );
    }

    // -- type-id derivation/verification --

    #[test]
    fn type_id_changes_with_constructor_and_asset_id_but_not_protocol_version() {
        let resolver_v1 = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            protocol_types::ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let resolver_v2 = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            protocol_types::ProtocolVersion::new(2),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();

        let coin_a = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0xA1)),
        };
        let coin_b = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0xB2)),
        };
        let cap_a = TypeTag {
            constructor: CAP_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0xA1)),
        };

        let coin_a_v1 = derive_type_id(&resolver_v1, Epoch::new(0), &coin_a).unwrap();
        let coin_a_v2 = derive_type_id(&resolver_v2, Epoch::new(0), &coin_a).unwrap();
        let coin_b_v1 = derive_type_id(&resolver_v1, Epoch::new(0), &coin_b).unwrap();
        let cap_a_v1 = derive_type_id(&resolver_v1, Epoch::new(0), &cap_a).unwrap();

        // Protocol-version invariance: an object's nominal type identity
        // must survive a protocol upgrade.
        assert_eq!(coin_a_v1, coin_a_v2);
        // Chain/constructor/AssetId separation.
        assert_ne!(coin_a_v1, coin_b_v1, "AssetId must separate type identity");
        assert_ne!(
            coin_a_v1, cap_a_v1,
            "constructor must separate type identity"
        );

        let other_chain_resolver = sample_resolver("sunrise-devnet-other");
        let coin_a_other_chain =
            derive_type_id(&other_chain_resolver, Epoch::new(0), &coin_a).unwrap();
        assert_ne!(
            coin_a_v1, coin_a_other_chain,
            "chain must separate type identity"
        );
    }

    #[test]
    fn verify_type_id_round_trips_and_rejects_tampering() {
        let resolver = sample_resolver("sunrise-devnet");
        let tag = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0x11)),
        };
        let digest = derive_type_id(&resolver, Epoch::new(0), &tag).unwrap();
        assert_eq!(
            verify_type_id(&resolver, &digest, Epoch::new(0), &tag),
            Ok(true)
        );

        let tampered_tag = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0x12)),
        };
        assert_eq!(
            verify_type_id(&resolver, &digest, Epoch::new(0), &tampered_tag),
            Ok(false)
        );
    }

    #[test]
    fn type_id_verification_fails_closed_for_out_of_schedule_algorithm() {
        let resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            protocol_types::ProtocolVersion::new(1),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(500),
                    suite: HashSuite::uniform(
                        HashSuiteId::new(2),
                        protocol_types::HashAlgorithmId::Sha3_256,
                    ),
                },
            ],
        )
        .unwrap();
        let tag = TypeTag {
            constructor: COIN_CONSTRUCTOR,
            type_arg: Some(asset_type_arg(0x11)),
        };
        let future_digest = derive_type_id(&resolver, Epoch::new(500), &tag).unwrap();
        assert_eq!(
            future_digest.algorithm(),
            protocol_types::HashAlgorithmId::Sha3_256
        );

        assert_eq!(
            verify_type_id(&resolver, &future_digest, Epoch::new(0), &tag),
            Err(AbiError::Hashing(
                HashingError::UntrustedAlgorithmForEpoch {
                    algorithm: protocol_types::HashAlgorithmId::Sha3_256,
                    purpose: protocol_types::HashPurpose::ObjectType,
                    epoch: Epoch::new(0),
                }
            ))
        );
    }

    // -- EntrypointSignature --

    #[test]
    fn entrypoint_signature_rejects_empty_and_oversized_name_and_too_many_params() {
        assert_eq!(
            EntrypointSignature::new("", vec![]),
            Err(AbiError::EmptyEntrypointName)
        );
        assert_eq!(
            EntrypointSignature::new("e".repeat(MAX_ENTRYPOINT_BYTES + 1), vec![]),
            Err(AbiError::EntrypointNameTooLong(MAX_ENTRYPOINT_BYTES + 1))
        );
        // Dependency-safe identical restatement of
        // `execution::MAX_TRANSACTION_ENTRYPOINT_BYTES`, not
        // `signing-view`'s narrower optional hardware display bound.
        assert_eq!(MAX_ENTRYPOINT_BYTES, 256);

        let params = (0..=MAX_PARAMS)
            .map(|_| ParamDeclaration {
                mode: AccessMode::Read,
                constructor: COIN_CONSTRUCTOR,
                schema_version: 1,
            })
            .collect();
        assert_eq!(
            EntrypointSignature::new("too-many", params),
            Err(AbiError::TooManyParams(MAX_PARAMS + 1))
        );
    }

    // -- single-pass pre-execution input verification --

    fn transfer_signature() -> EntrypointSignature {
        EntrypointSignature::new(
            "transfer",
            vec![ParamDeclaration {
                mode: AccessMode::Write,
                constructor: COIN_CONSTRUCTOR,
                schema_version: 1,
            }],
        )
        .unwrap()
    }

    fn mint_signature() -> EntrypointSignature {
        EntrypointSignature::new(
            "mint",
            vec![
                ParamDeclaration {
                    mode: AccessMode::Read,
                    constructor: CAP_CONSTRUCTOR,
                    schema_version: 1,
                },
                ParamDeclaration {
                    mode: AccessMode::Write,
                    constructor: COIN_CONSTRUCTOR,
                    schema_version: 1,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn verification_accepts_a_well_formed_single_input() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = transfer_signature();
        let coin = coin_object(0x01, 0x77, 500, &resolver);
        let inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &coin,
        }];

        let bindings =
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs)
                .unwrap();
        assert_eq!(bindings.inputs.len(), 1);
        assert_eq!(
            bindings.inputs[0].type_tag.type_arg,
            Some(asset_type_arg(0x77))
        );
    }

    #[test]
    fn verification_rejects_arity_mismatch() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = transfer_signature();

        assert_eq!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &[]),
            Err(AbiError::ArityMismatch {
                expected: 1,
                actual: 0,
            })
        );
    }

    #[test]
    fn verification_rejects_access_mode_mismatch() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = transfer_signature();
        let coin = coin_object(0x01, 0x77, 500, &resolver);
        let inputs = [ResolvedInput {
            mode: AccessMode::Read,
            object: &coin,
        }];

        assert_eq!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::AccessModeMismatch {
                index: 0,
                expected: AccessMode::Write,
                actual: AccessMode::Read,
            })
        );
    }

    #[test]
    fn verification_rejects_object_schema_version_mismatch() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = transfer_signature();
        let mut coin = coin_object(0x01, 0x77, 500, &resolver);
        coin.schema_version = 2;
        let inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &coin,
        }];

        assert_eq!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::ObjectSchemaVersionMismatch {
                index: 0,
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn verification_rejects_unknown_constructor() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = ConstructorRegistry::new();
        let signature = transfer_signature();
        let coin = coin_object(0x01, 0x77, 500, &resolver);
        let inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &coin,
        }];

        assert_eq!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::UnknownConstructor(COIN_CONSTRUCTOR))
        );
    }

    #[test]
    fn verification_rejects_coin_a_claimed_as_coin_b_body_header_disagreement() {
        // The object's stored `type_hash` is honestly derived for asset A,
        // but its body is swapped to encode asset B afterward: a
        // Coin<A>/Coin<B> disagreement between an object's header and its
        // projected body must be rejected.
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = transfer_signature();
        let mut coin = coin_object(0x01, 0xA0, 500, &resolver);
        let stored_digest = coin.type_hash;
        coin.data = encode_coin_body(0xB0, 500);
        let inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &coin,
        }];

        assert_eq!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::TypeIdentityMismatch {
                index: 0,
                type_tag: TypeTag {
                    constructor: COIN_CONSTRUCTOR,
                    type_arg: Some(asset_type_arg(0xB0)),
                },
                actual: stored_digest,
            })
        );
    }

    #[test]
    fn verification_accepts_mint_cap_a_and_coin_a_same_asset() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = mint_signature();
        let cap = cap_object(0x02, 0x55, &resolver);
        let coin = coin_object(0x03, 0x55, 10, &resolver);
        let inputs = [
            ResolvedInput {
                mode: AccessMode::Read,
                object: &cap,
            },
            ResolvedInput {
                mode: AccessMode::Write,
                object: &coin,
            },
        ];

        let bindings =
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs)
                .unwrap();
        assert_eq!(bindings.inputs.len(), 2);
    }

    #[test]
    fn verification_rejects_mint_cap_b_and_coin_a_different_assets() {
        let resolver = sample_resolver("sunrise-devnet");
        let registry = full_registry();
        let signature = mint_signature();
        let cap = cap_object(0x02, 0x66, &resolver);
        let coin = coin_object(0x03, 0x55, 10, &resolver);
        let inputs = [
            ResolvedInput {
                mode: AccessMode::Read,
                object: &cap,
            },
            ResolvedInput {
                mode: AccessMode::Write,
                object: &coin,
            },
        ];

        assert_eq!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::TypeVariableMismatch {
                index: 1,
                expected: asset_type_arg(0x66),
                actual: asset_type_arg(0x55),
            })
        );
    }

    #[test]
    fn verification_accepts_old_and_new_algorithm_commitments_for_same_type_after_rotation() {
        // A Coin<A> object created before a hash-suite rotation (`type_hash`
        // committed under SHA2-256) and one created after (committed under
        // SHA3-256) must both still verify once the active suite has moved
        // on to SHA3-256, and both must bind the same logical `AssetId`,
        // even though their raw `type_hash` bytes differ because they were
        // committed under different algorithms.
        let resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            protocol_types::ProtocolVersion::new(1),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(500),
                    suite: HashSuite::uniform(
                        HashSuiteId::new(2),
                        protocol_types::HashAlgorithmId::Sha3_256,
                    ),
                },
            ],
        )
        .unwrap();
        let registry = full_registry();
        let signature = transfer_signature();
        let asset_id_byte = 0x9A;

        let old_type_hash = derive_type_id(
            &resolver,
            Epoch::new(0),
            &TypeTag {
                constructor: COIN_CONSTRUCTOR,
                type_arg: Some(asset_type_arg(asset_id_byte)),
            },
        )
        .unwrap();
        assert_eq!(
            old_type_hash.algorithm(),
            protocol_types::HashAlgorithmId::Sha2_256
        );
        let old_coin = Object {
            id: ObjectId::new([0x01; 32]),
            version: 1,
            owner: objects::Owner::Shared,
            type_hash: old_type_hash,
            schema_version: 1,
            data: encode_coin_body(asset_id_byte, 500),
        };

        let new_type_hash = derive_type_id(
            &resolver,
            Epoch::new(500),
            &TypeTag {
                constructor: COIN_CONSTRUCTOR,
                type_arg: Some(asset_type_arg(asset_id_byte)),
            },
        )
        .unwrap();
        assert_eq!(
            new_type_hash.algorithm(),
            protocol_types::HashAlgorithmId::Sha3_256
        );
        let new_coin = Object {
            id: ObjectId::new([0x02; 32]),
            version: 1,
            owner: objects::Owner::Shared,
            type_hash: new_type_hash,
            schema_version: 1,
            data: encode_coin_body(asset_id_byte, 10),
        };

        // Both were committed under algorithms trusted at or before the
        // current epoch, so both verify, despite their differing raw bytes.
        assert_ne!(old_type_hash, new_type_hash);
        let verify_epoch = Epoch::new(600);

        let old_inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &old_coin,
        }];
        let new_inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &new_coin,
        }];
        let old_bindings =
            verify_entrypoint_inputs(&signature, &registry, &resolver, verify_epoch, &old_inputs)
                .unwrap();
        let new_bindings =
            verify_entrypoint_inputs(&signature, &registry, &resolver, verify_epoch, &new_inputs)
                .unwrap();

        // Both verified inputs bind the exact same logical `AssetId`.
        assert_eq!(
            old_bindings.inputs[0].type_tag.type_arg,
            new_bindings.inputs[0].type_tag.type_arg
        );
        assert_eq!(
            old_bindings.inputs[0].type_tag,
            new_bindings.inputs[0].type_tag
        );
    }

    // -- DR-0106: persisted typed-ABI policy components --

    #[test]
    fn projection_step_round_trips_and_rejects_trailing_and_unknown_fields() {
        let step = ProjectionStep {
            expected_type_id: 0x7102,
            expected_version: 1,
            field_id: 1,
        };
        let encoded = encode_projection_step(&step).unwrap();
        assert_eq!(decode_projection_step(&encoded).unwrap(), step);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_projection_step(&trailing).is_err());

        let mut unknown = CanonicalStruct::new(PROJECTION_STEP_TYPE_ID, ENCODING_VERSION);
        unknown.field_u16(1, 1).unwrap();
        unknown.field_u16(2, 1).unwrap();
        unknown.field_u16(3, 1).unwrap();
        unknown.field_u16(4, 1).unwrap();
        assert!(matches!(
            decode_projection_step(&unknown.finish().unwrap()),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(4)
            ))
        ));
    }

    #[test]
    fn projection_step_encoding_vector_is_stable() {
        const VECTOR: [u8; 34] = [
            83, 78, 82, 69, 3, 81, 1, 0, 3, 0, 1, 0, 2, 0, 0, 0, 2, 113, 2, 0, 2, 0, 0, 0, 1, 0, 3,
            0, 2, 0, 0, 0, 1, 0,
        ];
        let step = ProjectionStep {
            expected_type_id: 0x7102,
            expected_version: 1,
            field_id: 1,
        };
        assert_eq!(encode_projection_step(&step).unwrap(), VECTOR);
    }

    #[test]
    fn constructor_declaration_round_trips_fixed_and_variable_arity() {
        let coin = coin_constructor_decl();
        let encoded_coin = encode_constructor_declaration(&coin).unwrap();
        assert_eq!(decode_constructor_declaration(&encoded_coin).unwrap(), coin);

        let fixed = ConstructorDeclaration {
            id: ConstructorId::new(0x7101),
            body_type_id: 0x7101,
            body_version: 1,
            schema_version: 1,
            arity: TypeArity::Fixed,
            projection: Vec::new(),
        };
        let encoded_fixed = encode_constructor_declaration(&fixed).unwrap();
        assert_eq!(
            decode_constructor_declaration(&encoded_fixed).unwrap(),
            fixed
        );
        assert_ne!(encoded_coin, encoded_fixed);
    }

    #[test]
    fn constructor_declaration_decoder_rejects_zero_ids_bad_arity_and_deep_projection() {
        let mut zero_id = coin_constructor_decl();
        zero_id.id = ConstructorId::new(0);
        assert_eq!(
            decode_constructor_declaration(&encode_constructor_declaration(&zero_id).unwrap()),
            Err(AbiError::ZeroConstructorId)
        );

        let mut zero_body = coin_constructor_decl();
        zero_body.body_type_id = 0;
        assert_eq!(
            decode_constructor_declaration(&encode_constructor_declaration(&zero_body).unwrap()),
            Err(AbiError::ZeroBodyTypeId(zero_body.id))
        );

        let mut zero_step_type = coin_constructor_decl();
        zero_step_type.projection[1].expected_type_id = 0;
        assert_eq!(
            decode_constructor_declaration(
                &encode_constructor_declaration(&zero_step_type).unwrap()
            ),
            Err(AbiError::ZeroProjectionTypeId(zero_step_type.id))
        );

        let mut zero_field_id = coin_constructor_decl();
        zero_field_id.projection[1].field_id = 0;
        assert_eq!(
            decode_constructor_declaration(
                &encode_constructor_declaration(&zero_field_id).unwrap()
            ),
            Err(AbiError::ZeroProjectionFieldId(zero_field_id.id))
        );

        let mut mismatched_first_step = coin_constructor_decl();
        mismatched_first_step.projection[0].expected_type_id = 0x9999;
        let expected = AbiError::ProjectionFirstStepMismatch {
            constructor: mismatched_first_step.id,
            body_type_id: mismatched_first_step.body_type_id,
            body_version: mismatched_first_step.body_version,
            first_type_id: 0x9999,
            first_version: 1,
        };
        assert_eq!(
            decode_constructor_declaration(
                &encode_constructor_declaration(&mismatched_first_step).unwrap()
            ),
            Err(expected)
        );

        let mut fixed_with_projection = ConstructorDeclaration {
            id: ConstructorId::new(0x7101),
            body_type_id: 0x7101,
            body_version: 1,
            schema_version: 1,
            arity: TypeArity::Fixed,
            projection: coin_projection(),
        };
        assert_eq!(
            decode_constructor_declaration(
                &encode_constructor_declaration(&fixed_with_projection).unwrap()
            ),
            Err(AbiError::UnexpectedProjectionForFixedArity(
                fixed_with_projection.id
            ))
        );
        fixed_with_projection.projection.clear();

        let mut too_deep = coin_constructor_decl();
        too_deep.projection = (0..=u16::try_from(MAX_PROJECTION_DEPTH).unwrap())
            .map(|index| ProjectionStep {
                expected_type_id: if index == 0 { BODY_TYPE_ID } else { 1 },
                expected_version: 1,
                field_id: 1,
            })
            .collect();
        assert_eq!(
            encode_constructor_declaration(&too_deep),
            Err(AbiError::ProjectionTooDeep(MAX_PROJECTION_DEPTH + 1))
        );

        let mut unknown_arity =
            CanonicalStruct::new(CONSTRUCTOR_DECLARATION_TYPE_ID, ENCODING_VERSION);
        unknown_arity.field_u16(1, 0x7102).unwrap();
        unknown_arity.field_u16(2, 0x7102).unwrap();
        unknown_arity.field_u16(3, 1).unwrap();
        unknown_arity.field_u32(4, 1).unwrap();
        unknown_arity.field_u16(5, 7).unwrap();
        unknown_arity.field_u32(6, 0).unwrap();
        assert_eq!(
            decode_constructor_declaration(&unknown_arity.finish().unwrap()),
            Err(AbiError::UnknownTypeArityTag(7))
        );

        let mut trailing = encode_constructor_declaration(&coin_constructor_decl()).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_constructor_declaration(&trailing),
            Err(AbiError::CanonicalDecoding(_))
        ));
    }

    #[test]
    fn param_declaration_round_trips_and_rejects_zero_constructor() {
        let param = ParamDeclaration {
            mode: AccessMode::Write,
            constructor: COIN_CONSTRUCTOR,
            schema_version: 1,
        };
        let encoded = encode_param_declaration(&param).unwrap();
        assert_eq!(decode_param_declaration(&encoded).unwrap(), param);

        let zero = ParamDeclaration {
            mode: AccessMode::Write,
            constructor: ConstructorId::new(0),
            schema_version: 1,
        };
        assert_eq!(
            encode_param_declaration(&zero),
            Err(AbiError::ZeroConstructorId)
        );

        let mut wire = CanonicalStruct::new(PARAM_DECLARATION_TYPE_ID, ENCODING_VERSION);
        wire.field_bytes(1, encode_access_mode(AccessMode::Write).unwrap())
            .unwrap();
        wire.field_u16(2, 0).unwrap();
        wire.field_u32(3, 1).unwrap();
        assert_eq!(
            decode_param_declaration(&wire.finish().unwrap()),
            Err(AbiError::ZeroConstructorId)
        );
    }

    #[test]
    fn entrypoint_signature_round_trips_and_rejects_bad_shapes() {
        let signature = mint_signature();
        let encoded = encode_entrypoint_signature(&signature).unwrap();
        assert_eq!(decode_entrypoint_signature(&encoded).unwrap(), signature);

        let single = transfer_signature();
        let encoded_single = encode_entrypoint_signature(&single).unwrap();
        assert_ne!(encoded, encoded_single);
        assert_eq!(
            decode_entrypoint_signature(&encoded_single).unwrap(),
            single
        );

        let mut trailing = encoded_single.clone();
        trailing.push(0);
        assert!(matches!(
            decode_entrypoint_signature(&trailing),
            Err(AbiError::CanonicalDecoding(_))
        ));

        let mut declared_count_mismatch =
            CanonicalStruct::new(ENTRYPOINT_SIGNATURE_TYPE_ID, ENCODING_VERSION);
        declared_count_mismatch.field_str(1, "transfer").unwrap();
        declared_count_mismatch.field_u32(2, 2).unwrap();
        declared_count_mismatch
            .field_bytes(
                3,
                encode_param_declaration(&ParamDeclaration {
                    mode: AccessMode::Write,
                    constructor: COIN_CONSTRUCTOR,
                    schema_version: 1,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            decode_entrypoint_signature(&declared_count_mismatch.finish().unwrap()),
            Err(AbiError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(4)
            ))
        ));

        let too_many_params: Vec<ParamDeclaration> = (0..=MAX_PARAMS)
            .map(|_| ParamDeclaration {
                mode: AccessMode::Read,
                constructor: COIN_CONSTRUCTOR,
                schema_version: 1,
            })
            .collect();
        let mut oversized = CanonicalStruct::new(ENTRYPOINT_SIGNATURE_TYPE_ID, ENCODING_VERSION);
        oversized.field_str(1, "too-many").unwrap();
        oversized
            .field_u32(2, u32::try_from(too_many_params.len()).unwrap())
            .unwrap();
        assert_eq!(
            decode_entrypoint_signature(&oversized.finish().unwrap()),
            Err(AbiError::TooManyParams(too_many_params.len()))
        );
    }
}
