//! Reserved immutable public-instance authority storage and legacy isolation.
//!
//! Key construction confers no authority. Only the fenced typed execution
//! admission may populate these rows; generic plans cannot access either root.

use super::*;
use canonical_encoding::encode_chain_id;
use execution::publication::{PublicationContext, encode_publication_context};
use protocol_types::ValidatorId;

/// Reserved across storage-profile and protocol upgrades.
pub const INSTANCE_STATE_PREFIX: &[u8] = b"se/instances/";
/// Reserved authority provenance, including retained consumed-object sidecars.
pub const OBJECT_AUTHORITY_STATE_PREFIX: &[u8] = b"se/object-authority/";

/// Immutable logical instance key: self-framed chain followed by two bytes32
/// fields. Protocol versions, epochs and digest algorithms do not change it.
pub fn instance_record_key(
    chain: &ChainId,
    creator: &[u8; 32],
    seed: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = INSTANCE_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/records/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(creator);
    key.extend_from_slice(seed);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Immutable authority key in the same atomicity domain as its object head.
#[must_use]
pub fn object_authority_key(object_id: ObjectId) -> Vec<u8> {
    let mut key: Vec<u8> = OBJECT_AUTHORITY_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/");
    key.extend_from_slice(object_id.as_bytes());
    key
}

/// Trusted execution policy key retains the original verification context.
pub fn execution_policy_key(context: &PublicationContext) -> Result<Vec<u8>, NodeCoreError> {
    execution_policy_key_for_profile(context, 2)
}
/// Explicit profile-key activation; profile-two retains its historical key.
pub fn execution_policy_key_for_profile(
    context: &PublicationContext,
    profile: u32,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = INSTANCE_STATE_PREFIX.to_vec();
    match profile {
        2 => key.extend_from_slice(b"v1/policies/"),
        3 => key.extend_from_slice(b"v2/policies/"),
        4 => key.extend_from_slice(b"v3/policies/"),
        _ => {
            return Err(NodeCoreError::PersistenceInvariant(
                "unsupported execution profile",
            ));
        }
    }
    key.extend(encode_publication_context(context).map_err(|_| {
        NodeCoreError::PersistenceInvariant("invalid local execution policy context")
    })?);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Dedicated durable-policy prerequisite for DR-0124 paid execution. Reserved
/// under the instance-state namespace and context-bound like the execution
/// policy keys. Key construction alone confers no installation authority; a
/// distinct paid coordinator admission path governs whether any value at
/// this key is ever installed or read.
pub fn paid_fee_policy_key(context: &PublicationContext) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = INSTANCE_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/fee-policy/");
    key.extend(
        encode_publication_context(context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid paid fee policy context"))?,
    );
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Signed FastVote economics policy installed atomically with genesis.
///
/// The row is context-bound and lives under the already-reserved instance
/// namespace. Generic contract execution therefore cannot observe or mutate
/// the protocol's collateral and fee-custody authority.
pub fn fastpath_economics_policy_key(
    context: &PublicationContext,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"economics-policy/");
    key.extend(encode_publication_context(context).map_err(|_| {
        NodeCoreError::PersistenceInvariant("invalid fast-path economics policy context")
    })?);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

pub(super) fn is_reserved(key: &[u8]) -> bool {
    key.starts_with(INSTANCE_STATE_PREFIX) || key.starts_with(OBJECT_AUTHORITY_STATE_PREFIX)
}

/// Reserved under [`INSTANCE_STATE_PREFIX`], so every existing enforcement
/// point that already calls [`is_reserved`] covers it for free: no contract
/// or generic transactional plan may read or write here.
pub(crate) const FASTPATH_STATE_PREFIX: &[u8] = b"se/instances/v1/fastpath/";

/// One durable prepared-vote record, keyed by the *original* signed
/// [`execution::paid_execution::PaidIntent::request_id`]. Reconciled before
/// any nonce/policy/object read so exact replay is byte-identical and a
/// conflicting replay fails closed.
pub fn fastpath_prepared_record_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"prepared/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// One exclusive per-object lock, held from a successful prepare commit
/// until the owning request's certificate apply deletes it. There is no
/// timeout or clock-based expiry. DR-0132 additionally permits a lock stamped
/// with a permanently retired epoch to be lazily overwritten or deleted by a
/// later current-epoch mutation under the same CAS revision; a current-epoch
/// lock remains releasable only by its own successful
/// [`crate::fast_path::apply`].
pub fn fastpath_lock_key(chain: &ChainId, object_id: ObjectId) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"lock/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(object_id.as_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// One exclusive sender/epoch nonce lock. Prepare asserts the ordinary
/// sender-nonce row but does not advance it; certificate apply advances that
/// row and deletes this lock in the same durable invocation.
pub fn fastpath_nonce_lock_key(
    chain: &ChainId,
    sender: &[u8; 32],
    epoch: Epoch,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"nonce-lock/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(sender);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// The exact verified [`consensus::FastCertificate`] bytes a successful
/// apply committed for one original request id, retained as a permanent
/// audit record.
pub fn fastpath_certificate_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"certificate/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Charged-amount/fee-output/signer-set settlement metadata for later
/// (Phase 3, not implemented here) fee distribution to certificate signers.
pub fn fastpath_settlement_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"settlement/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// One DR-0136 typed bond commitment for a validator. The chain and
/// validator identify the single active bond row; the row itself binds the
/// resource and exact custody object. A second genesis custody object for the
/// same validator therefore collides instead of being summed implicitly.
pub fn fastpath_bond_record_key(
    chain: &ChainId,
    validator: &ValidatorId,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"bond/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(validator.as_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// One permanent DR-0137 [`crate::fast_path::records::FastPathBondTransitionRecord`]
/// audit row, keyed by validator and the post-transition generation. Never
/// overwritten: each lifecycle commit writes exactly one fresh key.
pub fn fastpath_bond_transition_key(
    chain: &ChainId,
    validator: &ValidatorId,
    generation: u64,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"bond-transition/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(validator.as_bytes());
    key.extend_from_slice(&generation.to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// The durable, epoch-scoped static validator set a [`consensus::FastPathCertifier`]
/// is bound to. Production installs it atomically from the signed
/// [`crate::genesis::GenesisManifest`]; the focused test helper in
/// [`crate::fast_path`] writes the same record shape. Contracts and generic
/// transactional plans can never write this reserved namespace.
pub fn fastpath_validator_set_key(context: &PublicationContext) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"validators/");
    key.extend(
        encode_publication_context(context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid validator set context"))?,
    );
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// First 8 bytes of every synthetic fast-path prepare-receipt
/// [`RequestId`](crate::RequestId): a fixed ASCII tag chosen so a
/// legitimately random, externally supplied 32-byte
/// [`execution::paid_execution::PaidIntent::request_id`] lands here with
/// negligible probability, and so it is trivial to reject any signed intent
/// that *does* land here before it could squat the namespace.
pub const FASTPATH_SYNTHETIC_REQUEST_ID_TAG: [u8; 8] = *b"SE:FPv1:";

/// True exactly for a 32-byte request id inside the reserved synthetic
/// fast-path prepare-receipt namespace. A [`execution::paid_execution::PaidIntent`]
/// carrying one of these must be rejected before any admission, so the
/// namespace can never be squatted by an externally chosen request id.
#[must_use]
pub fn is_reserved_paid_request_id(request_id: &[u8; 32]) -> bool {
    request_id[..FASTPATH_SYNTHETIC_REQUEST_ID_TAG.len()] == FASTPATH_SYNTHETIC_REQUEST_ID_TAG
}

/// DR-0131's one shared external-request validation boundary: every
/// externally reachable event/mutation family (`SignedPaidIntent`,
/// `SignedLocalExecutionIntent`, `PublicationSubmission`, and the
/// `SubmitTransaction` event envelope) calls this exact function on its own
/// admission/authentication boundary, before accepting the request id as
/// genuine external input. It is deliberately distinct from
/// [`fastpath_synthetic_prepare_request_id`]'s internal/system construction
/// path, which node-owned code alone calls to build a value *inside* this
/// reserved namespace; that path is never reachable from external input, so
/// it needs no gate here.
pub fn reject_reserved_request_id(request_id: &[u8; 32]) -> Result<(), &'static str> {
    if is_reserved_paid_request_id(request_id) {
        return Err("request id reserved for fast-path synthetic receipts");
    }
    Ok(())
}

/// Deterministically derives the synthetic
/// [`DurableRequestId`](runtime::DurableRequestId) a prepare commit's
/// mandatory [`runtime::DurableRequestReceipt`] is keyed by: the reserved
/// tag followed by 24 bytes of a dedicated hash of the *epoch* and the
/// *original* request id, so exact replay always re-derives the identical
/// synthetic id and two different `(epoch, original_request_id)` pairs
/// collide only with cryptographically negligible probability. This is
/// bookkeeping only: prepare's own replay idempotency is governed by
/// [`fastpath_prepared_record_key`], not by this synthetic id.
///
/// The epoch is mixed directly into the preimage bytes, not left to
/// `resolver.hash_for_purpose`'s own epoch-indexed suite selection alone
/// (DR-0132 C5): a [`HashSuiteResolver`] with one schedule entry spanning
/// both the outgoing and incoming epoch selects the identical suite for
/// both, which would otherwise make this function produce the identical
/// synthetic id for the same original request id reused at the next epoch
/// (DR-0132's own stale-prepared-record supersession case) -- silently
/// colliding with the outgoing epoch's already-committed synthetic receipt
/// instead of the two epochs' prepares ever being distinguishable.
pub fn fastpath_synthetic_prepare_request_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    original_request_id: &[u8; 32],
) -> Result<[u8; 32], NodeCoreError> {
    let mut preimage: Vec<u8> = b"se-fastpath-prepare-receipt-v1".to_vec();
    preimage.extend_from_slice(&epoch.get().to_be_bytes());
    preimage.extend_from_slice(original_request_id);
    let digest: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::NodeEvent, &preimage)
        .map_err(NodeCoreError::Hashing)?;
    let mut synthetic: [u8; 32] = [0u8; 32];
    let tag_len: usize = FASTPATH_SYNTHETIC_REQUEST_ID_TAG.len();
    synthetic[..tag_len].copy_from_slice(&FASTPATH_SYNTHETIC_REQUEST_ID_TAG);
    synthetic[tag_len..].copy_from_slice(&digest.bytes()[tag_len..]);
    Ok(synthetic)
}

/// Frame `0x641B/v1`: one exclusive fast-path object lock, stored at
/// [`fastpath_lock_key`]. Held from a successful prepare commit until the
/// owning request's certificate apply deletes it; never written or deleted
/// by anything else.
///
/// DR-0131 redefines this canonical version-1 layout in place to add
/// `locked_epoch`: this workspace is unreleased, so there is no v1/v2 split
/// and no obsolete layout preserved for compatibility.
pub const FASTPATH_LOCK_RECORD_TYPE: u16 = 0x641B;
/// Frame type for one sender/epoch nonce lock.
pub const FASTPATH_NONCE_LOCK_RECORD_TYPE: u16 = 0x6425;
/// Frame type for the singleton [`FastPathEpochRecord`] (DR-0131).
pub const FASTPATH_EPOCH_RECORD_TYPE: u16 = 0x6426;

/// One durable fast-path object lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathLockRecord {
    /// Original request id of the prepared record that owns this lock.
    pub request_id: [u8; 32],
    /// Exact object identity/version/digest observed and locked at prepare time.
    pub object: ObjectRef,
    /// [`FastPathEpochRecord::current_epoch`] as it stood at the moment of
    /// the same durable CAS commit that created this lock (DR-0131). Apply
    /// verifies the stamp against its certified/current epoch; Slice 1 does
    /// not reclaim with it. Retained so Slice 2's lazy stale-lock reclamation
    /// has the data it needs without a later migration.
    pub locked_epoch: Epoch,
}

/// Durable ownership of one exact sender nonce while a certificate is being
/// collected. Unlike the object locks, this prevents the ordinary direct
/// paid path from advancing beyond a prepared request before it is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathNonceLockRecord {
    /// Original request id that owns the lock.
    pub request_id: [u8; 32],
    /// Authenticated paid-intent sender.
    pub sender: [u8; 32],
    /// Epoch-scoped nonce domain.
    pub epoch: Epoch,
    /// Exact current nonce asserted at prepare and advanced at apply.
    pub nonce: u64,
}

/// Encodes Frame `0x641B/v1`.
pub fn encode_fastpath_lock_record(record: &FastPathLockRecord) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_LOCK_RECORD_TYPE, 1);
    frame.field_bytes(1, record.request_id.to_vec())?;
    frame.field_bytes(
        2,
        objects::encode_object_ref(&record.object)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid fastpath lock object"))?,
    )?;
    frame.field_u64(3, record.locked_epoch.get())?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x641B/v1`.
pub fn decode_fastpath_lock_record(bytes: &[u8]) -> Result<FastPathLockRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_LOCK_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("fastpath lock request id length"))?;
    let object: ObjectRef = objects::decode_object_ref(frame.required_field(2)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid fastpath lock object"))?;
    let locked_epoch: Epoch = Epoch::new(frame.required_u64(3)?);
    let record: FastPathLockRecord = FastPathLockRecord {
        request_id,
        object,
        locked_epoch,
    };
    if encode_fastpath_lock_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fastpath lock record",
        ));
    }
    Ok(record)
}

/// Per-`next_epoch` audit key for the DR-0132
/// [`crate::epoch_transition::FastPathEpochTransitionRecord`] (`0x6427`):
/// the exact verified certificate plus the activation write set's digest,
/// retained permanently so restart can re-walk and re-verify the whole
/// transition chain (C1). Unlike [`fastpath_epoch_record_key`] (the live
/// singleton), one row exists per completed transition and is never
/// overwritten.
pub fn fastpath_epoch_transition_key(
    chain: &ChainId,
    next_epoch: Epoch,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"transition/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&next_epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Singleton state key for the DR-0131 [`FastPathEpochRecord`]: the fenced
/// source of truth for the fast path's current epoch and active
/// validator-set identity, in place of scattered reads of the static
/// signed-genesis manifest. Scoped only by chain, matching the record's own
/// singleton nature -- unlike [`fastpath_validator_set_key`], it is never
/// keyed by epoch, since its entire purpose is to be found without already
/// knowing the current epoch.
pub fn fastpath_epoch_record_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"epoch/");
    key.extend(encode_chain_id(chain)?);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Frame `0x6426/v1`: the committed, CAS-fenced source of truth for the fast
/// path's current epoch and active validator-set identity (DR-0131). Created
/// atomically with genesis validator-set activation, then rewritten only by
/// an outgoing-set-certified DR-0132 epoch transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathEpochRecord {
    /// The current active epoch.
    pub current_epoch: Epoch,
    /// `ValidatorSet::digest()` of the active validator set, binding which
    /// set is active without embedding its contents.
    pub current_validator_set_digest: Digest32,
    /// The prior active epoch, for audit/transition bookkeeping. Absent at
    /// genesis; populated starting at Slice 2's first transition.
    pub previous_epoch: Option<Epoch>,
    /// The durable checkpoint/commit-sequence marker at which this record's
    /// current state became active, following the same
    /// `installed_at_checkpoint: u64` convention DR-0121's genesis install
    /// marker already uses.
    pub activated_at_checkpoint: u64,
}

/// Encodes Frame `0x6426/v1`.
pub fn encode_fastpath_epoch_record(
    record: &FastPathEpochRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_EPOCH_RECORD_TYPE, 1);
    frame.field_u64(1, record.current_epoch.get())?;
    frame.field_bytes(
        2,
        canonical_encoding::encode_digest32(&record.current_validator_set_digest)?,
    )?;
    if let Some(previous_epoch) = record.previous_epoch {
        frame.field_u64(3, previous_epoch.get())?;
    }
    frame.field_u64(4, record.activated_at_checkpoint)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x6426/v1`.
pub fn decode_fastpath_epoch_record(bytes: &[u8]) -> Result<FastPathEpochRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_EPOCH_RECORD_TYPE)?;
    frame.require_version(1)?;
    let current_epoch: Epoch = Epoch::new(frame.required_u64(1)?);
    let current_validator_set_digest: Digest32 =
        canonical_encoding::decode_digest32(frame.required_field(2)?)?;
    let (previous_epoch, allowed_fields): (Option<Epoch>, &[u16]) = match frame.field(3) {
        Some(_) => (Some(Epoch::new(frame.required_u64(3)?)), &[1, 2, 3, 4]),
        None => (None, &[1, 2, 4]),
    };
    frame.require_only_fields(allowed_fields)?;
    let activated_at_checkpoint: u64 = frame.required_u64(4)?;
    let record: FastPathEpochRecord = FastPathEpochRecord {
        current_epoch,
        current_validator_set_digest,
        previous_epoch,
        activated_at_checkpoint,
    };
    if encode_fastpath_epoch_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fastpath epoch record",
        ));
    }
    Ok(record)
}

/// Encodes frame `0x6425/v1`.
pub fn encode_fastpath_nonce_lock_record(
    record: &FastPathNonceLockRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_NONCE_LOCK_RECORD_TYPE, 1);
    frame.field_bytes(1, record.request_id.to_vec())?;
    frame.field_bytes(2, record.sender.to_vec())?;
    frame.field_u64(3, record.epoch.get())?;
    frame.field_u64(4, record.nonce)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6425/v1`.
pub fn decode_fastpath_nonce_lock_record(
    bytes: &[u8],
) -> Result<FastPathNonceLockRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_NONCE_LOCK_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("fastpath nonce-lock request id"))?;
    let sender: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("fastpath nonce-lock sender"))?;
    let record: FastPathNonceLockRecord = FastPathNonceLockRecord {
        request_id,
        sender,
        epoch: Epoch::new(frame.required_u64(3)?),
        nonce: frame.required_u64(4)?,
    };
    if encode_fastpath_nonce_lock_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fastpath nonce-lock record",
        ));
    }
    Ok(record)
}

/// Permanent, append-only key for one DR-0133 equivocation-evidence record
/// (`crate::equivocation::FastPathEquivocationEvidenceRecord`, `0x6429`):
/// the deterministic, normalized-identity `conflict_digest` (excluding
/// signatures, §6) makes the identical logical conflict, submitted any
/// number of times in any signature encoding, resolve to exactly this one
/// row. Never fenced against the live [`FastPathEpochRecord`]: evidence for
/// `evidence_epoch` remains addressable forever, including for a since-
/// retired validator or epoch.
pub fn fastpath_equivocation_evidence_key(
    chain: &ChainId,
    evidence_epoch: Epoch,
    validator: [u8; 32],
    conflict_digest: Digest32,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"equivocation/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&evidence_epoch.get().to_be_bytes());
    key.extend_from_slice(&validator);
    key.extend_from_slice(&conflict_digest.bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Permanent, append-only key for one DR-0137 unit 3
/// [`crate::bond_lifecycle::slash::EvidenceConsumptionRecord`] (`0x6432`):
/// keyed exactly like [`fastpath_equivocation_evidence_key`]'s own selector
/// (chain, evidence epoch, validator, normalized-identity `conflict_digest`),
/// but under a distinct prefix. This is the absence-fence
/// `handle_bond_slash` CAS-asserts before committing: presence proves the
/// exact evidence digest has already produced one forfeiture, so an exact
/// replay returns the original receipt (never reaches this fence) while a
/// different request over the same evidence fails closed here instead of
/// forfeiting a second time.
pub fn fastpath_evidence_consumed_key(
    chain: &ChainId,
    evidence_epoch: Epoch,
    validator: [u8; 32],
    conflict_digest: Digest32,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"evidence-consumed/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&evidence_epoch.get().to_be_bytes());
    key.extend_from_slice(&validator);
    key.extend_from_slice(&conflict_digest.bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Absence is asserted at commit, never treated as a permanent authorization.
/// Tombstones reject too: removing a sidecar cannot downgrade a public object.
pub(super) fn legacy_absence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    object_id: ObjectId,
) -> Result<StateReadAssertion, NodeCoreError> {
    let key: Vec<u8> = object_authority_key(object_id);
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
        return Err(NodeCoreError::ReservedStateAccess(key));
    }
    Ok(StateReadAssertion::new(key, observed.revision())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{
        DurableDomainStateStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };

    #[test]
    fn executable_publication_policy_matches_independent_node_vector() {
        let chain: ChainId = ChainId::new("local-vector").unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain,
            ProtocolVersion::new(3),
            vec![protocol_types::HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: protocol_types::HashSuite::genesis(),
            }],
        )
        .unwrap();
        let semantics: Digest32 =
            publication::local_executable_publication_semantics(&resolver, &context).unwrap();
        let policy: publication::LocalPublicationPolicy =
            publication::LocalPublicationPolicy::executable(context, semantics);
        let bytes: Vec<u8> = policy.encode().unwrap();
        assert_eq!(bytes.len(), 172);
        let digest: Digest32 = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, &bytes)
            .unwrap();
        let hex: String = digest
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hex,
            "4c92b0152c43b3ee7f8269472f0c47bbfc281473198f0617f6f53937303750f1"
        );
    }

    #[test]
    fn identity_keys_are_framed_and_namespaces_are_reserved() {
        let chain: ChainId = ChainId::new("local-instances").unwrap();
        let key: Vec<u8> = instance_record_key(&chain, &[1; 32], &[2; 32]).unwrap();
        assert_ne!(
            key,
            instance_record_key(&chain, &[2; 32], &[1; 32]).unwrap()
        );
        assert!(is_reserved(&key));
        let authority: Vec<u8> = object_authority_key(ObjectId::new([7; 32]));
        assert!(is_reserved(&authority));
        assert_eq!(&authority[authority.len() - 32..], &[7; 32]);
        let validator: ValidatorId = ValidatorId::new([8; 32]);
        let bond: Vec<u8> = fastpath_bond_record_key(&chain, &validator).unwrap();
        assert!(is_reserved(&bond));
        assert_eq!(&bond[bond.len() - 32..], validator.as_bytes());
        assert_ne!(
            bond,
            fastpath_bond_record_key(&chain, &ValidatorId::new([9; 32])).unwrap()
        );
        assert_ne!(
            bond,
            fastpath_bond_record_key(&ChainId::new("other-chain").unwrap(), &validator).unwrap()
        );
        for prefix in [INSTANCE_STATE_PREFIX, OBJECT_AUTHORITY_STATE_PREFIX] {
            let mut future: Vec<u8> = prefix.to_vec();
            future.extend_from_slice(b"v999/arbitrary");
            let plan: NodeStateAccessPlan = NodeStateAccessPlan::new(vec![
                NodeStateAccess::new(future.clone(), NodeStateAccessMode::ReadWrite).unwrap(),
            ])
            .unwrap();
            let layout: PersistenceLayout =
                PersistenceLayout::new(chain.clone(), ProtocolVersion::new(3));
            assert!(
                matches!(validate_sender_nonce_namespace(&plan, &layout), Err(NodeCoreError::ReservedStateAccess(actual)) if actual == future)
            );
        }
    }

    #[test]
    fn legacy_absence_is_cas_bound_and_live_or_tombstoned_authority_rejects() {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new(generation);
        let context: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([3; 16]).unwrap(),
        );
        let domain: AtomicityDomainId = AtomicityDomainId::new([5; 32]).unwrap();
        let id: ObjectId = ObjectId::new([7; 32]);
        let stale: StateReadAssertion = legacy_absence(&store, &context, domain, id).unwrap();
        let key: Vec<u8> = object_authority_key(id);
        for mutation in [StateMutation::Put(vec![1]), StateMutation::Delete] {
            let observed: VersionedStateValue =
                store.get_versioned_durable(&context, domain, &key).unwrap();
            let tx: AtomicStateTransaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(key.clone(), mutation).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                store.commit_durable(&context, tx),
                DurableCommitOutcome::Committed
            );
            assert!(matches!(
                legacy_absence(&store, &context, domain, id),
                Err(NodeCoreError::ReservedStateAccess(_))
            ));
        }
        let output_key: Vec<u8> = b"legacy-output".to_vec();
        let tx: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                stale,
                StateReadAssertion::new(output_key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(output_key.clone(), StateMutation::Put(vec![9])).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.commit_durable(&context, tx),
            DurableCommitOutcome::Rejected(_)
        ));
        assert!(
            store
                .get_versioned_durable(&context, domain, &output_key)
                .unwrap()
                .value()
                .is_none()
        );
    }

    #[test]
    fn execution_policy_key_for_profile_distinguishes_profiles_and_rejects_unknown() {
        let chain: ChainId = ChainId::new("local-policy-profiles").unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
        let other_context: PublicationContext =
            PublicationContext::new(chain, ProtocolVersion::new(3), Epoch::new(1)).unwrap();
        let key2: Vec<u8> = execution_policy_key_for_profile(&context, 2).unwrap();
        let key3: Vec<u8> = execution_policy_key_for_profile(&context, 3).unwrap();
        let key4: Vec<u8> = execution_policy_key_for_profile(&context, 4).unwrap();
        assert_ne!(key2, key3);
        assert_ne!(key3, key4);
        assert_ne!(key2, key4);
        assert_eq!(execution_policy_key(&context).unwrap(), key2);
        assert_ne!(
            key4,
            execution_policy_key_for_profile(&other_context, 4).unwrap()
        );
        for key in [&key2, &key3, &key4] {
            assert!(is_reserved(key));
        }
        assert!(matches!(
            execution_policy_key_for_profile(&context, 5),
            Err(NodeCoreError::PersistenceInvariant(_))
        ));
    }

    #[test]
    fn paid_fee_policy_key_is_context_bound_reserved_and_distinct_from_execution_keys() {
        let chain: ChainId = ChainId::new("local-paid-policy").unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
        let other_context: PublicationContext =
            PublicationContext::new(chain, ProtocolVersion::new(3), Epoch::new(1)).unwrap();
        let key: Vec<u8> = paid_fee_policy_key(&context).unwrap();
        assert_ne!(key, paid_fee_policy_key(&other_context).unwrap());
        assert!(is_reserved(&key));
        for profile in [2, 3, 4] {
            assert_ne!(
                key,
                execution_policy_key_for_profile(&context, profile).unwrap()
            );
        }
        let layout: PersistenceLayout =
            PersistenceLayout::new(context.chain_id().clone(), ProtocolVersion::new(3));
        let plan: NodeStateAccessPlan = NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(key.clone(), NodeStateAccessMode::ReadWrite).unwrap(),
        ])
        .unwrap();
        assert!(
            matches!(validate_sender_nonce_namespace(&plan, &layout), Err(NodeCoreError::ReservedStateAccess(actual)) if actual == key)
        );
    }

    #[test]
    fn fastpath_economics_policy_key_is_context_bound_reserved_and_distinct() {
        let chain: ChainId = ChainId::new("fastpath-economics-policy").unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
        let other_context: PublicationContext =
            PublicationContext::new(chain, ProtocolVersion::new(3), Epoch::new(1)).unwrap();
        let key: Vec<u8> = fastpath_economics_policy_key(&context).unwrap();
        assert_ne!(key, fastpath_economics_policy_key(&other_context).unwrap());
        assert_ne!(key, paid_fee_policy_key(&context).unwrap());
        assert_ne!(key, fastpath_validator_set_key(&context).unwrap());
        assert!(is_reserved(&key));
    }
}
