//! DR-0130 fast-path canonical durable records.
//!
//! [`FastPathPreparedRecord`], [`FastPathCertificateRecord`] and
//! [`FastPathSettlementRecord`] are stored under the reserved fast-path key
//! prefix (`crate::local_instance_state`); [`FastPathValidatorSetRecord`] is
//! installed atomically from the signed [`crate::genesis::GenesisManifest`]
//! in production. The
//! per-object lock record ([`crate::local_instance_state::FastPathLockRecord`])
//! lives alongside its key builder in `local_instance_state`, not here,
//! because [`crate::paid_execution::build_paid_admission`] -- shared by the
//! direct commit path -- reads it directly and must not depend on this
//! fast-path-only module.
use super::*;
use abi::package_types::ScopedTypeArg;
use bonds::{BondResourceId, decode_bond_resource_id, encode_bond_resource_id};
use execution::local_execution::{
    ObjectAuthority, decode_object_authority, encode_object_authority,
};

const FASTPATH_PREPARED_RECORD_TYPE: u16 = 0x641C;
const FASTPATH_CERTIFICATE_RECORD_TYPE: u16 = 0x641D;
const FASTPATH_SETTLEMENT_RECORD_TYPE: u16 = 0x641E;
const FASTPATH_VALIDATOR_SET_RECORD_TYPE: u16 = 0x641F;
const FASTPATH_OBJECT_REF_LIST_TYPE: u16 = 0x6420;
const FASTPATH_VALIDATOR_ENTRY_LIST_TYPE: u16 = 0x6422;
const FASTPATH_VALIDATOR_ENTRY_TYPE: u16 = 0x6423;
const FASTPATH_BOND_RECORD_TYPE: u16 = 0x642A;
const FASTPATH_BOND_STATE_TYPE: u16 = 0x642D;
const FASTPATH_BOND_TRANSITION_RECORD_TYPE: u16 = 0x6431;
const FASTPATH_BOND_TRANSITION_AUTHORIZATION_TYPE: u16 = 0x6433;
const FASTPATH_FEE_SHARE_TYPE: u16 = 0x6435;
const FASTPATH_FEE_SHARE_LIST_TYPE: u16 = 0x6436;
const ENCODING_VERSION: u16 = 1;

/// Bounds every nested fast-path record list. Locked-object and
/// certificate-signer lists are bounded by `MAX_FASTPATH_SIGNERS`; locked
/// objects are bounded by the per-request execution scope/object ceilings.
/// `MAX_FASTPATH_VALIDATORS` bounds the durable validator set itself.
const MAX_FASTPATH_LOCKED_OBJECTS: usize = 256;
/// Mirrors `validator_set::ValidatorSet`'s own private `MAX_VALIDATORS`
/// bound (10_000); [`validator_set::ValidatorSet::new`] independently
/// re-enforces it, so a looser bound here could not admit an oversized set.
const MAX_FASTPATH_SIGNERS: usize = 10_000;
const MAX_FASTPATH_VALIDATORS: usize = 10_000;

fn encode_item_list(
    type_id: u16,
    items: &[Vec<u8>],
    max_items: usize,
) -> Result<Vec<u8>, NodeCoreError> {
    if items.len() > max_items {
        return Err(NodeCoreError::PersistenceInvariant(
            "fast-path record list too large",
        ));
    }
    let mut list: CanonicalStruct = CanonicalStruct::new(type_id, ENCODING_VERSION);
    list.field_u32(1, items.len() as u32)?;
    for (index, item) in items.iter().enumerate() {
        let field_id: u16 = u16::try_from(2 + index)
            .map_err(|_| NodeCoreError::PersistenceInvariant("fast-path record list index"))?;
        list.field_bytes(field_id, item.clone())?;
    }
    Ok(list.finish()?)
}

fn decode_item_list(
    type_id: u16,
    bytes: &[u8],
    max_items: usize,
) -> Result<Vec<Vec<u8>>, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(type_id)?;
    frame.require_version(ENCODING_VERSION)?;
    let count: usize = frame.required_u32(1)? as usize;
    if count > max_items {
        return Err(NodeCoreError::PersistenceInvariant(
            "fast-path record list too large",
        ));
    }
    let mut allowed: Vec<u16> = vec![1];
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(count);
    for index in 0..count {
        let field_id: u16 = u16::try_from(2 + index)
            .map_err(|_| NodeCoreError::PersistenceInvariant("fast-path record list index"))?;
        allowed.push(field_id);
        items.push(frame.required_field(field_id)?.to_vec());
    }
    frame.require_only_fields(&allowed)?;
    Ok(items)
}

/// Frame `0x641C/v1`: the durable outcome of one successful fast-path
/// prepare commit, keyed by
/// [`local_instance_state::fastpath_prepared_record_key`]. Exact replay of
/// the same original request id and signed bytes returns this record's own
/// `vote` unchanged; a conflicting replay fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathPreparedRecord {
    /// Trusted chain/protocol-version/epoch context of the prepared intent.
    pub context: PublicationContext,
    /// Original signed intent's request id.
    pub request_id: [u8; 32],
    /// `paid_invocation_digest` of the signed intent: the `FastVote`/
    /// `FastCertificate` `tx_hash`.
    pub signed_intent_digest: Digest32,
    /// The full staged-commit commitment: the `FastVote`/`FastCertificate`
    /// `execution_effects_hash`.
    pub commitment: Digest32,
    /// Exact `consensus::encode_fast_vote` bytes this validator cast for
    /// `(signed_intent_digest, commitment)`. Returned unchanged on exact
    /// replay, never re-signed.
    pub vote: Vec<u8>,
    /// The fee source followed by every application input in signed access
    /// order, each at the exact version locked at prepare time.
    pub locked_objects: Vec<ObjectRef>,
    /// The exact sender nonce prepare reserved without advancing.
    pub pending_nonce: u64,
    /// The exact `created_checkpoint` prepare admitted and voted on. Durably
    /// bound here so `apply` re-derives the identical staged commitment
    /// regardless of how far checkpoint progress has moved by the time a
    /// certificate lands: `apply` uses this stored value rather than
    /// accepting one from its own caller.
    pub created_checkpoint: u64,
}

/// Encodes Frame `0x641C/v1`.
pub fn encode_fastpath_prepared_record(
    record: &FastPathPreparedRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut objects: Vec<Vec<u8>> = Vec::with_capacity(record.locked_objects.len());
    for object in &record.locked_objects {
        objects.push(
            objects::encode_object_ref(object)
                .map_err(|_| NodeCoreError::PersistenceInvariant("invalid locked object ref"))?,
        );
    }
    let objects_bytes: Vec<u8> = encode_item_list(
        FASTPATH_OBJECT_REF_LIST_TYPE,
        &objects,
        MAX_FASTPATH_LOCKED_OBJECTS,
    )?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_PREPARED_RECORD_TYPE, 1);
    frame.field_bytes(
        1,
        encode_publication_context(&record.context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid prepared record context"))?,
    )?;
    frame.field_bytes(2, record.request_id.to_vec())?;
    frame.field_bytes(3, encode_digest32(&record.signed_intent_digest)?)?;
    frame.field_bytes(4, encode_digest32(&record.commitment)?)?;
    frame.field_bytes(5, record.vote.clone())?;
    frame.field_bytes(6, objects_bytes)?;
    frame.field_u64(7, record.pending_nonce)?;
    frame.field_u64(8, record.created_checkpoint)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x641C/v1`.
pub fn decode_fastpath_prepared_record(
    bytes: &[u8],
) -> Result<FastPathPreparedRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_PREPARED_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid prepared record context"))?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("prepared record request id length"))?;
    let signed_intent_digest: Digest32 = decode_digest32(frame.required_field(3)?)?;
    let commitment: Digest32 = decode_digest32(frame.required_field(4)?)?;
    let vote: Vec<u8> = frame.required_field(5)?.to_vec();
    let object_items: Vec<Vec<u8>> = decode_item_list(
        FASTPATH_OBJECT_REF_LIST_TYPE,
        frame.required_field(6)?,
        MAX_FASTPATH_LOCKED_OBJECTS,
    )?;
    let mut locked_objects: Vec<ObjectRef> = Vec::with_capacity(object_items.len());
    for item in &object_items {
        locked_objects.push(
            objects::decode_object_ref(item)
                .map_err(|_| NodeCoreError::PersistenceInvariant("invalid locked object ref"))?,
        );
    }
    let pending_nonce: u64 = frame.required_u64(7)?;
    let created_checkpoint: u64 = frame.required_u64(8)?;
    let record: FastPathPreparedRecord = FastPathPreparedRecord {
        context,
        request_id,
        signed_intent_digest,
        commitment,
        vote,
        locked_objects,
        pending_nonce,
        created_checkpoint,
    };
    if encode_fastpath_prepared_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path prepared record",
        ));
    }
    Ok(record)
}

/// Frame `0x641D/v1`: the exact verified [`consensus::FastCertificate`]
/// bytes a successful apply committed for one original request id, a
/// permanent audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathCertificateRecord {
    /// Original signed intent's request id.
    pub request_id: [u8; 32],
    /// Exact `consensus::encode_fast_certificate` bytes verified at apply.
    pub certificate: Vec<u8>,
}

/// Encodes Frame `0x641D/v1`.
pub fn encode_fastpath_certificate_record(
    record: &FastPathCertificateRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_CERTIFICATE_RECORD_TYPE, 1);
    frame.field_bytes(1, record.request_id.to_vec())?;
    frame.field_bytes(2, record.certificate.clone())?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x641D/v1`.
pub fn decode_fastpath_certificate_record(
    bytes: &[u8],
) -> Result<FastPathCertificateRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_CERTIFICATE_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("certificate record request id"))?;
    let certificate: Vec<u8> = frame.required_field(2)?.to_vec();
    let record: FastPathCertificateRecord = FastPathCertificateRecord {
        request_id,
        certificate,
    };
    if encode_fastpath_certificate_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path certificate record",
        ));
    }
    Ok(record)
}

/// One deterministic active-validator entitlement carried inside the
/// bounded settlement row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathFeeShare {
    /// Ascending, unique active-validator identity.
    pub validator_id: ValidatorId,
    /// Exact share assigned by the quotient/remainder rule.
    pub amount: u64,
    /// Whether this share has already been finalized by a claim.
    pub claimed: bool,
}

/// Frame `0x641E/v1`: the authoritative bounded fee-escrow row committed by
/// successful certificate apply. This repository is unreleased, so the old
/// metadata-only shape was replaced in place rather than retaining a dead
/// compatibility decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathSettlementRecord {
    /// Exact certificate publication context.
    pub context: PublicationContext,
    /// Original signed intent's request id.
    pub request_id: [u8; 32],
    /// Escrow generation. Zero exactly for an uncharged outcome; one at the
    /// initial charged apply and advanced by each later claim.
    pub generation: u64,
    /// Exact generic resource identity, when charged.
    pub resource_id: Option<BondResourceId>,
    /// Exact fresh `FeeEscrow` output the charge minted, when charged.
    pub fee_output: Option<ObjectRef>,
    /// Epoch under whose object hash suite `fee_output` was minted.
    pub fee_output_epoch: Option<Epoch>,
    /// Exact total amount charged, when charged.
    pub total_amount: Option<u64>,
    /// Canonical ascending active-validator entitlements. Empty when uncharged.
    pub shares: Vec<FastPathFeeShare>,
}

/// Frame `0x642D/v1`: exact lifecycle state of one validator bond generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FastPathBondState {
    /// Bond is active and eligible for a future validator set.
    Active,
    /// Bond remains slashable until `unlock_epoch`, then may be released to
    /// the exact validator-authorized recipient.
    Unbonding {
        /// First epoch at which withdrawal may succeed.
        unlock_epoch: Epoch,
        /// Exact address that must receive the released object.
        recipient: [u8; 32],
    },
    /// Verified evidence consumed this generation and forfeited its value.
    Jailed {
        /// Canonical identity of the consumed evidence.
        evidence_digest: Digest32,
    },
    /// The last committed bond object has been released and cannot re-enter.
    Exited,
}

/// Encodes Frame `0x642D/v1`.
pub fn encode_fastpath_bond_state(state: &FastPathBondState) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_BOND_STATE_TYPE, 1);
    match state {
        FastPathBondState::Active => {
            frame.field_u16(1, 1)?;
        }
        FastPathBondState::Unbonding {
            unlock_epoch,
            recipient,
        } => {
            frame.field_u16(1, 2)?;
            frame.field_u64(2, unlock_epoch.get())?;
            frame.field_bytes(3, recipient.to_vec())?;
        }
        FastPathBondState::Jailed { evidence_digest } => {
            frame.field_u16(1, 3)?;
            frame.field_bytes(4, encode_digest32(evidence_digest)?)?;
        }
        FastPathBondState::Exited => {
            frame.field_u16(1, 4)?;
        }
    }
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x642D/v1`.
pub fn decode_fastpath_bond_state(bytes: &[u8]) -> Result<FastPathBondState, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_BOND_STATE_TYPE)?;
    frame.require_version(1)?;
    let state: FastPathBondState = match frame.required_u16(1)? {
        1 => {
            frame.require_only_fields(&[1])?;
            FastPathBondState::Active
        }
        2 => {
            frame.require_only_fields(&[1, 2, 3])?;
            let recipient: [u8; 32] = frame
                .required_field(3)?
                .try_into()
                .map_err(|_| NodeCoreError::PersistenceInvariant("bond recipient length"))?;
            FastPathBondState::Unbonding {
                unlock_epoch: Epoch::new(frame.required_u64(2)?),
                recipient,
            }
        }
        3 => {
            frame.require_only_fields(&[1, 4])?;
            FastPathBondState::Jailed {
                evidence_digest: decode_digest32(frame.required_field(4)?)?,
            }
        }
        4 => {
            frame.require_only_fields(&[1])?;
            FastPathBondState::Exited
        }
        _ => {
            return Err(NodeCoreError::PersistenceInvariant(
                "unknown fast-path bond state",
            ));
        }
    };
    if encode_fastpath_bond_state(&state)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path bond state",
        ));
    }
    Ok(state)
}

/// Frame `0x642A/v1`: one typed, positive authoritative bond lifecycle row.
/// It binds each transition to a public-contract custody object and a signed
/// economics-policy minimum; it grants no release or mutation authority by
/// itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathBondRecord {
    /// Exact publication context of the defining contract authority.
    pub context: PublicationContext,
    /// Validator named by the custody scope subject.
    pub validator_id: ValidatorId,
    /// Non-zero opaque nominal-type domain carrying the resource identity.
    pub resource_domain: u16,
    /// Exact custody scope resource and opaque nominal type value.
    pub resource: [u8; 32],
    /// Exact custody object version observed at commitment time. Once
    /// [`Self::state`] is [`FastPathBondState::Exited`] or
    /// [`FastPathBondState::Jailed`], this is a historical audit pointer to
    /// the last-known custody object only: the object itself has already
    /// been released or forfeited and is no longer custody-owned. Never read
    /// this field to compute live collateral; call [`Self::live_collateral`].
    pub custody_object: ObjectRef,
    /// The exact epoch at which [`Self::custody_object`]'s own digest was
    /// computed -- i.e. the committing epoch of whichever generation last
    /// actually minted a fresh object ref for this validator (genesis,
    /// `Deposit`, `Reactivate`, `Replace`, `Withdraw` or `Slash`). `Unbond`
    /// never touches the custody object and therefore carries this value
    /// forward unchanged from the previous row, even though
    /// [`Self::lifecycle_epoch`] itself advances to the `Unbond`'s own
    /// committing epoch. Restart (`genesis::verify_fastpath_bond_chain`)
    /// must hash a retained previous-object body at exactly this recorded
    /// epoch, never at [`Self::lifecycle_epoch`], or a hash-suite rotation
    /// that occurred while a bond sat `Unbonding` silently miscomputes the
    /// digest.
    pub custody_object_epoch: Epoch,
    /// Complete immutable public-contract authority for the custody object.
    /// Historical once [`Self::state`] is `Exited` or `Jailed`, exactly like
    /// [`Self::custody_object`].
    pub authority: ObjectAuthority,
    /// Positive scalar value decoded only through the signed executable ABI
    /// at the generation this row was committed. Once [`Self::state`] is
    /// `Exited` or `Jailed`, this is a historical record of the amount that
    /// was released or forfeited, not a live balance. Never read this field
    /// to compute live collateral; call [`Self::live_collateral`].
    pub amount: u64,
    /// Checkpoint of the atomic transition that committed this generation.
    pub committed_at_checkpoint: u64,
    /// Positive monotonically increasing lifecycle generation.
    pub generation: u64,
    /// Epoch in which this lifecycle generation was committed. Pure
    /// transition time: never overloaded to carry liability or object-mint
    /// provenance -- see [`Self::slashable_from_epoch`] and
    /// [`Self::custody_object_epoch`].
    pub lifecycle_epoch: Epoch,
    /// The earliest evidence epoch this generation's live collateral is
    /// liable for: [`slash::handle_bond_slash`] gates on
    /// `evidence_epoch >= slashable_from_epoch`, never on
    /// [`Self::lifecycle_epoch`]. Fresh collateral (`Deposit` from `Exited`,
    /// `Reactivate` from `Jailed`) sets this to the committing epoch plus
    /// one, since it can only ever join the *next* validator set and must
    /// never be liable for evidence at or before the epoch it was posted.
    /// `Replace` and `Unbond` preserve the exact value carried on the
    /// previous row unchanged (liability provenance survives a collateral
    /// swap or an unbonding request); `Withdraw` and `Slash` also preserve it
    /// unchanged, purely as historical audit data once the row is no longer
    /// live. The one genesis generation is liable from the genesis epoch
    /// itself. Distinct from [`Self::custody_object_epoch`], which tracks
    /// object digest provenance, not liability.
    pub slashable_from_epoch: Epoch,
    /// Positive policy minimum captured for this transition.
    pub required_minimum: u64,
    /// Exact lifecycle state for this generation.
    pub state: FastPathBondState,
    /// Committed validator authorization signature scheme. Installed once
    /// from the matching genesis validator entry (DR-0137) and copied
    /// unchanged by every later lifecycle transition; only [`SignatureSchemeId::Ed25519`]
    /// is accepted.
    pub authorization_scheme: SignatureSchemeId,
    /// Committed validator authorization verifying key: the exact canonical
    /// 32-byte Ed25519 key every [`crate::bond_lifecycle`] envelope for this
    /// validator must be signed by.
    pub authorization_key: [u8; 32],
}

impl FastPathBondRecord {
    /// The canonical, safe accessor for live collateral. Returns
    /// `Some((&self.custody_object, self.amount))` only while `self.state`
    /// is [`FastPathBondState::Active`] or [`FastPathBondState::Unbonding`]
    /// (still slashable, still custody-owned); returns `None` for
    /// [`FastPathBondState::Exited`] and [`FastPathBondState::Jailed`], whose
    /// `custody_object`/`amount` are historical audit fields only. Any code
    /// that sums or reports bonded stake should call this instead of reading
    /// [`Self::custody_object`]/[`Self::amount`] directly, so it does not
    /// silently double-count an exited or forfeited row. This is a
    /// discipline the type invites, not one Rust's field visibility
    /// mechanically enforces: [`Self::custody_object`]/[`Self::amount`]
    /// remain public fields a caller can still read directly.
    #[must_use]
    pub fn live_collateral(&self) -> Option<(&ObjectRef, u64)> {
        match self.state {
            FastPathBondState::Active | FastPathBondState::Unbonding { .. } => {
                Some((&self.custody_object, self.amount))
            }
            FastPathBondState::Exited | FastPathBondState::Jailed { .. } => None,
        }
    }
}

/// Encodes Frame `0x642A/v1`.
pub fn encode_fastpath_bond_record(record: &FastPathBondRecord) -> Result<Vec<u8>, NodeCoreError> {
    let resource_matches_type: bool = matches!(
        record.authority.ty.args(),
        [ScopedTypeArg::Opaque { domain, value }]
            if *domain == record.resource_domain && *value == record.resource
    );
    let lifecycle_valid: bool = match &record.state {
        FastPathBondState::Unbonding { unlock_epoch, .. } => {
            unlock_epoch.get() > record.lifecycle_epoch.get()
        }
        FastPathBondState::Active
        | FastPathBondState::Jailed { .. }
        | FastPathBondState::Exited => true,
    };
    // `slashable_from_epoch` may never exceed `lifecycle_epoch + 1`: every
    // producing operation either preserves a value inherited from a strictly
    // earlier (or equal) generation's `lifecycle_epoch`, or -- for fresh
    // collateral (`Deposit`/`Reactivate`) alone -- sets it to exactly
    // `lifecycle_epoch + 1`. A larger value could never have been produced
    // by any closed DR-0137 operation and is rejected as corrupt/forged
    // rather than silently accepted as an even-more-conservative floor.
    let slashable_from_valid: bool = record.slashable_from_epoch.get()
        >= record.context.epoch().get()
        && record.slashable_from_epoch.get() <= record.lifecycle_epoch.get().saturating_add(1);
    // `custody_object_epoch` names the exact epoch the live `custody_object`
    // digest was actually computed at, which can never postdate this row's
    // own commit time nor predate genesis.
    let custody_object_epoch_valid: bool = record.custody_object_epoch.get()
        >= record.context.epoch().get()
        && record.custody_object_epoch.get() <= record.lifecycle_epoch.get();
    if record.resource_domain == 0
        || record.amount == 0
        || record.generation == 0
        || record.lifecycle_epoch.get() < record.context.epoch().get()
        || record.required_minimum == 0
        || record.amount < record.required_minimum
        || record.authority.object_id != record.custody_object.id
        || record.authority.instance_context != record.context
        || !resource_matches_type
        || !lifecycle_valid
        || !slashable_from_valid
        || !custody_object_epoch_valid
        || record.authorization_scheme != SignatureSchemeId::Ed25519
        || Ed25519Verifier::from_verifying_key_bytes(&record.authorization_key).is_err()
    {
        return Err(NodeCoreError::PersistenceInvariant(
            "invalid fast-path bond record",
        ));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_BOND_RECORD_TYPE, 1);
    frame.field_bytes(
        1,
        encode_publication_context(&record.context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond context"))?,
    )?;
    frame.field_bytes(2, record.validator_id.as_bytes().to_vec())?;
    frame.field_u16(3, record.resource_domain)?;
    frame.field_bytes(4, record.resource.to_vec())?;
    frame.field_bytes(
        5,
        objects::encode_object_ref(&record.custody_object)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond object ref"))?,
    )?;
    frame.field_bytes(
        6,
        encode_object_authority(&record.authority)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond authority"))?,
    )?;
    frame.field_u64(7, record.amount)?;
    frame.field_u64(8, record.committed_at_checkpoint)?;
    frame.field_u64(9, record.generation)?;
    frame.field_u64(10, record.lifecycle_epoch.get())?;
    frame.field_u64(11, record.required_minimum)?;
    frame.field_bytes(12, encode_fastpath_bond_state(&record.state)?)?;
    frame.field_u16(13, record.authorization_scheme.as_u16())?;
    frame.field_bytes(14, record.authorization_key.to_vec())?;
    frame.field_u64(15, record.slashable_from_epoch.get())?;
    frame.field_u64(16, record.custody_object_epoch.get())?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x642A/v1`.
pub fn decode_fastpath_bond_record(bytes: &[u8]) -> Result<FastPathBondRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_BOND_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond context"))?;
    let validator_bytes: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("bond validator id length"))?;
    let resource: [u8; 32] = frame
        .required_field(4)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("bond resource length"))?;
    let custody_object: ObjectRef = objects::decode_object_ref(frame.required_field(5)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond object ref"))?;
    let authority: ObjectAuthority = decode_object_authority(frame.required_field(6)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond authority"))?;
    let authorization_scheme: SignatureSchemeId =
        SignatureSchemeId::try_from(frame.required_u16(13)?)
            .map_err(|_| NodeCoreError::PersistenceInvariant("bond authorization scheme"))?;
    let authorization_key: [u8; 32] = frame
        .required_field(14)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("bond authorization key length"))?;
    let record: FastPathBondRecord = FastPathBondRecord {
        context,
        validator_id: ValidatorId::new(validator_bytes),
        resource_domain: frame.required_u16(3)?,
        resource,
        custody_object,
        custody_object_epoch: Epoch::new(frame.required_u64(16)?),
        authority,
        amount: frame.required_u64(7)?,
        committed_at_checkpoint: frame.required_u64(8)?,
        generation: frame.required_u64(9)?,
        lifecycle_epoch: Epoch::new(frame.required_u64(10)?),
        slashable_from_epoch: Epoch::new(frame.required_u64(15)?),
        required_minimum: frame.required_u64(11)?,
        state: decode_fastpath_bond_state(frame.required_field(12)?)?,
        authorization_scheme,
        authorization_key,
    };
    if encode_fastpath_bond_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path bond record",
        ));
    }
    Ok(record)
}

/// Closed DR-0137 bond lifecycle operation tag, permanently recorded inside
/// [`FastPathBondTransitionRecord`] for audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastPathBondLifecycleOperation {
    /// `Exited -> Active`.
    Deposit,
    /// `Active -> Active`, atomic two-leg swap.
    Replace,
    /// `Active -> Unbonding`.
    Unbond,
    /// `Unbonding -> Exited`.
    Withdraw,
    /// `Jailed -> Active`, a fresh policy-compliant bond.
    Reactivate,
    /// `(Active | Unbonding) -> Jailed`, one-time verified-evidence
    /// forfeiture.
    Slash,
}

impl FastPathBondLifecycleOperation {
    pub(crate) const fn as_u16(self) -> u16 {
        match self {
            Self::Deposit => 1,
            Self::Replace => 2,
            Self::Unbond => 3,
            Self::Withdraw => 4,
            Self::Reactivate => 5,
            Self::Slash => 6,
        }
    }

    const fn decode(value: u16) -> Result<Self, NodeCoreError> {
        match value {
            1 => Ok(Self::Deposit),
            2 => Ok(Self::Replace),
            3 => Ok(Self::Unbond),
            4 => Ok(Self::Withdraw),
            5 => Ok(Self::Reactivate),
            6 => Ok(Self::Slash),
            _ => Err(NodeCoreError::PersistenceInvariant(
                "unknown fast-path bond lifecycle operation",
            )),
        }
    }

    /// True exactly for the one closed `(previous, resulting)` state pair
    /// this operation is allowed to produce: `Deposit` is
    /// `Exited -> Active`, `Replace` is `Active -> Active`, `Unbond` is
    /// `Active -> Unbonding`, `Withdraw` is `Unbonding -> Exited`,
    /// `Reactivate` is `Jailed -> Active`, `Slash` is
    /// `(Active | Unbonding) -> Jailed`. Shared by
    /// [`crate::bond_lifecycle`]'s own live admission and
    /// [`crate::genesis::verify_fastpath_bond_chain`]'s independent restart
    /// re-derivation, so both enforce the identical closed state machine.
    #[must_use]
    pub fn validates_transition(
        self,
        previous: &FastPathBondState,
        resulting: &FastPathBondState,
    ) -> bool {
        match self {
            Self::Deposit => {
                *previous == FastPathBondState::Exited
                    && matches!(resulting, FastPathBondState::Active)
            }
            Self::Replace => {
                matches!(previous, FastPathBondState::Active)
                    && matches!(resulting, FastPathBondState::Active)
            }
            Self::Unbond => {
                matches!(previous, FastPathBondState::Active)
                    && matches!(resulting, FastPathBondState::Unbonding { .. })
            }
            Self::Withdraw => {
                matches!(previous, FastPathBondState::Unbonding { .. })
                    && *resulting == FastPathBondState::Exited
            }
            Self::Reactivate => {
                matches!(previous, FastPathBondState::Jailed { .. })
                    && matches!(resulting, FastPathBondState::Active)
            }
            Self::Slash => {
                matches!(
                    previous,
                    FastPathBondState::Active | FastPathBondState::Unbonding { .. }
                ) && matches!(resulting, FastPathBondState::Jailed { .. })
            }
        }
    }
}

/// Maximum bytes of the exact canonical signed `bond_lifecycle` envelope
/// (`0x6430/v1`), DR-0133 evidence frame, or evidence-consumption leg a
/// [`BondTransitionAuthorization`] retains. Generous enough for a `Replace`
/// envelope's two embedded local-execution legs, and for class (b)'s
/// worst-case pair of `MAX_LOCKED_OBJECT_SET_ENTRIES`-sized preimages.
pub const MAX_BOND_TRANSITION_ENVELOPE_BYTES: usize = 1_500_000;
/// Maximum bytes of one exact canonical [`Object`] `BondTransitionAuthorization::ConsumedEvidence`
/// retains (either side of the forfeiture: the previous `BondCollateral`
/// object or the resulting `ForfeitedCollateral` object) -- the durable
/// object-body limit plus room for the fixed identity/owner/type fields.
pub const MAX_BOND_TRANSITION_OBJECT_BYTES: usize =
    crate::MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4_096;
/// Maximum bytes of the exact canonical resulting [`FastPathBondRecord`]
/// (`0x642A/v1`) a [`FastPathBondTransitionRecord`] retains.
pub const MAX_BOND_TRANSITION_ROW_BYTES: usize = 64 * 1024;
/// Maximum canonical bytes of one encoded [`BondTransitionAuthorization`]
/// (`0x6433/v1`): the sum of every per-field bound above, generous enough
/// for either a `Replace` envelope's two embedded legs, or a DR-0133
/// evidence frame plus one forfeiture leg plus the retained previous/
/// resulting object pair.
pub const MAX_BOND_TRANSITION_AUTHORIZATION_BYTES: usize =
    2 * MAX_BOND_TRANSITION_ENVELOPE_BYTES + 2 * MAX_BOND_TRANSITION_OBJECT_BYTES;

const BOND_TRANSITION_AUTHORIZATION_TAG_VALIDATOR: u16 = 1;
const BOND_TRANSITION_AUTHORIZATION_TAG_EVIDENCE: u16 = 2;

/// Frame `0x6433/v1`: the closed DR-0137 unit 3 authority that produced one
/// bond transition, retained in full inside
/// [`FastPathBondTransitionRecord::authorization`] so restart independently
/// re-verifies it from nothing but the stored row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BondTransitionAuthorization {
    /// A validator-signed lifecycle transition: `Deposit`, `Replace`,
    /// `Unbond`, `Withdraw` or `Reactivate`.
    ValidatorEnvelope {
        /// Exact canonical `SignedBondLifecycleIntent 0x6430/v1` bytes.
        signed_envelope: Vec<u8>,
    },
    /// A one-time evidence-driven forfeiture: `Slash`.
    ConsumedEvidence {
        /// Exact encoded `0xD00D`/`0xD00E`/`0xD00F` DR-0133 evidence frame
        /// this transition consumed.
        evidence_bytes: Vec<u8>,
        /// Evidence epoch the consumed evidence claims.
        evidence_epoch: Epoch,
        /// Normalized-identity `conflict_digest` of the consumed evidence
        /// row (`crate::equivocation::fastpath_equivocation_evidence_key`'s
        /// own selector).
        evidence_digest: Digest32,
        /// Exact signed local-execution leg that ran the forfeiture
        /// transfer entrypoint under the `Forfeit` protocol-custody
        /// direction.
        forfeiture_leg: Vec<u8>,
        /// Exact canonical `0x4005` [`Object`] bytes of the custody object as it stood
        /// immediately before this forfeiture (the live snapshot
        /// `handle_bond_slash` read), owned by `BondCollateral`. Retained so
        /// restart can independently re-derive its `ObjectRef` digest and
        /// cross-check it against `previous_row.custody_object`, rather than
        /// trusting the resulting row's fields alone.
        previous_object: Vec<u8>,
        /// Exact canonical `0x4005` [`Object`] bytes of the same object immediately
        /// after this forfeiture, owned by `ForfeitedCollateral`: identical
        /// identity/version+1/type/schema/body to `previous_object` except
        /// the owner. Retained so restart can independently re-derive its
        /// `ObjectRef` digest and cross-check it against
        /// `resulting_row.custody_object`.
        resulting_object: Vec<u8>,
    },
}

/// Encodes Frame `0x6433/v1`.
pub fn encode_bond_transition_authorization(
    authorization: &BondTransitionAuthorization,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_BOND_TRANSITION_AUTHORIZATION_TYPE, 1);
    match authorization {
        BondTransitionAuthorization::ValidatorEnvelope { signed_envelope } => {
            if signed_envelope.len() > MAX_BOND_TRANSITION_ENVELOPE_BYTES {
                return Err(NodeCoreError::PersistenceInvariant(
                    "invalid bond transition authorization",
                ));
            }
            frame.field_u16(1, BOND_TRANSITION_AUTHORIZATION_TAG_VALIDATOR)?;
            frame.field_bytes(2, signed_envelope.clone())?;
        }
        BondTransitionAuthorization::ConsumedEvidence {
            evidence_bytes,
            evidence_epoch,
            evidence_digest,
            forfeiture_leg,
            previous_object,
            resulting_object,
        } => {
            if evidence_bytes.len() > MAX_BOND_TRANSITION_ENVELOPE_BYTES
                || forfeiture_leg.len() > MAX_BOND_TRANSITION_ENVELOPE_BYTES
                || previous_object.len() > MAX_BOND_TRANSITION_OBJECT_BYTES
                || resulting_object.len() > MAX_BOND_TRANSITION_OBJECT_BYTES
            {
                return Err(NodeCoreError::PersistenceInvariant(
                    "invalid bond transition authorization",
                ));
            }
            frame.field_u16(1, BOND_TRANSITION_AUTHORIZATION_TAG_EVIDENCE)?;
            frame.field_bytes(3, evidence_bytes.clone())?;
            frame.field_u64(4, evidence_epoch.get())?;
            frame.field_bytes(5, encode_digest32(evidence_digest)?)?;
            frame.field_bytes(6, forfeiture_leg.clone())?;
            frame.field_bytes(7, previous_object.clone())?;
            frame.field_bytes(8, resulting_object.clone())?;
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_BOND_TRANSITION_AUTHORIZATION_BYTES {
        return Err(NodeCoreError::PersistenceInvariant(
            "invalid bond transition authorization",
        ));
    }
    Ok(bytes)
}

/// Strictly decodes Frame `0x6433/v1`.
pub fn decode_bond_transition_authorization(
    bytes: &[u8],
) -> Result<BondTransitionAuthorization, NodeCoreError> {
    if bytes.len() > MAX_BOND_TRANSITION_AUTHORIZATION_BYTES {
        return Err(NodeCoreError::PersistenceInvariant(
            "invalid bond transition authorization",
        ));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_BOND_TRANSITION_AUTHORIZATION_TYPE)?;
    frame.require_version(1)?;
    let authorization: BondTransitionAuthorization = match frame.required_u16(1)? {
        BOND_TRANSITION_AUTHORIZATION_TAG_VALIDATOR => {
            frame.require_only_fields(&[1, 2])?;
            let signed_envelope: Vec<u8> = frame.required_field(2)?.to_vec();
            if signed_envelope.len() > MAX_BOND_TRANSITION_ENVELOPE_BYTES {
                return Err(NodeCoreError::PersistenceInvariant(
                    "invalid bond transition authorization",
                ));
            }
            BondTransitionAuthorization::ValidatorEnvelope { signed_envelope }
        }
        BOND_TRANSITION_AUTHORIZATION_TAG_EVIDENCE => {
            frame.require_only_fields(&[1, 3, 4, 5, 6, 7, 8])?;
            let evidence_bytes: Vec<u8> = frame.required_field(3)?.to_vec();
            let forfeiture_leg: Vec<u8> = frame.required_field(6)?.to_vec();
            let previous_object: Vec<u8> = frame.required_field(7)?.to_vec();
            let resulting_object: Vec<u8> = frame.required_field(8)?.to_vec();
            if evidence_bytes.len() > MAX_BOND_TRANSITION_ENVELOPE_BYTES
                || forfeiture_leg.len() > MAX_BOND_TRANSITION_ENVELOPE_BYTES
                || previous_object.len() > MAX_BOND_TRANSITION_OBJECT_BYTES
                || resulting_object.len() > MAX_BOND_TRANSITION_OBJECT_BYTES
            {
                return Err(NodeCoreError::PersistenceInvariant(
                    "invalid bond transition authorization",
                ));
            }
            BondTransitionAuthorization::ConsumedEvidence {
                evidence_bytes,
                evidence_epoch: Epoch::new(frame.required_u64(4)?),
                evidence_digest: decode_digest32(frame.required_field(5)?)?,
                forfeiture_leg,
                previous_object,
                resulting_object,
            }
        }
        _ => {
            return Err(NodeCoreError::PersistenceInvariant(
                "unknown bond transition authorization",
            ));
        }
    };
    if encode_bond_transition_authorization(&authorization)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical bond transition authorization",
        ));
    }
    Ok(authorization)
}

/// Frame `0x6431/v1`: one permanent audit row binding a validator's bond
/// generation transition to the exact canonical bytes that produced it.
/// Keyed by validator and the *new* (post-transition) generation
/// ([`local_instance_state::fastpath_bond_transition_key`]). Generation 1 has
/// no transition record: it is re-derived byte-exactly from the signed
/// genesis manifest. Restart re-verifies every later generation by walking
/// this chain from generation 1 (see `genesis::verify_fastpath_bond_chain`),
/// which needs nothing beyond [`Self::authorization`] and
/// [`Self::resulting_row`]: both are retained in full (not merely digested),
/// so restart independently re-decodes, re-hashes and re-verifies the
/// authorizing signature(s)/evidence and every bound field rather than
/// trusting any redundant summary column. [`Self::context`],
/// [`Self::previous_row_digest`], [`Self::current_row_digest`],
/// [`Self::operation`] and [`Self::committed_at_checkpoint`] are redundant,
/// informational copies of data already inside
/// [`Self::authorization`]/[`Self::resulting_row`]; restart cross-checks them
/// against the decoded authorization/row rather than trusting them on their
/// own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathBondTransitionRecord {
    /// Exact signing [`PublicationContext`] of this transition -- never an
    /// ambient or genesis-pinned context.
    pub context: PublicationContext,
    /// Validator this transition belongs to.
    pub validator_id: ValidatorId,
    /// Post-transition generation (matches the current [`FastPathBondRecord::generation`]).
    pub generation: u64,
    /// Canonical digest of the exact previous generation's [`FastPathBondRecord`] bytes.
    pub previous_row_digest: Digest32,
    /// Canonical digest of the exact resulting [`FastPathBondRecord`] bytes.
    pub current_row_digest: Digest32,
    /// Closed operation that produced this transition.
    pub operation: FastPathBondLifecycleOperation,
    /// Checkpoint of the atomic commit that produced this generation.
    pub committed_at_checkpoint: u64,
    /// Exact encoded [`BondTransitionAuthorization`] `0x6433/v1` bytes that
    /// authorized this transition, retained in full so it is independently
    /// re-verifiable at restart from nothing but this record.
    pub authorization: BondTransitionAuthorization,
    /// Exact canonical [`FastPathBondRecord`] `0x642A/v1` bytes this
    /// transition produced.
    pub resulting_row: Vec<u8>,
}

/// Encodes Frame `0x6431/v1`.
pub fn encode_fastpath_bond_transition_record(
    record: &FastPathBondTransitionRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    if record.generation == 0 || record.resulting_row.len() > MAX_BOND_TRANSITION_ROW_BYTES {
        return Err(NodeCoreError::PersistenceInvariant(
            "invalid fast-path bond transition record",
        ));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_BOND_TRANSITION_RECORD_TYPE, 1);
    frame.field_bytes(
        1,
        encode_publication_context(&record.context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond transition context"))?,
    )?;
    frame.field_bytes(2, record.validator_id.as_bytes().to_vec())?;
    frame.field_u64(3, record.generation)?;
    frame.field_bytes(4, encode_digest32(&record.previous_row_digest)?)?;
    frame.field_bytes(5, encode_digest32(&record.current_row_digest)?)?;
    frame.field_u16(6, record.operation.as_u16())?;
    frame.field_u64(7, record.committed_at_checkpoint)?;
    frame.field_bytes(
        8,
        encode_bond_transition_authorization(&record.authorization)?,
    )?;
    frame.field_bytes(9, record.resulting_row.clone())?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x6431/v1`.
pub fn decode_fastpath_bond_transition_record(
    bytes: &[u8],
) -> Result<FastPathBondTransitionRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_BOND_TRANSITION_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid bond transition context"))?;
    let validator_bytes: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("bond transition validator id length"))?;
    let authorization: BondTransitionAuthorization =
        decode_bond_transition_authorization(frame.required_field(8)?)?;
    let resulting_row: Vec<u8> = frame.required_field(9)?.to_vec();
    if resulting_row.len() > MAX_BOND_TRANSITION_ROW_BYTES {
        return Err(NodeCoreError::PersistenceInvariant(
            "invalid fast-path bond transition record",
        ));
    }
    let record: FastPathBondTransitionRecord = FastPathBondTransitionRecord {
        context,
        validator_id: ValidatorId::new(validator_bytes),
        generation: frame.required_u64(3)?,
        previous_row_digest: decode_digest32(frame.required_field(4)?)?,
        current_row_digest: decode_digest32(frame.required_field(5)?)?,
        operation: FastPathBondLifecycleOperation::decode(frame.required_u16(6)?)?,
        committed_at_checkpoint: frame.required_u64(7)?,
        authorization,
        resulting_row,
    };
    if record.generation == 0 || encode_fastpath_bond_transition_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path bond transition record",
        ));
    }
    Ok(record)
}

fn encode_fastpath_fee_share(share: &FastPathFeeShare) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_FEE_SHARE_TYPE, 1);
    frame.field_bytes(1, share.validator_id.as_bytes().to_vec())?;
    frame.field_u64(2, share.amount)?;
    frame.field_u16(3, u16::from(share.claimed))?;
    Ok(frame.finish()?)
}

fn decode_fastpath_fee_share(bytes: &[u8]) -> Result<FastPathFeeShare, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_FEE_SHARE_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let validator: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("fee share validator length"))?;
    let claimed: bool = match frame.required_u16(3)? {
        0 => false,
        1 => true,
        _ => {
            return Err(NodeCoreError::PersistenceInvariant(
                "fee share claimed flag",
            ));
        }
    };
    let share: FastPathFeeShare = FastPathFeeShare {
        validator_id: ValidatorId::new(validator),
        amount: frame.required_u64(2)?,
        claimed,
    };
    if encode_fastpath_fee_share(&share)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path fee share",
        ));
    }
    Ok(share)
}

fn validate_fastpath_settlement_record(
    record: &FastPathSettlementRecord,
) -> Result<(), NodeCoreError> {
    let charged: bool = record.fee_output.is_some();
    if record.resource_id.is_some() != charged
        || record.fee_output_epoch.is_some() != charged
        || record.total_amount.is_some() != charged
    {
        return Err(NodeCoreError::PersistenceInvariant(
            "fast-path settlement charge fields presence mismatch",
        ));
    }
    if !charged {
        if record.generation != 0 || !record.shares.is_empty() {
            return Err(NodeCoreError::PersistenceInvariant(
                "uncharged fast-path settlement state",
            ));
        }
        return Ok(());
    }
    if record.generation == 0 || record.shares.is_empty() {
        return Err(NodeCoreError::PersistenceInvariant(
            "charged fast-path settlement state",
        ));
    }
    let total_amount: u64 = record
        .total_amount
        .ok_or(NodeCoreError::PersistenceInvariant(
            "settlement total absent",
        ))?;
    if total_amount == 0 {
        return Err(NodeCoreError::PersistenceInvariant(
            "charged fast-path settlement zero total",
        ));
    }
    let mut previous: Option<ValidatorId> = None;
    let mut sum: u64 = 0;
    let mut claimed_count: u64 = 0;
    for share in &record.shares {
        if previous.is_some_and(|id: ValidatorId| id >= share.validator_id) {
            return Err(NodeCoreError::PersistenceInvariant(
                "fee shares must be strictly ordered",
            ));
        }
        previous = Some(share.validator_id);
        sum = sum
            .checked_add(share.amount)
            .ok_or(NodeCoreError::PersistenceInvariant(
                "fee share sum overflow",
            ))?;
        claimed_count = claimed_count.checked_add(u64::from(share.claimed)).ok_or(
            NodeCoreError::PersistenceInvariant("fee share claimed count overflow"),
        )?;
    }
    if sum != total_amount {
        return Err(NodeCoreError::PersistenceInvariant(
            "fee shares do not conserve settlement total",
        ));
    }
    let expected_generation: u64 =
        claimed_count
            .checked_add(1)
            .ok_or(NodeCoreError::PersistenceInvariant(
                "fee share generation overflow",
            ))?;
    if record.generation != expected_generation {
        return Err(NodeCoreError::PersistenceInvariant(
            "fee share generation mismatch",
        ));
    }
    Ok(())
}

/// Encodes Frame `0x641E/v1`.
pub fn encode_fastpath_settlement_record(
    record: &FastPathSettlementRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    validate_fastpath_settlement_record(record)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_SETTLEMENT_RECORD_TYPE, 1);
    frame.field_bytes(
        1,
        encode_publication_context(&record.context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("invalid settlement context"))?,
    )?;
    frame.field_bytes(2, record.request_id.to_vec())?;
    frame.field_u64(3, record.generation)?;
    if let (Some(resource_id), Some(fee_output), Some(fee_output_epoch), Some(total_amount)) = (
        record.resource_id,
        &record.fee_output,
        record.fee_output_epoch,
        record.total_amount,
    ) {
        frame.field_bytes(
            4,
            encode_bond_resource_id(resource_id)
                .map_err(|_| NodeCoreError::PersistenceInvariant("invalid fee resource id"))?,
        )?;
        frame.field_bytes(
            5,
            objects::encode_object_ref(fee_output).map_err(|_| {
                NodeCoreError::PersistenceInvariant("invalid settlement fee output")
            })?,
        )?;
        frame.field_u64(6, fee_output_epoch.get())?;
        frame.field_u64(7, total_amount)?;
        let share_items: Vec<Vec<u8>> = record
            .shares
            .iter()
            .map(encode_fastpath_fee_share)
            .collect::<Result<_, _>>()?;
        frame.field_bytes(
            8,
            encode_item_list(
                FASTPATH_FEE_SHARE_LIST_TYPE,
                &share_items,
                MAX_FASTPATH_SIGNERS,
            )?,
        )?;
    }
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x641E/v1`.
pub fn decode_fastpath_settlement_record(
    bytes: &[u8],
) -> Result<FastPathSettlementRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_SETTLEMENT_RECORD_TYPE)?;
    frame.require_version(1)?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid settlement context"))?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("settlement record request id"))?;
    let generation: u64 = frame.required_u64(3)?;
    let (resource_id, fee_output, fee_output_epoch, total_amount, shares) =
        if frame.field(4).is_some() {
            frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
            let share_items: Vec<Vec<u8>> = decode_item_list(
                FASTPATH_FEE_SHARE_LIST_TYPE,
                frame.required_field(8)?,
                MAX_FASTPATH_SIGNERS,
            )?;
            let shares: Vec<FastPathFeeShare> = share_items
                .iter()
                .map(|item| decode_fastpath_fee_share(item))
                .collect::<Result<_, _>>()?;
            (
                Some(
                    decode_bond_resource_id(frame.required_field(4)?).map_err(|_| {
                        NodeCoreError::PersistenceInvariant("invalid fee resource id")
                    })?,
                ),
                Some(
                    objects::decode_object_ref(frame.required_field(5)?).map_err(|_| {
                        NodeCoreError::PersistenceInvariant("invalid settlement fee output")
                    })?,
                ),
                Some(Epoch::new(frame.required_u64(6)?)),
                Some(frame.required_u64(7)?),
                shares,
            )
        } else {
            frame.require_only_fields(&[1, 2, 3])?;
            (None, None, None, None, Vec::new())
        };
    let record: FastPathSettlementRecord = FastPathSettlementRecord {
        context,
        request_id,
        generation,
        resource_id,
        fee_output,
        fee_output_epoch,
        total_amount,
        shares,
    };
    validate_fastpath_settlement_record(&record)?;
    if encode_fastpath_settlement_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path settlement record",
        ));
    }
    Ok(record)
}

/// One durable validator set member, mirroring
/// [`validator_set::ValidatorInfo`] but with its own frame identity since
/// `validator_set` provides no decode function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathValidatorEntry {
    pub id: ValidatorId,
    pub voting_power: u64,
    pub signature_scheme: SignatureSchemeId,
    pub public_key: Vec<u8>,
}

fn encode_validator_entry(entry: &FastPathValidatorEntry) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_VALIDATOR_ENTRY_TYPE, 1);
    frame.field_bytes(1, entry.id.as_bytes().to_vec())?;
    frame.field_u64(2, entry.voting_power)?;
    frame.field_u16(3, entry.signature_scheme.as_u16())?;
    frame.field_bytes(4, entry.public_key.clone())?;
    Ok(frame.finish()?)
}

fn decode_validator_entry(bytes: &[u8]) -> Result<FastPathValidatorEntry, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_VALIDATOR_ENTRY_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let id_bytes: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("validator entry id length"))?;
    let signature_scheme: SignatureSchemeId =
        SignatureSchemeId::try_from(frame.required_u16(3)?)
            .map_err(|_| NodeCoreError::PersistenceInvariant("validator entry signature scheme"))?;
    let entry: FastPathValidatorEntry = FastPathValidatorEntry {
        id: ValidatorId::new(id_bytes),
        voting_power: frame.required_u64(2)?,
        signature_scheme,
        public_key: frame.required_field(4)?.to_vec(),
    };
    if encode_validator_entry(&entry)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path validator entry",
        ));
    }
    Ok(entry)
}

/// Frame `0x641F/v1`: the durable, epoch-scoped static validator set a
/// [`consensus::FastPathCertifier`] is bound to. Production installation is
/// part of the signed [`crate::genesis::GenesisManifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathValidatorSetRecord {
    pub context: PublicationContext,
    pub validators: Vec<FastPathValidatorEntry>,
}

/// Encodes Frame `0x641F/v1`.
pub fn encode_fastpath_validator_set_record(
    record: &FastPathValidatorSetRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut entries: Vec<Vec<u8>> = Vec::with_capacity(record.validators.len());
    for validator in &record.validators {
        entries.push(encode_validator_entry(validator)?);
    }
    let entries_bytes: Vec<u8> = encode_item_list(
        FASTPATH_VALIDATOR_ENTRY_LIST_TYPE,
        &entries,
        MAX_FASTPATH_VALIDATORS,
    )?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_VALIDATOR_SET_RECORD_TYPE, 1);
    frame.field_bytes(
        1,
        encode_publication_context(&record.context).map_err(|_| {
            NodeCoreError::PersistenceInvariant("invalid validator set record context")
        })?,
    )?;
    frame.field_bytes(2, entries_bytes)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x641F/v1`.
pub fn decode_fastpath_validator_set_record(
    bytes: &[u8],
) -> Result<FastPathValidatorSetRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_VALIDATOR_SET_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid validator set record context"))?;
    let entry_items: Vec<Vec<u8>> = decode_item_list(
        FASTPATH_VALIDATOR_ENTRY_LIST_TYPE,
        frame.required_field(2)?,
        MAX_FASTPATH_VALIDATORS,
    )?;
    let mut validators: Vec<FastPathValidatorEntry> = Vec::with_capacity(entry_items.len());
    for item in &entry_items {
        validators.push(decode_validator_entry(item)?);
    }
    let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context,
        validators,
    };
    if encode_fastpath_validator_set_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path validator set record",
        ));
    }
    Ok(record)
}
