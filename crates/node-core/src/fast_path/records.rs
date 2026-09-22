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
use execution::local_execution::{
    ObjectAuthority, decode_object_authority, encode_object_authority,
};

const FASTPATH_PREPARED_RECORD_TYPE: u16 = 0x641C;
const FASTPATH_CERTIFICATE_RECORD_TYPE: u16 = 0x641D;
const FASTPATH_SETTLEMENT_RECORD_TYPE: u16 = 0x641E;
const FASTPATH_VALIDATOR_SET_RECORD_TYPE: u16 = 0x641F;
const FASTPATH_OBJECT_REF_LIST_TYPE: u16 = 0x6420;
const FASTPATH_ID_LIST_TYPE: u16 = 0x6421;
const FASTPATH_VALIDATOR_ENTRY_LIST_TYPE: u16 = 0x6422;
const FASTPATH_VALIDATOR_ENTRY_TYPE: u16 = 0x6423;
const FASTPATH_BOND_RECORD_TYPE: u16 = 0x642A;
const FASTPATH_BOND_STATE_TYPE: u16 = 0x642D;
const ENCODING_VERSION: u16 = 1;

/// Bounds every nested fast-path record list. Locked-object and
/// certificate-signer lists are bounded by the same per-request execution
/// scope/object ceilings the rest of paid admission already enforces;
/// `MAX_VALIDATORS` bounds the durable validator set itself.
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

/// Frame `0x641E/v1`: settlement metadata a successful apply commits
/// alongside the final receipt, for later (not-yet-implemented) Phase 3 fee
/// distribution to certificate signers. Fields 2/3 are present exactly when
/// the applied outcome charged a fee (`Success` or `ApplicationFailed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathSettlementRecord {
    /// Original signed intent's request id.
    pub request_id: [u8; 32],
    /// Exact fresh fee output the charge minted, when charged.
    pub fee_output: Option<ObjectRef>,
    /// Exact actual amount charged, when charged.
    pub actual_amount: Option<u64>,
    /// Canonical ascending-`ValidatorId` order of the certificate's signers.
    pub signer_ids: Vec<ValidatorId>,
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
    /// Exact custody object version observed at commitment time.
    pub custody_object: ObjectRef,
    /// Complete immutable public-contract authority for the custody object.
    pub authority: ObjectAuthority,
    /// Positive scalar value decoded only through the signed executable ABI.
    pub amount: u64,
    /// Checkpoint of the atomic transition that committed this generation.
    pub committed_at_checkpoint: u64,
    /// Positive monotonically increasing lifecycle generation.
    pub generation: u64,
    /// Epoch in which this lifecycle generation was committed.
    pub lifecycle_epoch: Epoch,
    /// Positive policy minimum captured for this transition.
    pub required_minimum: u64,
    /// Exact lifecycle state for this generation.
    pub state: FastPathBondState,
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
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x642A/v1`.
pub fn decode_fastpath_bond_record(bytes: &[u8]) -> Result<FastPathBondRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_BOND_RECORD_TYPE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])?;
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
    let record: FastPathBondRecord = FastPathBondRecord {
        context,
        validator_id: ValidatorId::new(validator_bytes),
        resource_domain: frame.required_u16(3)?,
        resource,
        custody_object,
        authority,
        amount: frame.required_u64(7)?,
        committed_at_checkpoint: frame.required_u64(8)?,
        generation: frame.required_u64(9)?,
        lifecycle_epoch: Epoch::new(frame.required_u64(10)?),
        required_minimum: frame.required_u64(11)?,
        state: decode_fastpath_bond_state(frame.required_field(12)?)?,
    };
    if encode_fastpath_bond_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical fast-path bond record",
        ));
    }
    Ok(record)
}

/// Encodes Frame `0x641E/v1`.
pub fn encode_fastpath_settlement_record(
    record: &FastPathSettlementRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    if record.fee_output.is_some() != record.actual_amount.is_some() {
        return Err(NodeCoreError::PersistenceInvariant(
            "fast-path settlement charge fields presence mismatch",
        ));
    }
    let signer_items: Vec<Vec<u8>> = record
        .signer_ids
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect();
    let signers_bytes: Vec<u8> =
        encode_item_list(FASTPATH_ID_LIST_TYPE, &signer_items, MAX_FASTPATH_SIGNERS)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(FASTPATH_SETTLEMENT_RECORD_TYPE, 1);
    frame.field_bytes(1, record.request_id.to_vec())?;
    if let (Some(fee_output), Some(actual_amount)) = (&record.fee_output, record.actual_amount) {
        frame.field_bytes(
            2,
            objects::encode_object_ref(fee_output).map_err(|_| {
                NodeCoreError::PersistenceInvariant("invalid settlement fee output")
            })?,
        )?;
        frame.field_u64(3, actual_amount)?;
    }
    frame.field_bytes(4, signers_bytes)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x641E/v1`.
pub fn decode_fastpath_settlement_record(
    bytes: &[u8],
) -> Result<FastPathSettlementRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_SETTLEMENT_RECORD_TYPE)?;
    frame.require_version(1)?;
    let request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("settlement record request id"))?;
    let (fee_output, actual_amount) = match (frame.field(2), frame.field(3)) {
        (Some(fee_output_bytes), Some(_)) => {
            frame.require_only_fields(&[1, 2, 3, 4])?;
            (
                Some(objects::decode_object_ref(fee_output_bytes).map_err(|_| {
                    NodeCoreError::PersistenceInvariant("invalid settlement fee output")
                })?),
                Some(frame.required_u64(3)?),
            )
        }
        (None, None) => {
            frame.require_only_fields(&[1, 4])?;
            (None, None)
        }
        _ => {
            return Err(NodeCoreError::PersistenceInvariant(
                "fast-path settlement charge fields presence mismatch",
            ));
        }
    };
    let signer_items: Vec<Vec<u8>> = decode_item_list(
        FASTPATH_ID_LIST_TYPE,
        frame.required_field(4)?,
        MAX_FASTPATH_SIGNERS,
    )?;
    let mut signer_ids: Vec<ValidatorId> = Vec::with_capacity(signer_items.len());
    for item in &signer_items {
        let bytes32: [u8; 32] = item
            .as_slice()
            .try_into()
            .map_err(|_| NodeCoreError::PersistenceInvariant("settlement signer id length"))?;
        signer_ids.push(ValidatorId::new(bytes32));
    }
    let record: FastPathSettlementRecord = FastPathSettlementRecord {
        request_id,
        fee_output,
        actual_amount,
        signer_ids,
    };
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
