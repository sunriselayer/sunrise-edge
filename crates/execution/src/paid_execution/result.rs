//! `PaidExecutionResult` (Frame `0x6415/v1`), the durable receipt result for
//! authenticated paid Call/Instantiate/Publish (DR-0124 authenticated
//! durable integration, 2026-09-08).
//!
//! Charged statuses (`Success`, `ApplicationFailed`) carry the reserved,
//! actual and refund asset units, the fee/refund `ObjectRef`s, the consumed
//! reservation `ObjectId` and the complete [`crate::ExecutionEffects`].
//! Zero-charge statuses (`ReservationFailed`, `SettlementFailed`,
//! `HostRejected`) carry none of those fields: there are no object effects,
//! events, creation authority or charge to report. Existing zero-fee result
//! bytes are unrelated and unchanged by this type.
use super::PaidExecutionError;
use crate::local_execution::{InstanceRecord, decode_instance_record, encode_instance_record};
use crate::{ExecutionEffects, decode_execution_effects, encode_execution_effects};
use abi::package_types::{PackageOrigin, decode_package_origin, encode_package_origin};
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use fees::Amount;
use objects::{
    ObjectId, ObjectRef, decode_object_id, decode_object_ref, encode_object_id, encode_object_ref,
};

const RESULT_TYPE: u16 = 0x6415;
const VERSION_1: u16 = 1;

const KIND_INSTANTIATE: u16 = 1;
const KIND_CALL: u16 = 2;
const KIND_PUBLISH: u16 = 3;

const STATUS_SUCCESS: u16 = 1;
const STATUS_APPLICATION_FAILED: u16 = 2;
const STATUS_RESERVATION_FAILED: u16 = 3;
const STATUS_SETTLEMENT_FAILED: u16 = 4;
const STATUS_HOST_REJECTED: u16 = 5;

/// Bounds the complete encoded [`PaidExecutionResult`], including its header
/// and object references, not only its embedded effects. This equals the
/// same ceiling the phase coordinator already reserves headroom against, so
/// a successful phase run can never produce a result too large to encode.
pub const MAX_PAID_EXECUTION_RESULT_BYTES: usize =
    crate::local_execution::MAX_LOCAL_EXECUTION_OUTPUT_BYTES;

/// Which application kind this result describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaidResultKind {
    Instantiate,
    Call,
    Publish,
}

/// Field 3: the actual durable instance record for `Instantiate`/`Call`, or the
/// published package origin for `Publish`.
#[derive(Clone, Debug, PartialEq, Eq)]
/// `InstanceRecord` is unavoidably larger than `PackageOrigin`; this type
/// is a short-lived receipt value, never stored in a hot per-object array,
/// so boxing would only move, not remove, the cost.
#[allow(clippy::large_enum_variant)]
pub enum PaidResultTarget {
    Instance(InstanceRecord),
    Package(PackageOrigin),
}

/// Field 4: which phase determined the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaidExecutionStatus {
    /// All three phases succeeded.
    Success,
    /// The application failed or, for Publish, exceeded the admitted limit;
    /// its effects were discarded (or its publication suppressed) and the
    /// fee was still settled.
    ApplicationFailed,
    /// Reservation failed: zero charge, no effects.
    ReservationFailed,
    /// Settlement failed: zero charge, no effects.
    SettlementFailed,
    /// A deterministic host invariant/finalization failure after reserve was
    /// attempted: zero charge, no effects, but nonce and receipt commit.
    HostRejected,
}

impl PaidExecutionStatus {
    const fn code(self) -> u16 {
        match self {
            Self::Success => STATUS_SUCCESS,
            Self::ApplicationFailed => STATUS_APPLICATION_FAILED,
            Self::ReservationFailed => STATUS_RESERVATION_FAILED,
            Self::SettlementFailed => STATUS_SETTLEMENT_FAILED,
            Self::HostRejected => STATUS_HOST_REJECTED,
        }
    }
    fn from_code(code: u16) -> Result<Self, PaidExecutionError> {
        Ok(match code {
            STATUS_SUCCESS => Self::Success,
            STATUS_APPLICATION_FAILED => Self::ApplicationFailed,
            STATUS_RESERVATION_FAILED => Self::ReservationFailed,
            STATUS_SETTLEMENT_FAILED => Self::SettlementFailed,
            STATUS_HOST_REJECTED => Self::HostRejected,
            _ => return Err(PaidExecutionError::Invalid("unknown paid result status")),
        })
    }
    /// True exactly for the two statuses that settled a fee and carry effects.
    #[must_use]
    pub const fn charged(self) -> bool {
        matches!(self, Self::Success | Self::ApplicationFailed)
    }
}

/// Fields 5..10 and 12, present exactly for charged statuses. Field 11
/// ([`ExecutionEffects`]) is carried separately on [`PaidExecutionResult`]
/// and is always present, including for zero-charge statuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidChargedOutcome {
    pub reserved: Amount,
    pub actual: Amount,
    pub refund: Amount,
    pub fee_output: ObjectRef,
    pub refund_output: Option<ObjectRef>,
    pub reservation: ObjectId,
    /// Field 12: the actual metered application gas units `A` this charge
    /// is based on. This is the sole pricing basis together with the fixed
    /// `R`/`S` allowances; it is disclosed, not a measured phase-gas claim.
    pub application_gas_units: u64,
}

/// Frame `0x6415/v1`: the complete durable paid execution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidExecutionResult {
    pub request_id: [u8; 32],
    pub kind: PaidResultKind,
    pub target: PaidResultTarget,
    pub status: PaidExecutionStatus,
    /// Field 11: complete committed effects, always present. Zero-charge
    /// statuses carry empty object effects and events but may still report
    /// a positive `gas_used` diagnostic (reserve/application/settle metered
    /// fuel spent before the deterministic rejection).
    pub effects: ExecutionEffects,
    pub charged: Option<PaidChargedOutcome>,
}

fn validate(result: &PaidExecutionResult) -> Result<(), PaidExecutionError> {
    match (&result.kind, &result.target) {
        (PaidResultKind::Instantiate | PaidResultKind::Call, PaidResultTarget::Instance(_)) => {}
        (PaidResultKind::Publish, PaidResultTarget::Package(_)) => {}
        _ => {
            return Err(PaidExecutionError::Invalid(
                "paid result kind/target mismatch",
            ));
        }
    }
    match (&result.charged, result.status.charged()) {
        (Some(charged), true) => {
            if charged.actual.get() == 0 {
                return Err(PaidExecutionError::Invalid(
                    "paid result actual must be positive",
                ));
            }
            let sum: u64 = charged
                .actual
                .get()
                .checked_add(charged.refund.get())
                .ok_or(PaidExecutionError::Invalid("paid result charge overflow"))?;
            if sum != charged.reserved.get() {
                return Err(PaidExecutionError::Invalid(
                    "paid result actual + refund must equal reserved",
                ));
            }
            if charged.refund_output.is_some() != (charged.refund.get() > 0) {
                return Err(PaidExecutionError::Invalid(
                    "paid result refund output presence",
                ));
            }
            if let Some(refund_output) = &charged.refund_output
                && refund_output.id == charged.fee_output.id
            {
                return Err(PaidExecutionError::Invalid(
                    "paid result fee and refund outputs must be distinct",
                ));
            }
            // gas_used = measured reserve + application + settle fuel, never
            // the fee-conversion basis; application_gas_units A can never
            // exceed that total.
            if charged.application_gas_units > result.effects.gas_used {
                return Err(PaidExecutionError::Invalid(
                    "paid result application gas exceeds total gas_used",
                ));
            }
            let expected_status = match result.status {
                PaidExecutionStatus::Success => crate::ExecutionStatus::Success,
                _ => crate::ExecutionStatus::Failure {
                    reason: crate::local_execution::LOCAL_EXECUTION_TRAP_REASON.into(),
                },
            };
            // Every charged failure reports the one canonical, normalized
            // trap reason string, never an arbitrary or empty message.
            if result.effects.status != expected_status {
                return Err(PaidExecutionError::Invalid(
                    "paid result effects status does not match paid status",
                ));
            }
        }
        (None, false) => {
            if !result.effects.object_effects.is_empty() || !result.effects.events.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "zero-charge paid result must have empty effects",
                ));
            }
            match &result.effects.status {
                crate::ExecutionStatus::Success => {
                    return Err(PaidExecutionError::Invalid(
                        "zero-charge paid result cannot report success",
                    ));
                }
                crate::ExecutionStatus::Failure { reason } => {
                    if reason != crate::local_execution::LOCAL_EXECUTION_TRAP_REASON {
                        return Err(PaidExecutionError::Invalid(
                            "zero-charge paid result unnormalized failure reason",
                        ));
                    }
                }
            }
        }
        _ => {
            return Err(PaidExecutionError::Invalid(
                "paid result charged fields presence mismatch",
            ));
        }
    }
    Ok(())
}

/// Encodes Frame `0x6415/v1`.
pub fn encode_paid_execution_result(
    result: &PaidExecutionResult,
) -> Result<Vec<u8>, PaidExecutionError> {
    validate(result)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(RESULT_TYPE, VERSION_1);
    frame.field_bytes(1, result.request_id.to_vec())?;
    let kind_code: u16 = match result.kind {
        PaidResultKind::Instantiate => KIND_INSTANTIATE,
        PaidResultKind::Call => KIND_CALL,
        PaidResultKind::Publish => KIND_PUBLISH,
    };
    frame.field_u16(2, kind_code)?;
    let target_bytes: Vec<u8> = match &result.target {
        PaidResultTarget::Instance(instance) => encode_instance_record(instance)?,
        PaidResultTarget::Package(origin) => encode_package_origin(origin)?,
    };
    frame.field_bytes(3, target_bytes)?;
    frame.field_u16(4, result.status.code())?;
    if let Some(charged) = &result.charged {
        frame.field_u64(5, charged.reserved.get())?;
        frame.field_u64(6, charged.actual.get())?;
        frame.field_u64(7, charged.refund.get())?;
        frame.field_bytes(8, encode_object_ref(&charged.fee_output)?)?;
        if let Some(refund_output) = &charged.refund_output {
            frame.field_bytes(9, encode_object_ref(refund_output)?)?;
        }
        frame.field_bytes(10, encode_object_id(&charged.reservation)?)?;
        frame.field_u64(12, charged.application_gas_units)?;
    }
    frame.field_bytes(11, encode_execution_effects(&result.effects)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_PAID_EXECUTION_RESULT_BYTES {
        return Err(PaidExecutionError::Limit("paid execution result"));
    }
    Ok(bytes)
}

/// Strictly decodes Frame `0x6415/v1`.
pub fn decode_paid_execution_result(
    bytes: &[u8],
) -> Result<PaidExecutionResult, PaidExecutionError> {
    if bytes.len() > MAX_PAID_EXECUTION_RESULT_BYTES {
        return Err(PaidExecutionError::Limit("paid execution result"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(RESULT_TYPE)?;
    frame.require_version(VERSION_1)?;
    let request_id: [u8; 32] = frame
        .required_field(1)?
        .try_into()
        .map_err(|_| PaidExecutionError::Invalid("expected exactly 32 bytes"))?;
    let kind_code: u16 = frame.required_u16(2)?;
    let kind: PaidResultKind = match kind_code {
        KIND_INSTANTIATE => PaidResultKind::Instantiate,
        KIND_CALL => PaidResultKind::Call,
        KIND_PUBLISH => PaidResultKind::Publish,
        _ => return Err(PaidExecutionError::Invalid("unknown paid result kind")),
    };
    let target_bytes: &[u8] = frame.required_field(3)?;
    let target: PaidResultTarget = match kind {
        PaidResultKind::Instantiate | PaidResultKind::Call => {
            PaidResultTarget::Instance(decode_instance_record(target_bytes)?)
        }
        PaidResultKind::Publish => PaidResultTarget::Package(decode_package_origin(target_bytes)?),
    };
    let status: PaidExecutionStatus = PaidExecutionStatus::from_code(frame.required_u16(4)?)?;
    let charged: Option<PaidChargedOutcome> = if status.charged() {
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])?;
        Some(PaidChargedOutcome {
            reserved: Amount::new(frame.required_u64(5)?),
            actual: Amount::new(frame.required_u64(6)?),
            refund: Amount::new(frame.required_u64(7)?),
            fee_output: decode_object_ref(frame.required_field(8)?)?,
            refund_output: match frame.field(9) {
                Some(bytes) => Some(decode_object_ref(bytes)?),
                None => None,
            },
            reservation: decode_object_id(frame.required_field(10)?)?,
            application_gas_units: frame.required_u64(12)?,
        })
    } else {
        frame.require_only_fields(&[1, 2, 3, 4, 11])?;
        None
    };
    let effects: ExecutionEffects = decode_execution_effects(frame.required_field(11)?)?;
    let result: PaidExecutionResult = PaidExecutionResult {
        request_id,
        kind,
        target,
        status,
        effects,
        charged,
    };
    validate(&result)?;
    if encode_paid_execution_result(&result)? != bytes {
        return Err(PaidExecutionError::Invalid(
            "noncanonical paid execution result",
        ));
    }
    Ok(result)
}
