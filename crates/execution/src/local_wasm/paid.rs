//! [`LocalWasmExecutionEngine`]'s implementation of the injectable
//! [`PaidContractEngine`] boundary (DR-0124 "Authenticated durable
//! integration", 2026-09-08).
//!
//! This is the only place where the public paid request types meet the
//! private phase/grant/source API. `crate::paid_execution` performs the
//! complete runtime-independent validation and never sees a VM type; this
//! module translates that validated description into the private
//! [`coordinator::PhasePlan`] and translates the private
//! [`coordinator::PhaseOutcome`] back into the public
//! [`PaidExecutionResult`].
//!
//! The error boundary is exact:
//!
//! * Every failure *before* the reserve phase is attempted is `Err`. Nothing
//!   executed, nothing may be committed and no nonce is consumed.
//! * Every deterministic host invariant or finalization failure once reserve
//!   has been attempted — including a receipt-assembly or final encoding
//!   failure discovered after the VM finished — is an `Ok` zero-charge
//!   [`PaidExecutionStatus::HostRejected`] receipt carrying the exact
//!   measured gas, except that an internal accounting-bound violation reports
//!   the admitted total ceiling instead. It is never a bare `Err`, because
//!   the caller must still
//!   commit the consumed nonce and that receipt.
use super::LocalWasmExecutionEngine;
use super::coordinator::{
    self, ApplicationCall, ApplicationExecution, FeeTarget, PhaseOutcome, PhasePlan, PhaseStatus,
    ReservationAccess,
};
use crate::paid_execution::engine::{
    SettledOutputs, ValidatedApplication, ValidatedPaidRequest, charged_outcome,
    host_rejected_result, validate_paid_request,
};
use crate::paid_execution::{
    PaidContractEngine, PaidExecutionError, PaidExecutionOutcome, PaidExecutionRequest,
    PaidExecutionResult, PaidExecutionStatus, ReservationAccessKind, encode_paid_execution_result,
};
use protocol_types::Epoch;

impl PaidContractEngine for LocalWasmExecutionEngine {
    fn execute_paid(
        &self,
        request: PaidExecutionRequest<'_>,
    ) -> Result<PaidExecutionOutcome, PaidExecutionError> {
        // ---- pre-reserve: every rejection below writes nothing.
        let validated: ValidatedPaidRequest = validate_paid_request(&request)?;
        let intent = request.authenticated.intent();
        let epoch: Epoch = intent.context.epoch();
        let request_id: [u8; 32] = intent.request_id;
        let invocation_digest = validated.invocation_digest;

        let target: FeeTarget = FeeTarget {
            scope: validated.fee_scope,
            code: request.fee_policy.code.clone(),
            reserve_entrypoint: request.fee_policy.reserve_entrypoint.clone(),
            reserve_all_entrypoint: request.fee_policy.reserve_all_entrypoint.clone(),
            settle_entrypoint: request.fee_policy.settle_entrypoint.clone(),
            type_arguments: request.fee_policy.type_arguments.clone(),
            asset_type: request.fee_policy.asset_type.clone(),
            reservation_type: request.fee_policy.reservation_type.clone(),
            schema: request.fee_policy.schema,
        };
        let access: ReservationAccess = match intent.consent.access {
            ReservationAccessKind::Write => ReservationAccess::Write,
            ReservationAccessKind::Consume => ReservationAccess::Consume,
        };
        let application: ApplicationExecution = match &validated.application {
            ValidatedApplication::Wasm(call) => ApplicationExecution::Wasm(ApplicationCall {
                scope: call.scope,
                code: call.code.clone(),
                entrypoint: call.entrypoint.clone(),
                mode: call.mode,
                type_arguments: call.type_arguments.clone(),
                arguments: call.arguments.clone(),
                inputs: call.inputs.clone(),
                authorizations: call.authorizations.clone(),
            }),
            ValidatedApplication::Publish { units } => {
                ApplicationExecution::Publish { units: *units }
            }
        };
        let plan: PhasePlan<'_> = PhasePlan {
            scopes: request.scopes,
            resolver: request.resolver,
            policy: request.base_policy,
            context: intent.context.clone(),
            sender: intent.sender,
            event_digest: invocation_digest,
            invocation_digest,
            fee_policy_digest: intent.fee_policy_digest,
            target,
            access,
            source: request.source.clone(),
            application,
            admission: validated.admission.clone(),
            pricer: validated.pricer.clone(),
            fee_recipient: request.fee_policy.fee_recipient,
            refund_recipient: intent.consent.refund_recipient,
        };

        // `run` returns `Err` only for a pre-reserve structural rejection.
        let outcome: PhaseOutcome = coordinator::run(&plan)?;

        // ---- post-reserve: only `Ok` outcomes from here on.
        let measured_gas: u64 = outcome.effects.gas_used;
        let host_rejected = |gas: u64| PaidExecutionOutcome {
            result: host_rejected_result(&validated, request_id, invocation_digest, gas),
            created_authorities: Vec::new(),
        };

        let status: PaidExecutionStatus = match outcome.status {
            PhaseStatus::Success => PaidExecutionStatus::Success,
            PhaseStatus::ApplicationFailed => PaidExecutionStatus::ApplicationFailed,
            PhaseStatus::ReservationFailed => PaidExecutionStatus::ReservationFailed,
            PhaseStatus::SettlementFailed => PaidExecutionStatus::SettlementFailed,
            PhaseStatus::HostRejected => return Ok(host_rejected(measured_gas)),
        };
        let charged = if status.charged() {
            let (Some(fee_output), Some(reservation)) = (outcome.fee_output, outcome.reservation)
            else {
                // A charged status without its settled outputs is a host
                // invariant failure discovered after the VM finished.
                return Ok(host_rejected(measured_gas));
            };
            match charged_outcome(
                request.resolver,
                epoch,
                &outcome.effects,
                SettledOutputs {
                    reserved: outcome.reserved,
                    actual: outcome.actual_charge,
                    refund: outcome.refund,
                    fee_output,
                    refund_output: outcome.refund_output,
                    reservation,
                    application_gas_units: outcome.application_gas,
                },
            ) {
                Ok(charged) => Some(charged),
                Err(_) => return Ok(host_rejected(measured_gas)),
            }
        } else {
            None
        };

        let result: PaidExecutionResult = PaidExecutionResult {
            request_id,
            kind: validated.kind,
            target: validated.target_record.clone(),
            status,
            effects: outcome.effects,
            charged,
        };
        // Bounds and validates the complete receipt. A failure here is a
        // deterministic finalization failure after the VM ran, so it becomes
        // the small zero-charge `HostRejected` receipt whose encodability was
        // already proven before execution, not a bare `Err`.
        if encode_paid_execution_result(&result).is_err() {
            return Ok(host_rejected(measured_gas));
        }
        Ok(PaidExecutionOutcome {
            result,
            created_authorities: outcome.created_authorities,
        })
    }
}
