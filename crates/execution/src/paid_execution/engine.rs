//! [`PaidContractEngine`]: the injectable authenticated durable integration
//! entry point (DR-0124 "Authenticated durable integration", 2026-09-08).
//!
//! This module owns the *public* request/outcome types and the complete
//! runtime-independent validation of a [`PaidExecutionRequest`]: quote and
//! policy correspondence, the entire supplied scope set, exact canonical
//! source and application input references, the signed access modes, and
//! Publish's deterministic metered units. It contains no VM type: the
//! private phase/grant/source API stays inside `crate::local_wasm`, whose
//! [`crate::LocalWasmExecutionEngine`] provides the only in-crate
//! implementation of the trait.
//!
//! Call and Instantiate enter the ordinary frame validator with their actual
//! signed mode. Publish has no application WASM frame or arbitrary callback:
//! its metered application units are the deterministic
//! `artifact_encoded_bytes * artifact_byte_price + unique_closure_nodes *
//! closure_node_price` (the candidate counts as one node).
use std::collections::BTreeSet;

use super::result::{
    PaidChargedOutcome, PaidExecutionResult, PaidExecutionStatus, PaidResultKind, PaidResultTarget,
};
use super::{
    AuthenticatedPaidIntent, PaidApplication, PaidExecutionError, PaidFeePolicy,
    ReservationAccessKind, encode_paid_execution_result, paid_invocation_digest, quote_paid_intent,
};
use crate::ExecutionEffects;
use crate::call::{CallIntent, InstanceTarget};
use crate::execution_scopes::{
    required_scope_instances, validate_authorization_target_scopes, validate_execution_scope_set,
};
use crate::local_execution::{
    CreatedObjectAuthority, LocalExecutionMode, LocalExecutionPolicy, ResolvedExecutionScope,
    ScopedResolvedObject, generic_object_result_semantics,
};
use crate::publication::{
    AuthenticatedPublicationCandidate, candidate_from_paid_artifact, encode_code_artifact,
    verify_publication_interface,
};
use abi::AccessEntry;
use fees::reservation::{Admission, ReservationPricer};
use hashing::HashSuiteResolver;
use objects::{Object, ObjectId, ObjectRef, encode_object};
use protocol_types::{Digest32, Epoch, HashPurpose};

/// Which resolved application scope/inputs a [`PaidExecutionRequest`] supplies,
/// selected by the authenticated intent's own [`PaidApplication`] kind.
pub enum PaidApplicationScopes<'a> {
    /// The application root scope index and its declared, resolved inputs in
    /// signed order (matching the nested `CallIntent`'s access entries).
    Call {
        scope: usize,
        inputs: &'a [ScopedResolvedObject],
    },
    /// The scope describing the exact instance about to be created. It
    /// carries no application inputs: Instantiate forbids them.
    Instantiate { scope: usize },
    /// Already independently authenticated dependency candidates for the
    /// embedded artifact's declared closure. Publish never enters an
    /// application WASM frame.
    Publish {
        dependencies: Vec<AuthenticatedPublicationCandidate>,
    },
}

/// The public request: the immutable authenticated paid intent, resolved
/// scopes/inputs and trusted policies. The engine rechecks their
/// correspondence and never trusts caller-computed pricing, digests or scope
/// selection.
pub struct PaidExecutionRequest<'a> {
    pub authenticated: &'a AuthenticatedPaidIntent,
    pub resolver: &'a HashSuiteResolver,
    pub base_policy: &'a LocalExecutionPolicy,
    pub fee_policy: &'a PaidFeePolicy,
    /// Bounded admitted scopes; index selection is validated below.
    pub scopes: &'a [ResolvedExecutionScope],
    /// The resolved fee source, checked against the signed consent's
    /// original `ObjectRef` before any reservation is attempted.
    pub source: ScopedResolvedObject,
    pub application: PaidApplicationScopes<'a>,
}

/// The engine's outcome: the durable [`PaidExecutionResult`] wire type and
/// the surviving creations' authority, mirroring [`crate::local_execution::LocalExecutionOutcome`].
#[derive(Clone, Debug)]
pub struct PaidExecutionOutcome {
    pub result: PaidExecutionResult,
    pub created_authorities: Vec<CreatedObjectAuthority>,
}

/// The injectable paid execution boundary.
///
/// The method is named `execute_paid` so an engine type may implement both
/// this trait and [`crate::local_execution::LocalContractEngine`] without an
/// ambiguous `execute` call. Implementing it grants no storage authority and
/// performs no admission: the caller must have already reconciled exact
/// replay, nonce freshness, current object provenance and the installed
/// policy, and it alone commits the returned [`PaidExecutionOutcome`].
pub trait PaidContractEngine {
    /// Runs one authenticated paid Call, Instantiate or Publish.
    ///
    /// `Err` means the request was rejected *before* any reservation was
    /// attempted: nothing executed, nothing may be committed and no nonce is
    /// consumed. Every deterministic host failure once reserve has been
    /// attempted is instead an `Ok` zero-charge
    /// [`PaidExecutionStatus::HostRejected`] receipt.
    fn execute_paid(
        &self,
        request: PaidExecutionRequest<'_>,
    ) -> Result<PaidExecutionOutcome, PaidExecutionError>;
}

/// Derives and validates one authenticated publication candidate from an
/// authenticated paid Publish application (DR-0124 authenticated durable
/// integration, 2026-09-08). Performs the same context/semantics/publisher/
/// commitment/structural-WASM checks `candidate_from_paid_artifact`
/// performs. Authenticity comes entirely from the caller's own already
/// signature-verified [`AuthenticatedPaidIntent`]; this never fabricates or
/// nests a `PublicationRequest` signature, and grants no execution, storage
/// or dependency authority on its own.
pub fn authenticate_paid_publication_candidate(
    resolver: &HashSuiteResolver,
    authenticated: &AuthenticatedPaidIntent,
) -> Result<AuthenticatedPublicationCandidate, PaidExecutionError> {
    let intent = authenticated.intent();
    let PaidApplication::Publish(artifact) = &intent.application else {
        return Err(PaidExecutionError::Invalid(
            "not a paid publish application",
        ));
    };
    let semantics = generic_object_result_semantics(resolver, &intent.context)?;
    Ok(candidate_from_paid_artifact(
        resolver,
        &intent.context,
        &semantics,
        artifact.clone(),
    )?)
}

fn fee_pricer(policy: &PaidFeePolicy) -> Result<ReservationPricer, PaidExecutionError> {
    Ok(ReservationPricer::new(
        policy.gas_schedule.clone(),
        policy.conversion_divisor,
        policy.reserve_allowance,
        policy.settle_allowance,
    )?)
}

/// One fully validated application phase, described without any VM type.
pub(crate) struct ValidatedApplicationCall {
    /// Index of the application scope inside the validated scope set.
    pub scope: usize,
    /// Signed root mode; Instantiate and Call are never interchanged.
    pub mode: LocalExecutionMode,
    /// Signed exact root defining code.
    pub code: crate::publication::UnverifiedDependencyRef,
    /// Signed exact entrypoint.
    pub entrypoint: String,
    /// Signed bound type arguments, used verbatim.
    pub type_arguments: Vec<abi::package_types::ScopedTypeArg>,
    /// Signed canonical argument bytes, used verbatim.
    pub arguments: Vec<u8>,
    /// Resolved application inputs in signed order, each already matched to
    /// its signed [`AccessEntry`] by complete canonical `ObjectRef` and by
    /// exact access mode. Empty for Instantiate.
    pub inputs: Vec<ScopedResolvedObject>,
    /// Signed reusable call ceilings, used verbatim. Empty except for Call.
    pub authorizations: Vec<crate::call_authorization::CallAuthorization>,
}

/// The validated application phase: an ordinary WASM root frame, or
/// Publish's deterministic, WASM-free metered units.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ValidatedApplication {
    Wasm(ValidatedApplicationCall),
    Publish { units: u64 },
}

/// The complete runtime-independent validation of a [`PaidExecutionRequest`].
///
/// Producing one proves quote/policy correspondence, that the *entire*
/// supplied scope set is exactly the required set, that the fee source and
/// every application input match their signed canonical references and
/// access modes, and that a zero-charge `HostRejected` receipt for this
/// request is encodable. It is still not durable admission.
pub(crate) struct ValidatedPaidRequest {
    pub kind: PaidResultKind,
    pub target_record: PaidResultTarget,
    pub invocation_digest: Digest32,
    pub admission: Admission,
    pub pricer: ReservationPricer,
    /// Index of the pinned fee scope inside the validated scope set.
    pub fee_scope: usize,
    pub application: ValidatedApplication,
}

/// Checks that supplied resolved application inputs, in signed order,
/// identify exactly the nested `CallIntent`'s declared access entries. The
/// comparison uses the complete canonical `ObjectRef` (id, version and
/// content digest), not merely id/version: a caller-supplied
/// `ScopedResolvedObject` whose body digest disagrees with the signed
/// access entry must never be accepted as a match.
fn matched_inputs(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    entries: &[AccessEntry],
    supplied: &[ScopedResolvedObject],
) -> Result<Vec<ScopedResolvedObject>, PaidExecutionError> {
    if supplied.len() != entries.len() {
        return Err(PaidExecutionError::Invalid("application input count"));
    }
    let mut ids: BTreeSet<ObjectId> = BTreeSet::new();
    for (input, access) in supplied.iter().zip(entries) {
        let object: &Object = &input.resolved.object;
        let actual_ref: ObjectRef = object_ref(resolver, epoch, object)?;
        if !ids.insert(object.id)
            || actual_ref != access.object_ref
            || input.resolved.mode != access.mode
        {
            return Err(PaidExecutionError::Invalid("application input authority"));
        }
    }
    Ok(supplied.to_vec())
}

fn object_ref(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    object: &Object,
) -> Result<ObjectRef, PaidExecutionError> {
    Ok(ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver.hash_for_purpose(epoch, HashPurpose::Object, &encode_object(object)?)?,
    })
}

/// Locates the one supplied scope pinned by the fee policy.
///
/// The scope set has already been validated as a whole, including the
/// independently derived [`InstanceTarget`] of every record, so matching on
/// `scope.target` here compares a derived value, not a caller claim. A
/// second match is impossible for a validated set and is rejected explicitly
/// rather than silently resolved by iteration order.
fn fee_scope_index(
    scopes: &[ResolvedExecutionScope],
    policy: &PaidFeePolicy,
) -> Result<usize, PaidExecutionError> {
    let mut found: Option<usize> = None;
    for (index, scope) in scopes.iter().enumerate() {
        if scope.target != policy.instance {
            continue;
        }
        if found.is_some() {
            return Err(PaidExecutionError::Invalid("duplicate fee scope"));
        }
        found = Some(index);
    }
    let index: usize = found.ok_or(PaidExecutionError::Invalid("fee scope not resolved"))?;
    if scopes[index].instance.code != policy.code {
        return Err(PaidExecutionError::Invalid("pinned fee code"));
    }
    Ok(index)
}

/// Validates one application root scope selector against the signed nested
/// `CallIntent`, and binds the signed arguments to that scope's exact ABI.
fn application_scope<'a>(
    scopes: &'a [ResolvedExecutionScope],
    selected: usize,
    inner: &CallIntent,
    policy: &LocalExecutionPolicy,
    mode: LocalExecutionMode,
) -> Result<&'a ResolvedExecutionScope, PaidExecutionError> {
    let scope: &ResolvedExecutionScope = scopes.get(selected).ok_or(
        PaidExecutionError::Invalid("application scope not resolved"),
    )?;
    let target: &InstanceTarget = &scope.target;
    if target != &inner.instance || scope.instance.code != inner.code {
        return Err(PaidExecutionError::Invalid("application scope mismatch"));
    }
    if inner.gas_limit == 0 || inner.gas_limit > policy.max_gas() {
        return Err(PaidExecutionError::Invalid("application gas limit"));
    }
    let metadata = scope
        .interface
        .executable_abi(inner.code.origin())
        .ok_or(PaidExecutionError::Invalid("application executable ABI"))?;
    let initializer: Option<&str> = metadata.initializer.as_deref();
    match mode {
        LocalExecutionMode::Instantiate => {
            // The instance about to be created must be the one the sender
            // signed, created by that sender in this exact context, through
            // the ABI-designated initializer.
            if scope.instance.creator != inner.sender
                || scope.instance.context != inner.context
                || initializer != Some(inner.entrypoint.as_str())
            {
                return Err(PaidExecutionError::Invalid("initializer authority"));
            }
        }
        LocalExecutionMode::Call => {
            if initializer == Some(inner.entrypoint.as_str()) {
                return Err(PaidExecutionError::Invalid("initializer replay"));
            }
        }
    }
    crate::call::bind_call_intent(inner, &scope.interface)?;
    Ok(scope)
}

/// Publish's deterministic metered application units:
/// `artifact_encoded_bytes * artifact_byte_price + unique_closure_nodes *
/// closure_node_price`, where the candidate itself counts as one node.
fn publish_units(
    resolver: &HashSuiteResolver,
    authenticated: &AuthenticatedPaidIntent,
    policy: &PaidFeePolicy,
    artifact: &crate::publication::CodeArtifact,
    dependencies: &[AuthenticatedPublicationCandidate],
) -> Result<u64, PaidExecutionError> {
    let candidate: AuthenticatedPublicationCandidate =
        authenticate_paid_publication_candidate(resolver, authenticated)?;
    let interface = verify_publication_interface(candidate, dependencies.to_vec())?;
    let closure_nodes: u64 = 1u64
        .checked_add(interface.dependencies().len() as u64)
        .ok_or(PaidExecutionError::Invalid("publish closure size"))?;
    let artifact_bytes: u64 = encode_code_artifact(artifact)?.len() as u64;
    let byte_units: u64 = artifact_bytes
        .checked_mul(policy.publish_artifact_byte_price)
        .ok_or(PaidExecutionError::Invalid("publish unit overflow"))?;
    let node_units: u64 = closure_nodes
        .checked_mul(policy.publish_closure_node_price)
        .ok_or(PaidExecutionError::Invalid("publish unit overflow"))?;
    byte_units
        .checked_add(node_units)
        .ok_or(PaidExecutionError::Invalid("publish unit overflow"))
}

/// The zero-charge `HostRejected` receipt for one request.
///
/// `gas_used` is the exact fuel the invocation metered before the
/// deterministic host failure. Every other field is fixed, so its encoded
/// length does not depend on the measured value: pre-validating this
/// skeleton before execution therefore proves the post-execution fallback
/// still fits the complete 16 MiB [`super::MAX_PAID_EXECUTION_RESULT_BYTES`]
/// bound.
pub(crate) fn host_rejected_result(
    validated: &ValidatedPaidRequest,
    request_id: [u8; 32],
    tx_hash: Digest32,
    gas_used: u64,
) -> PaidExecutionResult {
    PaidExecutionResult {
        request_id,
        kind: validated.kind,
        target: validated.target_record.clone(),
        status: PaidExecutionStatus::HostRejected,
        effects: ExecutionEffects {
            tx_hash,
            status: crate::ExecutionStatus::Failure {
                reason: crate::local_execution::LOCAL_EXECUTION_TRAP_REASON.into(),
            },
            object_effects: Vec::new(),
            events: Vec::new(),
            gas_used,
        },
        charged: None,
    }
}

/// Performs the complete runtime-independent validation of one
/// [`PaidExecutionRequest`].
///
/// Errors here are *pre-reserve* rejections: nothing has executed, nothing
/// may be committed and no nonce is consumed.
pub(crate) fn validate_paid_request(
    request: &PaidExecutionRequest<'_>,
) -> Result<ValidatedPaidRequest, PaidExecutionError> {
    let admission: Admission = quote_paid_intent(
        request.authenticated,
        request.resolver,
        request.base_policy,
        request.fee_policy,
    )?;
    let intent = request.authenticated.intent();
    let invocation_digest: Digest32 =
        paid_invocation_digest(request.resolver, request.authenticated.signed())?;
    let epoch: Epoch = intent.context.epoch();

    // The complete canonical `ObjectRef`, including the content digest of
    // the actually supplied body, must equal the signed consent reference.
    let source_ref: ObjectRef =
        object_ref(request.resolver, epoch, &request.source.resolved.object)?;
    if source_ref != intent.consent.source {
        return Err(PaidExecutionError::Invalid("fee source reference mismatch"));
    }
    // The signed reservation access mode selects the pinned export; it never
    // strengthens or weakens the application's own signed modes.
    let reservation_mode: objects::AccessMode = match intent.consent.access {
        ReservationAccessKind::Write => objects::AccessMode::Write,
        ReservationAccessKind::Consume => objects::AccessMode::Consume,
    };
    if request.source.resolved.mode != reservation_mode {
        return Err(PaidExecutionError::Invalid("fee source access mode"));
    }

    // The entire supplied scope set is validated as a set: contexts, derived
    // instance targets, verified code references, initializers, code
    // semantics/profiles and the invocation-wide closure budgets, and it must
    // equal the required union of the fee instance plus the application and
    // authorization instances exactly. A duplicate or unneeded scope is
    // rejected here, not silently ignored by selector lookup.
    let mut required: BTreeSet<([u8; 32], [u8; 32])> = match &intent.application {
        PaidApplication::Call(inner) | PaidApplication::Instantiate(inner) => {
            required_scope_instances(&inner.instance, &intent.authorizations)
        }
        PaidApplication::Publish(_) => BTreeSet::new(),
    };
    required.insert((
        request.fee_policy.instance.creator,
        request.fee_policy.instance.seed,
    ));
    validate_execution_scope_set(
        request.resolver,
        request.base_policy,
        &intent.context,
        &required,
        request.scopes,
    )?;
    validate_authorization_target_scopes(request.scopes, &intent.authorizations)?;

    let fee_scope: usize = fee_scope_index(request.scopes, request.fee_policy)?;

    let (kind, application, target_record): (
        PaidResultKind,
        ValidatedApplication,
        PaidResultTarget,
    ) = match (&intent.application, &request.application) {
        (PaidApplication::Call(inner), PaidApplicationScopes::Call { scope, inputs }) => {
            let application_scope: &ResolvedExecutionScope = application_scope(
                request.scopes,
                *scope,
                inner,
                request.base_policy,
                LocalExecutionMode::Call,
            )?;
            let inputs: Vec<ScopedResolvedObject> =
                matched_inputs(request.resolver, epoch, &inner.access.entries, inputs)?;
            (
                PaidResultKind::Call,
                ValidatedApplication::Wasm(ValidatedApplicationCall {
                    scope: *scope,
                    mode: LocalExecutionMode::Call,
                    code: inner.code.clone(),
                    entrypoint: inner.entrypoint.clone(),
                    type_arguments: inner.type_arguments.clone(),
                    arguments: inner.arguments.clone(),
                    inputs,
                    authorizations: intent.authorizations.clone(),
                }),
                PaidResultTarget::Instance(application_scope.instance.clone()),
            )
        }
        (PaidApplication::Instantiate(inner), PaidApplicationScopes::Instantiate { scope }) => {
            let application_scope: &ResolvedExecutionScope = application_scope(
                request.scopes,
                *scope,
                inner,
                request.base_policy,
                LocalExecutionMode::Instantiate,
            )?;
            // `validate_paid_intent_structure` already requires empty
            // type arguments, application access and authorizations for
            // Instantiate; reuse the signed fields directly rather than
            // fabricating fresh empty ones, so a future relaxation of
            // that structural rule cannot be silently ignored here.
            if !intent.authorizations.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "instantiate forbids authorizations",
                ));
            }
            if !inner.access.entries.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "instantiate forbids application object inputs",
                ));
            }
            (
                PaidResultKind::Instantiate,
                ValidatedApplication::Wasm(ValidatedApplicationCall {
                    scope: *scope,
                    mode: LocalExecutionMode::Instantiate,
                    code: inner.code.clone(),
                    entrypoint: inner.entrypoint.clone(),
                    type_arguments: inner.type_arguments.clone(),
                    arguments: inner.arguments.clone(),
                    inputs: Vec::new(),
                    authorizations: intent.authorizations.clone(),
                }),
                PaidResultTarget::Instance(application_scope.instance.clone()),
            )
        }
        (PaidApplication::Publish(artifact), PaidApplicationScopes::Publish { dependencies }) => (
            PaidResultKind::Publish,
            ValidatedApplication::Publish {
                units: publish_units(
                    request.resolver,
                    request.authenticated,
                    request.fee_policy,
                    artifact,
                    dependencies,
                )?,
            },
            PaidResultTarget::Package(artifact.origin().clone()),
        ),
        _ => {
            return Err(PaidExecutionError::Invalid(
                "application scope selector kind mismatch",
            ));
        }
    };

    let validated: ValidatedPaidRequest = ValidatedPaidRequest {
        kind,
        target_record,
        invocation_digest,
        admission,
        pricer: fee_pricer(request.fee_policy)?,
        fee_scope,
        application,
    };
    // Prove the zero-charge fallback receipt is encodable *before* anything
    // executes, so a post-reserve host failure always has a committable
    // receipt inside the complete 16 MiB result bound.
    let _: Vec<u8> = encode_paid_execution_result(&host_rejected_result(
        &validated,
        intent.request_id,
        invocation_digest,
        0,
    ))?;
    Ok(validated)
}

/// Assembles the charged fields of a paid receipt from the settled outputs,
/// recomputing each output's complete canonical `ObjectRef` from the object
/// actually created by settlement.
pub(crate) fn charged_outcome(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    effects: &ExecutionEffects,
    settled: SettledOutputs,
) -> Result<PaidChargedOutcome, PaidExecutionError> {
    let find = |id: objects::ObjectId| -> Option<&Object> {
        effects
            .object_effects
            .iter()
            .find_map(|effect| match effect {
                crate::ObjectEffect::Created(object) if object.id == id => Some(object),
                _ => None,
            })
    };
    let fee_object: &Object =
        find(settled.fee_output).ok_or(PaidExecutionError::Invalid("fee output not created"))?;
    let fee_output: ObjectRef = object_ref(resolver, epoch, fee_object)?;
    let refund_output: Option<ObjectRef> = match settled.refund_output {
        Some(refund_id) => {
            let refund_object: &Object =
                find(refund_id).ok_or(PaidExecutionError::Invalid("refund output not created"))?;
            Some(object_ref(resolver, epoch, refund_object)?)
        }
        None => None,
    };
    Ok(PaidChargedOutcome {
        reserved: settled.reserved,
        actual: settled.actual,
        refund: settled.refund,
        fee_output,
        refund_output,
        reservation: settled.reservation,
        application_gas_units: settled.application_gas_units,
    })
}

/// The settled values one charged phase run produced, described without any
/// VM type so the receipt assembly above stays runtime-independent.
pub(crate) struct SettledOutputs {
    pub reserved: fees::Amount,
    pub actual: fees::Amount,
    pub refund: fees::Amount,
    pub fee_output: objects::ObjectId,
    pub refund_output: Option<objects::ObjectId>,
    pub reservation: objects::ObjectId,
    pub application_gas_units: u64,
}
