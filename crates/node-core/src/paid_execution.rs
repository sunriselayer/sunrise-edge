//! Fenced durable admission for DR-0124 paid Call/Instantiate/Publish.
//!
//! This is the node-core counterpart of the internal
//! [`PaidContractEngine`](execution::paid_execution::PaidContractEngine)
//! boundary. It never wraps the zero-fee handler, never fabricates an
//! `AuthenticatedLocalExecutionIntent` or a `PublicationRequest` signature,
//! and never converts a zero-fee signature into a paid one: the only entry is
//! a complete signed `SignedPaidIntent` frame authenticated under a
//! caller-supplied trusted [`PublicationContext`].
//!
//! Admission order is exactly DR-0124's:
//!
//! 1. signature/context authentication of the signed paid bytes;
//! 2. exact replay reconciliation, before any nonce, policy, code, object or
//!    blob read, so a replay re-executes nothing and a conflicting request ID
//!    still returns `RequestIdReuse` unchanged;
//! 3. sender nonce freshness;
//! 4. the installed profile-four base execution policy and the installed paid
//!    fee policy, compared as exact stored bytes, then the immutable quote;
//! 5. the pinned fee instance, the application instance/publication origin and
//!    every exact code closure, through one shared publication budget and one
//!    shared read map;
//! 6. original object snapshots, authority rows, nominal bodies and ABI types;
//! 7. the engine, then independent verification of its receipt;
//! 8. one fenced [`DurableInvocationTransaction`] carrying object heads and
//!    versions, immutable creation authority, the instance or publication
//!    record, the consumed nonce and the complete receipt.
//!
//! Nothing here activates paid execution: no CLI, HTTP, bootstrap or installer
//! route reaches this function, and no policy is installed by it.
use super::*;
use execution::call_authorization::MAX_EXECUTION_SCOPES;
use execution::local_execution::{
    InstanceRecord, LocalExecutionError, LocalExecutionPolicy, ObjectAuthority,
    ResolvedExecutionScope, ScopedResolvedObject, decode_instance_record, decode_object_authority,
    encode_instance_record, instance_target,
};
use execution::paid_execution::{
    AuthenticatedPaidIntent, PaidApplication, PaidApplicationScopes, PaidContractEngine,
    PaidExecutionError, PaidExecutionOutcome, PaidExecutionRequest, PaidExecutionStatus,
    PaidFeePolicy, PaidIntent, ReservationAccessKind, authenticate_paid_intent,
    authenticate_paid_publication_candidate, encode_paid_execution_result, encode_paid_fee_policy,
    encode_signed_paid_intent, paid_invocation_digest, quote_paid_intent,
    verify_paid_execution_result,
};
use execution::publication::{
    AuthenticatedPublicationCandidate, BoundObjectSignature, PublicationContext,
    VerifiedPublicationInterface,
};
use local_execution::{
    LocalExecutionAdmissionError, effects, original_resolver, read_state, reference_matches,
    scopes, validate_authority, validate_closure,
};
use local_instance_state::{
    execution_policy_key_for_profile, instance_record_key, object_authority_key,
    paid_fee_policy_key,
};
use publication::{PublicationAdmissionError, PublicationLoadBudget};

#[cfg(test)]
mod tests;

/// Fail-closed paid admission errors. A pre-admission rejection writes nothing
/// and consumes no nonce; only an executed invocation commits a receipt.
#[derive(Debug)]
pub enum PaidExecutionAdmissionError {
    /// Storage, conflict, or node boundary failure.
    Node(NodeCoreError),
    /// Invalid signed execution scope, instance or engine result.
    Execution(LocalExecutionError),
    /// Invalid paid wire, policy, quote or independently verified receipt.
    Paid(PaidExecutionError),
    /// Invalid durable publication closure or provenance.
    Publication(PublicationAdmissionError),
    /// Policy or authority invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for PaidExecutionAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::Execution(error) => error.fmt(f),
            Self::Paid(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for PaidExecutionAdmissionError {}
macro_rules! conversion {
    ($source:ty,$variant:ident) => {
        impl From<$source> for PaidExecutionAdmissionError {
            fn from(error: $source) -> Self {
                Self::$variant(error.into())
            }
        }
    };
}
conversion!(NodeCoreError, Node);
conversion!(RuntimeError, Node);
conversion!(DurableReadError, Node);
conversion!(DurableInvocationError, Node);
conversion!(CanonicalEncodingError, Node);
conversion!(HashingError, Node);
conversion!(LocalExecutionError, Execution);
conversion!(PaidExecutionError, Paid);
conversion!(PublicationAdmissionError, Publication);
impl From<LocalExecutionAdmissionError> for PaidExecutionAdmissionError {
    fn from(error: LocalExecutionAdmissionError) -> Self {
        match error {
            LocalExecutionAdmissionError::Node(error) => Self::Node(error),
            LocalExecutionAdmissionError::Execution(error) => Self::Execution(error),
            LocalExecutionAdmissionError::Publication(error) => Self::Publication(error),
            LocalExecutionAdmissionError::Invalid(message) => Self::Invalid(message),
        }
    }
}
type PaidResult<T> = Result<T, PaidExecutionAdmissionError>;

fn invalid<T>(message: &'static str) -> PaidResult<T> {
    Err(PaidExecutionAdmissionError::Invalid(message))
}

/// Durable conflict/mutation authority uses the stronger of the signed
/// reservation and application modes; neither signed grant is widened.
const fn rank(mode: AccessMode) -> u8 {
    match mode {
        AccessMode::Read => 1,
        AccessMode::Write => 2,
        AccessMode::Consume => 3,
    }
}
const fn stronger(left: AccessMode, right: AccessMode) -> AccessMode {
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

fn scope_index(
    scopes: &[ResolvedExecutionScope],
    creator: &[u8; 32],
    seed: &[u8; 32],
) -> Option<usize> {
    scopes
        .iter()
        .position(|scope| &scope.instance.creator == creator && &scope.instance.seed == seed)
}

/// Resolves one instance record's exact durable code closure into a scope.
///
/// The record's own original context selects the trusted historical resolver,
/// so an instance created in an earlier epoch keeps its identity. The complete
/// scope set is separately revalidated as a whole by the engine.
#[allow(clippy::too_many_arguments)]
fn load_scope<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    call_context: &PublicationContext,
    instance: InstanceRecord,
    budget: &mut PublicationLoadBudget,
) -> PaidResult<ResolvedExecutionScope> {
    if instance.context.chain_id() != call_context.chain_id()
        || instance.context.protocol_version() != call_context.protocol_version()
        || instance.context.epoch() > call_context.epoch()
    {
        return invalid("instance context authority");
    }
    let loaded = publication::load_verified_publication_with_budget(
        store,
        context,
        domain,
        resolver,
        history,
        instance.code.origin(),
        budget,
    )?
    .ok_or(PaidExecutionAdmissionError::Invalid("instance code absent"))?;
    validate_closure(resolver, history, &loaded.interface)?;
    if !reference_matches(&instance.code, &loaded.interface)
        || loaded
            .interface
            .executable_abi(instance.code.origin())
            .and_then(|abi| abi.initializer.as_ref())
            != Some(&instance.initializer)
    {
        return invalid("instance code mismatch");
    }
    let target = instance_target(
        original_resolver(resolver, history, &instance.context)?,
        &instance,
    )?;
    Ok(ResolvedExecutionScope {
        instance,
        target,
        interface: loaded.interface,
    })
}

/// Reads one existing instance record and admits its scope exactly once.
#[allow(clippy::too_many_arguments)]
fn admit_existing_instance<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    call_context: &PublicationContext,
    creator: &[u8; 32],
    seed: &[u8; 32],
    admitted: &mut Vec<ResolvedExecutionScope>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    budget: &mut PublicationLoadBudget,
) -> PaidResult<usize> {
    if let Some(index) = scope_index(admitted, creator, seed) {
        return Ok(index);
    }
    if admitted.len() >= MAX_EXECUTION_SCOPES {
        return invalid("execution scope limit");
    }
    let key: Vec<u8> = instance_record_key(call_context.chain_id(), creator, seed)?;
    let observed: VersionedStateValue = read_state(store, context, domain, key, reads)?;
    let record: InstanceRecord = decode_instance_record(
        observed
            .value()
            .ok_or(PaidExecutionAdmissionError::Invalid("instance absent"))?,
    )?;
    let scope = load_scope(
        store,
        context,
        domain,
        resolver,
        history,
        call_context,
        record,
        budget,
    )?;
    admitted.push(scope);
    Ok(admitted.len() - 1)
}

/// The application-shaped state one admitted request carries into its commit.
struct ApplicationAdmission {
    /// Index of the application root scope, absent for Publish.
    scope: Option<usize>,
    /// Index of the pinned fee scope after the application was admitted.
    fee_scope: usize,
    /// Instance record key written only by a successful Instantiate.
    instantiate_key: Option<Vec<u8>>,
    /// Publication record key written only by a successful Publish.
    publication_key: Option<Vec<u8>>,
    /// Exact authenticated dependency closure of a paid Publish.
    dependencies: Vec<AuthenticatedPublicationCandidate>,
}

/// Authenticates, admits and durably commits one paid invocation.
///
/// `expected` is the caller's trusted execution context; `base_policy` and
/// `fee_policy` are the caller's trusted expected records, each of which must
/// equal the installed durable bytes exactly. `Err` before the engine runs
/// writes nothing and consumes no nonce.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn handle_paid_execution<
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
    engine: &E,
    signed_bytes: &[u8],
    created_checkpoint: u64,
) -> PaidResult<NodeOutput> {
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return invalid("resolver history bound");
    }
    // 1. Cryptographic authentication under the caller's trusted expected
    //    context. This proves signed bytes only, never durable admission.
    let authenticated: AuthenticatedPaidIntent =
        authenticate_paid_intent(resolver, expected, signed_bytes)?;
    let intent: &PaidIntent = authenticated.intent();
    let event_digest: Digest32 = paid_invocation_digest(resolver, authenticated.signed())?;
    let request_id: RequestId = RequestId::new(intent.request_id)?;
    // 2. Exact replay reconciliation, immediately after authentication and
    //    before every nonce, policy, code, object and blob read. A conflicting
    //    request ID returns `RequestIdReuse` from here, unchanged.
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
    {
        return Ok(output);
    }
    // 3. Sender nonce freshness.
    let layout: PersistenceLayout = PersistenceLayout::new(
        intent.context.chain_id().clone(),
        intent.context.protocol_version(),
    );
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce(
        store,
        context,
        domain,
        &layout,
        SenderNonceReservation {
            sender: intent.sender,
            epoch: intent.context.epoch(),
            nonce: intent.nonce,
        },
    )?;
    // 4. Installed profile-four base policy and installed paid fee policy, as
    //    exact stored bytes. A missing or different value fails closed.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    if base_policy.profile() != execution::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION {
        return invalid("paid execution requires the profile-four base policy");
    }
    let observed: VersionedStateValue = read_state(
        store,
        context,
        domain,
        execution_policy_key_for_profile(base_policy.context(), base_policy.profile())?,
        &mut reads,
    )?;
    if observed.value() != Some(base_policy.encode()?.as_slice()) {
        return invalid("execution policy absent or different");
    }
    let observed: VersionedStateValue = read_state(
        store,
        context,
        domain,
        paid_fee_policy_key(&fee_policy.context)?,
        &mut reads,
    )?;
    if observed.value() != Some(encode_paid_fee_policy(fee_policy)?.as_slice()) {
        return invalid("paid fee policy absent or different");
    }
    // Checks the signed/base/fee contexts, the signed policy digest, the
    // refund recipient and derives the immutable reservation quote. The engine
    // and the independent verifier both recompute it; none of them trust a
    // caller-supplied price.
    let _quote = quote_paid_intent(&authenticated, resolver, base_policy, fee_policy)?;

    // 5. One publication budget and one read map span every fee/application
    //    scope and the Publish dependency closure.
    let mut budget: PublicationLoadBudget = PublicationLoadBudget::default();
    let fee_key: Vec<u8> = instance_record_key(
        intent.context.chain_id(),
        &fee_policy.instance.creator,
        &fee_policy.instance.seed,
    )?;
    let observed: VersionedStateValue = read_state(store, context, domain, fee_key, &mut reads)?;
    let fee_instance: InstanceRecord = decode_instance_record(
        observed
            .value()
            .ok_or(PaidExecutionAdmissionError::Invalid("fee instance absent"))?,
    )?;
    // The pinned fee instance may legitimately originate in an earlier epoch,
    // but never in another chain or protocol version.
    if fee_instance.code != fee_policy.code {
        return invalid("pinned fee code");
    }
    let fee_scope: ResolvedExecutionScope = load_scope(
        store,
        context,
        domain,
        resolver,
        history,
        &intent.context,
        fee_instance.clone(),
        &mut budget,
    )?;
    if fee_scope.target != fee_policy.instance {
        return invalid("pinned fee instance");
    }
    let mut admitted: Vec<ResolvedExecutionScope> = vec![fee_scope];

    let application: ApplicationAdmission = match &intent.application {
        PaidApplication::Call(inner) => {
            let index: usize = admit_existing_instance(
                store,
                context,
                domain,
                resolver,
                history,
                &intent.context,
                &inner.instance.creator,
                &inner.instance.seed,
                &mut admitted,
                &mut reads,
                &mut budget,
            )?;
            for authorization in &intent.authorizations {
                for target in [&authorization.caller, &authorization.callee] {
                    admit_existing_instance(
                        store,
                        context,
                        domain,
                        resolver,
                        history,
                        &intent.context,
                        &target.instance.creator,
                        &target.instance.seed,
                        &mut admitted,
                        &mut reads,
                        &mut budget,
                    )?;
                }
            }
            ApplicationAdmission {
                scope: Some(index),
                fee_scope: 0,
                instantiate_key: None,
                publication_key: None,
                dependencies: Vec::new(),
            }
        }
        PaidApplication::Instantiate(inner) => {
            let key: Vec<u8> = instance_record_key(
                intent.context.chain_id(),
                &inner.instance.creator,
                &inner.instance.seed,
            )?;
            let observed: VersionedStateValue =
                read_state(store, context, domain, key.clone(), &mut reads)?;
            if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
                return invalid("instance already reserved");
            }
            if scope_index(&admitted, &inner.instance.creator, &inner.instance.seed).is_some() {
                return invalid("instantiate target collides with the fee instance");
            }
            if admitted.len() >= MAX_EXECUTION_SCOPES {
                return invalid("execution scope limit");
            }
            // The record about to be created, exactly as a successful commit
            // will persist it. The engine independently rederives its target.
            let record: InstanceRecord = InstanceRecord {
                context: intent.context.clone(),
                creator: intent.sender,
                seed: inner.instance.seed,
                code: inner.code.clone(),
                revision: 1,
                initializer: inner.entrypoint.clone(),
            };
            let scope = load_scope(
                store,
                context,
                domain,
                resolver,
                history,
                &intent.context,
                record,
                &mut budget,
            )?;
            // The instance being created is the application root scope; the
            // pinned fee scope follows it and can never be the same instance.
            admitted.insert(0, scope);
            ApplicationAdmission {
                scope: Some(0),
                fee_scope: 1,
                instantiate_key: Some(key),
                publication_key: None,
                dependencies: Vec::new(),
            }
        }
        PaidApplication::Publish(artifact) => {
            if artifact.wasm_profile() != base_policy.profile() {
                return invalid("paid publish requires the profile-four artifact");
            }
            let key: Vec<u8> = publication::publication_record_key(artifact.origin())?;
            let observed: VersionedStateValue =
                read_state(store, context, domain, key.clone(), &mut reads)?;
            if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
                return invalid("publication origin already exists");
            }
            // The root candidate is derived from the signed intent alone; no
            // `PublicationRequest` or publisher signature is fabricated.
            let candidate: AuthenticatedPublicationCandidate =
                authenticate_paid_publication_candidate(resolver, &authenticated)?;
            let (interface, dependencies): (
                VerifiedPublicationInterface,
                Vec<AuthenticatedPublicationCandidate>,
            ) = publication::load_paid_publish_closure(
                store,
                context,
                domain,
                resolver,
                history,
                candidate,
                signed_bytes.len(),
                &mut budget,
            )?;
            validate_closure(resolver, history, &interface)?;
            ApplicationAdmission {
                scope: None,
                fee_scope: 0,
                instantiate_key: None,
                publication_key: Some(key),
                dependencies,
            }
        }
    };

    // 6. The durable union of original inputs: the declared fee source plus
    //    every signed application input, deduplicated by ObjectId and loaded
    //    exactly once. The durable union takes the stronger of the two signed
    //    modes while the engine's source and the application's grants keep
    //    exactly their own signed modes.
    let source_mode: AccessMode = match intent.consent.access {
        ReservationAccessKind::Write => AccessMode::Write,
        ReservationAccessKind::Consume => AccessMode::Consume,
    };
    let application_entries: &[AccessEntry] = match &intent.application {
        PaidApplication::Call(inner) => &inner.access.entries,
        _ => &[],
    };
    let mut order: Vec<(ObjectRef, AccessMode)> =
        vec![(intent.consent.source.clone(), source_mode)];
    for entry in application_entries {
        if entry.object_ref.id == intent.consent.source.id {
            if entry.object_ref != intent.consent.source {
                return invalid("fee source reference mismatch");
            }
            order[0].1 = stronger(order[0].1, entry.mode);
            continue;
        }
        if order
            .iter()
            .any(|(reference, _)| reference.id == entry.object_ref.id)
        {
            return invalid("duplicate object");
        }
        order.push((entry.object_ref.clone(), entry.mode));
    }
    let mut snapshots: BTreeMap<ObjectId, object_snapshots::ObjectSnapshot> = BTreeMap::new();
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut inputs: Vec<ScopedResolvedObject> = Vec::new();
    let mut total_bytes: usize = 0;
    for (reference, mode) in &order {
        let snapshot: object_snapshots::ObjectSnapshot = object_snapshots::load_object_snapshot(
            store,
            blob_store,
            context,
            domain,
            intent.context.chain_id(),
            reference,
            &mut total_bytes,
        )?;
        if snapshot.object.owner != Owner::Address(Address::new(intent.sender)) {
            return invalid("paid inputs require sender address ownership");
        }
        let observed: VersionedStateValue = read_state(
            store,
            context,
            domain,
            object_authority_key(snapshot.object.id),
            &mut reads,
        )?;
        let authority: ObjectAuthority = decode_object_authority(observed.value().ok_or(
            PaidExecutionAdmissionError::Invalid("object authority absent"),
        )?)?;
        let scope: &ResolvedExecutionScope = scopes::for_authority(&admitted, &authority)?;
        validate_authority(&authority, &scope.instance, &scope.target, &scope.interface)?;
        if authority.object_id != snapshot.object.id {
            return invalid("object authority identity mismatch");
        }
        head_reads.push(DurableObjectHeadRead::new(
            snapshot.object.id,
            snapshot.head.clone(),
        ));
        inputs.push(ScopedResolvedObject {
            resolved: ResolvedObject {
                object: snapshot.object.clone(),
                mode: *mode,
            },
            authority,
        });
        if snapshots.insert(snapshot.object.id, snapshot).is_some() {
            return invalid("duplicate object");
        }
    }
    // The fee source is pinned to the policy's exact instance, code and asset
    // type, and its nominal body must decode under the policy's schema.
    let source_input: &ScopedResolvedObject = inputs
        .first()
        .ok_or(PaidExecutionAdmissionError::Invalid("fee source absent"))?;
    if source_input.authority.ty != fee_policy.asset_type
        || source_input.authority.code != fee_policy.code
        || source_input.authority.instance != fee_policy.instance
    {
        return invalid("fee source authority");
    }
    execution::publication::validate_nominal_body(
        &admitted[application.fee_scope].interface,
        &fee_policy.asset_type,
        fee_policy.schema,
        &source_input.resolved.object.data,
    )
    .map_err(|_| PaidExecutionAdmissionError::Invalid("fee source body mismatch"))?;
    let source: ScopedResolvedObject = ScopedResolvedObject {
        resolved: ResolvedObject {
            object: source_input.resolved.object.clone(),
            mode: source_mode,
        },
        authority: source_input.authority.clone(),
    };

    // Application inputs keep exactly their signed access modes and are
    // validated against the application ABI's bound parameters and bodies.
    let mut application_inputs: Vec<ScopedResolvedObject> = Vec::new();
    if let PaidApplication::Call(inner) = &intent.application {
        let index: usize = application
            .scope
            .ok_or(PaidExecutionAdmissionError::Invalid("application scope"))?;
        let binding: BoundObjectSignature<'_> =
            execution::call::bind_call_intent(inner, &admitted[index].interface)
                .map_err(|_| PaidExecutionAdmissionError::Invalid("application ABI binding"))?;
        if binding.objects().len() != inner.access.entries.len() {
            return invalid("application input count");
        }
        for (entry, param) in inner.access.entries.iter().zip(binding.objects()) {
            let input: &ScopedResolvedObject = inputs
                .iter()
                .find(|input| input.resolved.object.id == entry.object_ref.id)
                .ok_or(PaidExecutionAdmissionError::Invalid(
                    "application input absent",
                ))?;
            if &input.authority.ty != param.ty() {
                return invalid("object authority type mismatch");
            }
            application_inputs.push(ScopedResolvedObject {
                resolved: ResolvedObject {
                    object: input.resolved.object.clone(),
                    mode: entry.mode,
                },
                authority: input.authority.clone(),
            });
        }
        let resolved: Vec<ResolvedObject> = application_inputs
            .iter()
            .map(|input| input.resolved.clone())
            .collect();
        execution::publication::validate_object_input_bodies(
            &binding,
            resolver,
            intent.context.epoch(),
            &inner.access,
            &resolved,
        )
        .map_err(|_| PaidExecutionAdmissionError::Invalid("input body mismatch"))?;
        scopes::validate_inputs(
            &intent.context,
            &inner.access,
            &intent.authorizations,
            &admitted,
            &application_inputs,
            resolver,
        )?;
    }

    // 7. The engine, then independent verification of its receipt against the
    //    trusted fee instance and the exact Publish dependency closure.
    let application_scopes: PaidApplicationScopes<'_> = match &intent.application {
        PaidApplication::Call(_) => PaidApplicationScopes::Call {
            scope: application
                .scope
                .ok_or(PaidExecutionAdmissionError::Invalid("application scope"))?,
            inputs: &application_inputs,
        },
        PaidApplication::Instantiate(_) => PaidApplicationScopes::Instantiate {
            scope: application
                .scope
                .ok_or(PaidExecutionAdmissionError::Invalid("application scope"))?,
        },
        PaidApplication::Publish(_) => PaidApplicationScopes::Publish {
            dependencies: application.dependencies.clone(),
        },
    };
    let outcome: PaidExecutionOutcome = engine.execute_paid(PaidExecutionRequest {
        authenticated: &authenticated,
        resolver,
        base_policy,
        fee_policy,
        scopes: &admitted,
        source,
        application: application_scopes,
    })?;
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        resolver,
        base_policy,
        fee_policy,
        &fee_instance,
        &application.dependencies,
    )?;
    let result_bytes: Vec<u8> = encode_paid_execution_result(&outcome.result)?;
    let success: bool = outcome.result.status == PaidExecutionStatus::Success;

    // 8. One fenced transaction. Charged outcomes translate every application
    //    and fee effect; zero-charge phase failures commit only the consumed
    //    nonce and the receipt.
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    let object_mutations: Vec<DurableObjectMutationEntry> = if outcome.result.charged.is_some() {
        for created in &outcome.created_authorities {
            if created.authority.ty == fee_policy.reservation_type {
                return invalid("surviving reservation authority");
            }
        }
        effects::translate(
            store,
            context,
            domain,
            resolver,
            &admitted,
            &effects::CheckedEffects {
                context: &intent.context,
                effects: &outcome.result.effects,
                created_authorities: &outcome.created_authorities,
            },
            created_checkpoint,
            &inputs,
            &snapshots,
            &mut reads,
            &mut head_reads,
            &mut mutations,
        )?
    } else {
        if !outcome.result.effects.object_effects.is_empty()
            || !outcome.result.effects.events.is_empty()
            || !outcome.created_authorities.is_empty()
        {
            return invalid("zero-charge paid outcome must have no effects");
        }
        Vec::new()
    };
    if success {
        if let Some(key) = application.instantiate_key {
            let index: usize = application
                .scope
                .ok_or(PaidExecutionAdmissionError::Invalid("application scope"))?;
            mutations.push(StateMutationEntry::new(
                key,
                StateMutation::Put(encode_instance_record(&admitted[index].instance)?),
            )?);
        }
        if let Some(key) = application.publication_key {
            // The complete canonical signed paid frame is the durable record.
            let record: Vec<u8> = encode_signed_paid_intent(authenticated.signed())?;
            if record != signed_bytes {
                return invalid("noncanonical signed paid record");
            }
            mutations.push(StateMutationEntry::new(key, StateMutation::Put(record))?);
        }
    }
    budget.merge_reads(&mut reads)?;
    reads.insert(nonce.key.clone(), nonce.read_revision);
    mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let state: DurableStateTransaction =
        DurableStateTransaction::new(domain, AtomicStateReadSet::new(assertions)?, mutations)?;
    let output: NodeOutput = NodeOutput::new(
        vec![NodeResponse::new(
            request_id,
            if success {
                NodeResponseStatus::Accepted
            } else {
                NodeResponseStatus::Rejected
            },
            Some(result_bytes),
        )?],
        Vec::new(),
    )?;
    let dedup: NodeDedupRecord =
        NodeDedupRecord::new(request_id, event_digest, output.responses().to_vec())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(intent.request_id)
            .map_err(|_| PaidExecutionAdmissionError::Invalid("request id"))?,
        event_digest,
        dedup.encode()?,
    )?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(head_reads, object_mutations)?,
        receipt,
        None,
    )?;
    Ok(durable_reconciliation::committed_output(
        store.commit_invocation(context, transaction),
        output,
    )?)
}
