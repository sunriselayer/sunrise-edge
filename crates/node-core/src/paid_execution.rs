//! Fenced durable admission for DR-0124 paid Call/Instantiate/Publish, shared
//! by the direct commit path here and the DR-0130 fast-path prepare/apply
//! flow in [`crate::fast_path`].
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
//! 1. signature/context authentication of the signed paid bytes, and
//!    rejection of any request id inside the reserved fast-path synthetic
//!    receipt namespace (DR-0130) so that namespace can never be squatted;
//! 2. exact replay reconciliation, before any nonce, policy, code, object or
//!    blob read, so a replay re-executes nothing and a conflicting request ID
//!    still returns `RequestIdReuse` unchanged;
//! 3. sender nonce freshness and fast-path nonce-lock reconciliation;
//! 4. the installed profile-four base execution policy and the installed paid
//!    fee policy, compared as exact stored bytes, then the immutable quote;
//! 5. the pinned fee instance, the application instance/publication origin and
//!    every exact code closure, through one shared publication budget and one
//!    shared read map;
//! 6. original object snapshots, authority rows, nominal bodies, ABI types,
//!    and (DR-0130) the fast-path lock row for every input: an input locked
//!    by a *different* request id fails closed, so an in-flight prepare's
//!    inputs cannot be reused by a direct commit or a different prepare;
//! 7. the engine, then independent verification of its receipt;
//! 8. one fenced [`DurableInvocationTransaction`] carrying object heads and
//!    versions, immutable creation authority, the instance or publication
//!    record, the nonce advance and the complete receipt.
//!
//! [`preflight_paid_execution`] performs steps 1 and 2 and returns either the
//! exact committed replay or an unforgeable fresh witness.
//! [`build_paid_admission`] performs steps 3 through 7 plus the effect
//! translation half of step 8, returning a complete staged envelope neither
//! committed nor turned into a final receipt. [`handle_paid_execution`] is a
//! thin wrapper over that preflight and [`handle_preflighted_paid_execution`],
//! which admits the fresh witness and commits its real receipt.
//! `crate::fast_path::prepare`/`crate::fast_path::apply` are the other two
//! callers: neither duplicates this admission/execution pipeline.
//!
//! Nothing here activates paid execution: no CLI, HTTP, bootstrap or installer
//! route reaches this function, and no policy is installed by it.
use super::*;
use execution::call_authorization::MAX_EXECUTION_SCOPES;
use execution::execution_scopes::{
    required_scope_instances, validate_authorization_target_scopes, validate_execution_scope_set,
};
use execution::local_execution::{
    CreatedObjectAuthority, InstanceRecord, LocalExecutionError, LocalExecutionPolicy,
    ObjectAuthority, ResolvedExecutionScope, ScopedResolvedObject, decode_instance_record,
    decode_object_authority, encode_instance_record, instance_target,
};
use execution::paid_execution::{
    AuthenticatedPaidIntent, PaidApplication, PaidApplicationScopes, PaidChargedOutcome,
    PaidContractEngine, PaidExecutionError, PaidExecutionOutcome, PaidExecutionRequest,
    PaidExecutionStatus, PaidFeePolicy, PaidIntent, ReservationAccessKind,
    authenticate_paid_intent, authenticate_paid_publication_candidate,
    encode_paid_execution_result, encode_paid_fee_policy, encode_signed_paid_intent,
    paid_invocation_digest, quote_paid_intent, validate_fee_interface_admission,
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
    execution_policy_key_for_profile, fastpath_lock_key, instance_record_key, object_authority_key,
    paid_fee_policy_key,
};
use publication::{PublicationAdmissionError, PublicationLoadBudget};

#[cfg(test)]
pub(crate) mod tests;

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
pub(crate) type PaidResult<T> = Result<T, PaidExecutionAdmissionError>;

fn invalid<T>(message: &'static str) -> PaidResult<T> {
    Err(PaidExecutionAdmissionError::Invalid(message))
}

/// Authenticated fresh paid invocation returned only after exact durable
/// receipt reconciliation proved that no final result exists yet.
///
/// Fields are private so callers cannot fabricate or alter the authenticated
/// intent, digest, or request identity between preflight and admission.
pub struct FreshPaidExecution {
    authenticated: AuthenticatedPaidIntent,
    event_digest: Digest32,
    request_id: RequestId,
}

impl FreshPaidExecution {
    /// Returns the authenticated request identity.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
}

/// Result of paid authentication plus receipt reconciliation.
pub enum PaidExecutionPreflight {
    /// An exact committed replay; no current nonce or policy row was read.
    Replayed {
        /// Authenticated request identity of the persisted result.
        request_id: RequestId,
        /// Exact independently reverified durable result.
        output: NodeOutput,
    },
    /// A fresh authenticated request that still requires current admission.
    Fresh(FreshPaidExecution),
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

/// Independently checks that a non-`Success` charged outcome's reported
/// effects and events are exactly the fee settlement footprint derivable
/// from `charged` and the resolved fee source: the fee source's own
/// mutation (`Write`) or deletion (`Consume`), an optional consumed
/// transient reservation deletion, the fresh fee output and an optional
/// fresh refund output, with created authorities naming exactly those
/// fresh outputs. [`verify_paid_execution_result`] already proves the fee
/// and refund outputs and the absent surviving reservation type in
/// isolation; this additionally proves that nothing else -- no
/// application-created object, mutation, deletion or event -- survives
/// into the durable commit under a forged or buggy `ApplicationFailed`
/// receipt. Events are required empty because the real reserve/
/// application/settle coordinator never emits one from reserve or settle;
/// this is deliberately not an open allowlist for "fee events" it does not
/// actually produce.
fn validate_application_failed_footprint(
    effects: &ExecutionEffects,
    created_authorities: &[CreatedObjectAuthority],
    charged: &PaidChargedOutcome,
    source: &Object,
    source_mode: AccessMode,
) -> PaidResult<()> {
    if !effects.events.is_empty() {
        return invalid("application-failed events must be empty");
    }
    let mut remaining: Vec<&ObjectEffect> = effects.object_effects.iter().collect();
    let source_index: usize = remaining
        .iter()
        .position(|effect| match (source_mode, effect) {
            (
                AccessMode::Write,
                ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                },
            ) => *previous_version == source.version && new_object.id == source.id,
            (AccessMode::Consume, ObjectEffect::Deleted { id, version }) => {
                *id == source.id && *version == source.version
            }
            _ => false,
        })
        .ok_or(PaidExecutionAdmissionError::Invalid(
            "application-failed fee source footprint",
        ))?;
    remaining.remove(source_index);
    let fee_index: usize = remaining
        .iter()
        .position(|effect| {
            matches!(effect, ObjectEffect::Created(object) if object.id == charged.fee_output.id)
        })
        .ok_or(PaidExecutionAdmissionError::Invalid(
            "application-failed fee output footprint",
        ))?;
    remaining.remove(fee_index);
    if let Some(refund_output) = &charged.refund_output {
        let refund_index: usize = remaining
            .iter()
            .position(|effect| {
                matches!(effect, ObjectEffect::Created(object) if object.id == refund_output.id)
            })
            .ok_or(PaidExecutionAdmissionError::Invalid(
                "application-failed refund output footprint",
            ))?;
        remaining.remove(refund_index);
    }
    match remaining.as_slice() {
        [] => {}
        [ObjectEffect::Deleted { id, .. }] if *id == charged.reservation => {}
        _ => return invalid("application-failed effect footprint"),
    }
    let mut expected_authorities: BTreeSet<ObjectId> = BTreeSet::new();
    expected_authorities.insert(charged.fee_output.id);
    if let Some(refund_output) = &charged.refund_output {
        expected_authorities.insert(refund_output.id);
    }
    let mut actual_authorities: BTreeSet<ObjectId> = BTreeSet::new();
    for created in created_authorities {
        if !actual_authorities.insert(created.authority.object_id) {
            return invalid("application-failed duplicate creation authority");
        }
    }
    if actual_authorities != expected_authorities {
        return invalid("application-failed creation authority footprint");
    }
    Ok(())
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

/// How [`build_paid_admission`] treats the sender nonce and fast-path locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonceMode {
    /// Direct commit or first prepare: the ordinary nonce must be fresh and
    /// no sender/epoch nonce lock or object lock may already exist.
    Fresh,
    /// Certificate apply: the ordinary nonce is still fresh because prepare
    /// did not advance it, while the exact request must own every nonce/object
    /// lock. Apply commits the returned nonce write with all effects.
    PreparedApply,
}

/// The complete staged, uncommitted admission envelope [`build_paid_admission`]
/// returns. Every durable side effect a caller commits from this must come
/// from these fields unchanged: nothing else observed during admission may
/// silently leak into a transaction.
pub(crate) struct PaidAdmissionOutput {
    pub(crate) event_digest: Digest32,
    pub(crate) outcome: PaidExecutionOutcome,
    pub(crate) result_bytes: Vec<u8>,
    pub(crate) success: bool,
    /// Every state key this admission observed, other than the sender-nonce
    /// row (the caller's own responsibility). Includes one fast-path lock
    /// key read per locked input, in both [`NonceMode`] variants.
    pub(crate) reads: BTreeMap<Vec<u8>, StateRevision>,
    pub(crate) head_reads: Vec<DurableObjectHeadRead>,
    /// State mutations other than the sender-nonce write and any fast-path
    /// lock write: the instantiate/publication record and every created
    /// object's authority row.
    pub(crate) state_mutations: Vec<StateMutationEntry>,
    pub(crate) object_mutations: Vec<DurableObjectMutationEntry>,
    /// Present in both modes: prepare uses its read assertion without writing
    /// the next nonce; direct commit and certificate apply commit the write.
    pub(crate) nonce_write: Option<PendingSenderNonceWrite>,
    /// The fee source plus every application input, in the exact versions
    /// this admission observed and validated: the complete fast-path
    /// exclusive-lock set for this request.
    pub(crate) locked_objects: Vec<ObjectRef>,
}

/// Step 1 (authentication, event digest, request id) plus the DR-0130
/// reserved synthetic request-id rejection, shared unchanged by the direct
/// commit path and both fast-path entry points.
pub(crate) fn authenticate_and_identify(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    signed_bytes: &[u8],
) -> PaidResult<(AuthenticatedPaidIntent, Digest32, RequestId)> {
    let authenticated: AuthenticatedPaidIntent =
        authenticate_paid_intent(resolver, expected, signed_bytes)?;
    local_instance_state::reject_reserved_request_id(&authenticated.intent().request_id)
        .map_err(PaidExecutionAdmissionError::Invalid)?;
    let event_digest: Digest32 = paid_invocation_digest(resolver, authenticated.signed())?;
    let request_id: RequestId = RequestId::new(authenticated.intent().request_id)?;
    Ok((authenticated, event_digest, request_id))
}

/// Translates paid admission's own [`NonceMode`] into the shared
/// [`mutation_fence::LockMode`] every mutation path fences through.
const fn lock_mode(nonce_mode: NonceMode) -> mutation_fence::LockMode {
    match nonce_mode {
        NonceMode::Fresh => mutation_fence::LockMode::Fresh,
        NonceMode::PreparedApply => mutation_fence::LockMode::OwnedByRequest,
    }
}

/// Preserves this module's pre-existing `Invalid(&'static str)` shape for a
/// shared fence's fail-closed rejection message, rather than exposing every
/// caller to the newly shared [`NodeCoreError::PersistenceInvariant`]
/// wrapping: every one of this module's own lock-conflict messages was, and
/// remains, an [`PaidExecutionAdmissionError::Invalid`].
fn fence_lock_result<T>(result: Result<T, NodeCoreError>) -> PaidResult<T> {
    result.map_err(|error| match error {
        NodeCoreError::PersistenceInvariant(message) => {
            PaidExecutionAdmissionError::Invalid(message)
        }
        other => PaidExecutionAdmissionError::Node(other),
    })
}

/// Reads, and validates ownership of, the fast-path lock row for one input
/// object, through the DR-0131 shared fence
/// ([`mutation_fence::fence_object_lock`]). A lock owned by a different
/// request id fails closed: an in-flight prepare's exclusive inputs can
/// never be reused by a direct commit, by a different prepare, or (because
/// ownership binds to the original request id, unaffected by [`NonceMode`])
/// by anything other than that same request's own certificate apply.
/// DR-0132: under [`NonceMode::Fresh`], a lock stamped a strictly older
/// epoch is [`mutation_fence::ObjectLockState::Reclaimable`] rather than a
/// rejection.
#[allow(clippy::too_many_arguments)]
fn check_object_lock<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    object_ref: &ObjectRef,
    current_request_id: &[u8; 32],
    current_epoch: Epoch,
    nonce_mode: NonceMode,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> PaidResult<mutation_fence::ObjectLockState> {
    fence_lock_result(mutation_fence::fence_object_lock(
        store,
        context,
        domain,
        chain,
        object_ref,
        current_request_id,
        current_epoch,
        lock_mode(nonce_mode),
        reads,
    ))
}

/// Reconciles the sender/epoch nonce lock with the admission mode, through
/// the DR-0131 shared fence ([`mutation_fence::fence_sender_nonce_lock`]).
/// Fresh direct/prepare calls require absence; certificate apply requires
/// the exact locally prepared request and nonce. The ordinary nonce row is
/// separately read by `reserve_sender_nonce` and remains unchanged until
/// final apply.
fn check_nonce_lock<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    intent: &PaidIntent,
    nonce_mode: NonceMode,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> PaidResult<()> {
    fence_lock_result(mutation_fence::fence_sender_nonce_lock(
        store,
        context,
        domain,
        intent.context.chain_id(),
        &intent.sender,
        intent.context.epoch(),
        &intent.request_id,
        intent.nonce,
        lock_mode(nonce_mode),
        reads,
    ))
}

/// Steps 2..7 plus the effect-translation half of step 8: authenticated,
/// admitted, executed and translated, but neither committed nor turned into
/// a final receipt. Every one of [`handle_paid_execution`],
/// `crate::fast_path::prepare` and `crate::fast_path::apply` calls this once
/// and assembles its own transaction from the result; none of them
/// duplicates this pipeline.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn build_paid_admission<
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
    engine: &E,
    authenticated: AuthenticatedPaidIntent,
    event_digest: Digest32,
    created_checkpoint: u64,
    nonce_mode: NonceMode,
) -> PaidResult<PaidAdmissionOutput> {
    let intent: &PaidIntent = authenticated.intent();
    let current_request_id: [u8; 32] = intent.request_id;
    // 3. Sender nonce freshness. Prepare only asserts this row and installs a
    //    separate nonce lock; direct commit and certificate apply commit the
    //    returned next-nonce write.
    let layout: PersistenceLayout = PersistenceLayout::new(
        intent.context.chain_id().clone(),
        intent.context.protocol_version(),
    );
    let nonce_write: Option<PendingSenderNonceWrite> =
        Some(durable_reconciliation::reserve_sender_nonce(
            store,
            context,
            domain,
            &layout,
            SenderNonceReservation {
                sender: intent.sender,
                epoch: intent.context.epoch(),
                nonce: intent.nonce,
            },
        )?);
    // 4. Installed profile-four base policy and installed paid fee policy, as
    //    exact stored bytes. A missing or different value fails closed.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    // DR-0131: CAS-fence the committed epoch record and reject a request
    // bound to a non-current epoch before any lock, execution, or mutation.
    // Shared unchanged by the direct commit path and both fast-path entry
    // points, since both call this function.
    mutation_fence::fence_current_epoch(
        store,
        context,
        domain,
        intent.context.chain_id(),
        intent.context.epoch(),
        &mut reads,
    )?;
    check_nonce_lock(store, context, domain, intent, nonce_mode, &mut reads)?;
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

    // 5. One publication budget and one read map span every fee/application
    //    scope and the Publish dependency closure. The pinned fee instance
    //    and its exact code closure are resolved here, before quoting or
    //    consuming the nonce, so the DR-0126 installed ABI/role admission
    //    below always runs against an already-authenticated interface.
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
    // 5b. DR-0126 installed fee ABI/role admission: proves the pinned fee
    //     code's actual `reserve`/`reserve_all`/`settle` exports match every
    //     role the policy claims, before any quote is derived or the nonce
    //     is committed. `PaidFeePolicy`'s own intrinsic decoding
    //     (`validate_paid_fee_policy`) only proves the policy bytes are
    //     self-consistent; it never resolves installed code.
    validate_fee_interface_admission(&fee_scope.interface, fee_policy)?;
    // Checks the signed/base/fee contexts, the signed policy digest, the
    // refund recipient and derives the immutable reservation quote. The engine
    // and the independent verifier both recompute it; none of them trust a
    // caller-supplied price.
    let _quote = quote_paid_intent(&authenticated, resolver, base_policy, fee_policy)?;

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
                encode_signed_paid_intent(authenticated.signed())?.len(),
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

    // 5b. An independent node-core barrier, never delegated to the injectable
    //     `E: PaidContractEngine`. It revalidates the *entire* admitted scope
    //     set against exactly the same required-instance set, cross-protocol/
    //     cross-chain rejection, conflicting-revision, code-node/code-byte
    //     budget and authorization-target-ceiling rules
    //     `execution::execution_scopes` enforces inside the engine boundary
    //     itself, using the same shared public validators. A forged or
    //     buggy engine that skips its own internal call to
    //     `validate_paid_request` therefore still cannot commit a request
    //     whose admitted scopes disagree on context, collide, omit a
    //     required instance, exceed the closure budget, or grant an
    //     authorization target beyond its signed ceiling: the engine's own
    //     validation stays defense in depth, not the sole barrier.
    let mut required_scopes: BTreeSet<([u8; 32], [u8; 32])> = match &intent.application {
        PaidApplication::Call(inner) | PaidApplication::Instantiate(inner) => {
            required_scope_instances(&inner.instance, &intent.authorizations)
        }
        PaidApplication::Publish(_) => BTreeSet::new(),
    };
    required_scopes.insert((fee_policy.instance.creator, fee_policy.instance.seed));
    validate_execution_scope_set(
        resolver,
        base_policy,
        &intent.context,
        &required_scopes,
        &admitted,
    )?;
    if let PaidApplication::Call(inner) | PaidApplication::Instantiate(inner) = &intent.application
    {
        let index: usize = application
            .scope
            .ok_or(PaidExecutionAdmissionError::Invalid("application scope"))?;
        let root: &ResolvedExecutionScope =
            admitted
                .get(index)
                .ok_or(PaidExecutionAdmissionError::Invalid(
                    "application scope not admitted",
                ))?;
        if root.target != inner.instance || root.instance.code != inner.code {
            return invalid("root execution scope");
        }
    }
    validate_authorization_target_scopes(&admitted, &intent.authorizations)?;

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
    let mut object_resolvers: BTreeMap<ObjectId, &HashSuiteResolver> = BTreeMap::new();
    let mut locked_objects: Vec<ObjectRef> = Vec::new();
    // DR-0132 §3.D: a stale (strictly older epoch) lock observed under
    // `NonceMode::Fresh` is reclaimed by emitting a `Delete` for it into
    // `state_mutations` below. `fast_path::prepare` never applies
    // `state_mutations` (it always writes its own fresh `Put` per locked
    // object instead, under the same fenced CAS revision), so this only
    // takes effect for the direct commit path
    // (`handle_paid_execution`); `apply`'s `NonceMode::PreparedApply` never
    // observes `Reclaimable` in the first place. Lock keys are excluded from
    // the fast-path commitment (`commitment::is_excluded_from_commitment`),
    // so this never perturbs a `FastVote`/`FastCertificate` digest.
    let mut reclaimed_lock_keys: Vec<Vec<u8>> = Vec::new();
    for (reference, mode) in &order {
        // Reject a held lock from durable state before any object head/body
        // I/O. Certificate apply additionally proves the lock was acquired
        // by this exact request in this exact committed epoch.
        let lock_state: mutation_fence::ObjectLockState = check_object_lock(
            store,
            context,
            domain,
            intent.context.chain_id(),
            reference,
            &current_request_id,
            intent.context.epoch(),
            nonce_mode,
            &mut reads,
        )?;
        if lock_state == mutation_fence::ObjectLockState::Reclaimable {
            reclaimed_lock_keys.push(fastpath_lock_key(intent.context.chain_id(), reference.id)?);
        }
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
        let digest: Digest32 = match &snapshot.head {
            DurableObjectHead::Current { digest, .. } => *digest,
            _ => return invalid("locked object head not current"),
        };
        locked_objects.push(ObjectRef {
            id: snapshot.object.id,
            version: snapshot.object.version,
            digest,
        });
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
        // DR-0126: select the trusted resolver matching this object's own
        // recorded creating protocol version, never unconditionally the
        // current resolver.
        object_resolvers.insert(
            snapshot.object.id,
            object_snapshots::historical_resolver_for_provenance(
                resolver,
                history,
                snapshot.object.id,
                &snapshot.provenance,
            )?,
        );
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
    let fee_interface: &VerifiedPublicationInterface = admitted
        .get(application.fee_scope)
        .map(|scope| &scope.interface)
        .ok_or(PaidExecutionAdmissionError::Invalid(
            "fee scope not admitted",
        ))?;
    execution::publication::validate_nominal_body(
        fee_interface,
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
        let application_interface: &VerifiedPublicationInterface =
            admitted.get(index).map(|scope| &scope.interface).ok_or(
                PaidExecutionAdmissionError::Invalid("application scope not admitted"),
            )?;
        let binding: BoundObjectSignature<'_> =
            execution::call::bind_call_intent(inner, application_interface)
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
        let ordered_resolvers: Vec<&HashSuiteResolver> = resolved
            .iter()
            .map(|input| {
                object_resolvers.get(&input.object.id).copied().ok_or(
                    PaidExecutionAdmissionError::Invalid(
                        "resolver recorded for every loaded input",
                    ),
                )
            })
            .collect::<PaidResult<Vec<&HashSuiteResolver>>>()?;
        execution::publication::validate_object_input_bodies(
            &binding,
            resolver,
            &ordered_resolvers,
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
            &object_resolvers,
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

    // 8 (translation half). Charged outcomes translate every application and
    //    fee effect; zero-charge phase failures translate nothing.
    let mut state_mutations: Vec<StateMutationEntry> = reclaimed_lock_keys
        .into_iter()
        .map(|key| StateMutationEntry::new(key, StateMutation::Delete))
        .collect::<Result<_, RuntimeError>>()?;
    let object_mutations: Vec<DurableObjectMutationEntry> =
        if let Some(charged) = outcome.result.charged.as_ref() {
            for created in &outcome.created_authorities {
                if created.authority.ty == fee_policy.reservation_type {
                    return invalid("surviving reservation authority");
                }
            }
            if !success {
                validate_application_failed_footprint(
                    &outcome.result.effects,
                    &outcome.created_authorities,
                    charged,
                    &source_input.resolved.object,
                    source_mode,
                )?;
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
                &mut state_mutations,
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
            let created_instance: &InstanceRecord =
                admitted.get(index).map(|scope| &scope.instance).ok_or(
                    PaidExecutionAdmissionError::Invalid("instantiate scope not admitted"),
                )?;
            state_mutations.push(StateMutationEntry::new(
                key,
                StateMutation::Put(encode_instance_record(created_instance)?),
            )?);
        }
        if let Some(key) = application.publication_key {
            // The complete canonical signed paid frame is the durable record.
            let record: Vec<u8> = encode_signed_paid_intent(authenticated.signed())?;
            state_mutations.push(StateMutationEntry::new(key, StateMutation::Put(record))?);
        }
    }
    budget.merge_reads(&mut reads)?;

    Ok(PaidAdmissionOutput {
        event_digest,
        outcome,
        result_bytes,
        success,
        reads,
        head_reads,
        state_mutations,
        object_mutations,
        nonce_write,
        locked_objects,
    })
}

/// Authenticates and reconciles one paid invocation before any nonce, policy,
/// code, object, or blob read.
pub fn preflight_paid_execution<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    signed_bytes: &[u8],
) -> PaidResult<PaidExecutionPreflight> {
    let (authenticated, event_digest, request_id) =
        authenticate_and_identify(resolver, expected, signed_bytes)?;
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
    {
        return Ok(PaidExecutionPreflight::Replayed { request_id, output });
    }
    Ok(PaidExecutionPreflight::Fresh(FreshPaidExecution {
        authenticated,
        event_digest,
        request_id,
    }))
}

/// Admits and durably commits a fresh invocation returned by
/// [`preflight_paid_execution`].
///
/// The private fields of [`FreshPaidExecution`] preserve the exact
/// authenticated request and digest across the adapter's current-policy
/// lookup without repeating authentication or replay reconciliation.
#[allow(clippy::too_many_arguments)]
pub fn handle_preflighted_paid_execution<
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
    engine: &E,
    fresh: FreshPaidExecution,
    created_checkpoint: u64,
) -> PaidResult<NodeOutput> {
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return invalid("resolver history bound");
    }
    let FreshPaidExecution {
        authenticated,
        event_digest,
        request_id,
    } = fresh;
    let admission: PaidAdmissionOutput = build_paid_admission(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        base_policy,
        fee_policy,
        engine,
        authenticated,
        event_digest,
        created_checkpoint,
        NonceMode::Fresh,
    )?;
    commit_direct_paid_admission(store, context, domain, request_id, event_digest, admission)
}

/// Authenticates, admits and durably commits one paid invocation.
///
/// `expected` is the caller's trusted execution context; `base_policy` and
/// `fee_policy` are the caller's trusted expected records, each of which must
/// equal the installed durable bytes exactly. `Err` before the engine runs
/// writes nothing and consumes no nonce.
#[allow(clippy::too_many_arguments)]
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
    match preflight_paid_execution(store, context, domain, resolver, expected, signed_bytes)? {
        PaidExecutionPreflight::Replayed { output, .. } => Ok(output),
        PaidExecutionPreflight::Fresh(fresh) => handle_preflighted_paid_execution(
            store,
            blob_store,
            context,
            domain,
            resolver,
            history,
            base_policy,
            fee_policy,
            engine,
            fresh,
            created_checkpoint,
        ),
    }
}

fn commit_direct_paid_admission<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_id: RequestId,
    event_digest: Digest32,
    admission: PaidAdmissionOutput,
) -> PaidResult<NodeOutput> {
    let PaidAdmissionOutput {
        result_bytes,
        success,
        mut reads,
        head_reads,
        mut state_mutations,
        object_mutations,
        nonce_write,
        ..
    } = admission;
    let nonce: PendingSenderNonceWrite = nonce_write.ok_or(
        PaidExecutionAdmissionError::Invalid("direct commit always reserves a fresh nonce"),
    )?;
    reads.insert(nonce.key.clone(), nonce.read_revision);
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let state: DurableStateTransaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        state_mutations,
    )?;
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
        DurableRequestId::new(*request_id.as_bytes())
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
