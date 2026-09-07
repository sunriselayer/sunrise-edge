//! Fenced local execution. Engine output is a proposal, never authority.
use super::*;
use execution::local_execution::*;
use execution::publication::{
    PublicationContext, UnverifiedDependencyRef, VerifiedPublicationInterface,
};
#[cfg(test)]
use local_instance_state::execution_policy_key;
use local_instance_state::{
    execution_policy_key_for_profile, instance_record_key, object_authority_key,
};
use publication::{
    PublicationAdmissionError, VerifiedDurablePublication, load_verified_publication,
};
mod effects;
mod scopes;
#[cfg(test)]
mod tests;

/// Fail-closed admission errors. These do not consume a sender nonce.
#[derive(Debug)]
pub enum LocalExecutionAdmissionError {
    /// Storage, conflict, or node boundary failure.
    Node(NodeCoreError),
    /// Invalid signed execution or engine result.
    Execution(LocalExecutionError),
    /// Invalid durable publication closure.
    Publication(PublicationAdmissionError),
    /// Policy or authority invariant failed.
    Invalid(&'static str),
}
impl fmt::Display for LocalExecutionAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(e) => e.fmt(f),
            Self::Execution(e) => e.fmt(f),
            Self::Publication(e) => e.fmt(f),
            Self::Invalid(s) => f.write_str(s),
        }
    }
}
impl Error for LocalExecutionAdmissionError {}
macro_rules! conversion {
    ($source:ty,$variant:ident) => {
        impl From<$source> for LocalExecutionAdmissionError {
            fn from(e: $source) -> Self {
                Self::$variant(e.into())
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
conversion!(PublicationAdmissionError, Publication);
type AdmissionResult<T> = Result<T, LocalExecutionAdmissionError>;

fn original_resolver<'a>(
    current: &'a HashSuiteResolver,
    history: &'a [HashSuiteResolver],
    context: &PublicationContext,
) -> AdmissionResult<&'a HashSuiteResolver> {
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return Err(LocalExecutionAdmissionError::Invalid(
            "resolver history bound",
        ));
    }
    std::iter::once(current)
        .chain(history)
        .find(|r| {
            r.chain_id() == context.chain_id() && r.protocol_version() == context.protocol_version()
        })
        .ok_or(LocalExecutionAdmissionError::Invalid(
            "trusted historical resolver unavailable",
        ))
}
fn reference_matches(
    reference: &UnverifiedDependencyRef,
    interface: &VerifiedPublicationInterface,
) -> bool {
    let request = interface.candidate().request();
    reference.origin() == request.artifact().origin()
        && reference.context() == request.artifact().context()
        && reference.revision() == request.artifact().revision()
        && reference.artifact_digest() == request.artifact_digest()
}
fn validate_closure(
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    interface: &VerifiedPublicationInterface,
) -> AdmissionResult<()> {
    for candidate in std::iter::once(interface.candidate()).chain(interface.dependencies()) {
        let artifact = candidate.request().artifact();
        let historical: &HashSuiteResolver =
            original_resolver(resolver, history, artifact.context())?;
        let expected = match artifact.wasm_profile() {
            2 => local_execution_semantics(historical, artifact.context()),
            3 => general_execution_semantics(historical, artifact.context()),
            _ => {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "non-executable publication profile",
                ));
            }
        }
        .map_err(LocalExecutionError::from)?;
        if artifact.semantics() != &expected {
            return Err(LocalExecutionAdmissionError::Invalid(
                "non-executable publication semantics",
            ));
        }
    }
    Ok(())
}
fn read_state<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: Vec<u8>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> AdmissionResult<VersionedStateValue> {
    let value: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(old) = reads.insert(key, value.revision())
        && old != value.revision()
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(value)
}
fn validate_authority(
    authority: &ObjectAuthority,
    instance: &InstanceRecord,
    target: &execution::call::InstanceTarget,
    interface: &VerifiedPublicationInterface,
) -> AdmissionResult<()> {
    if &authority.instance != target
        || authority.instance_context != instance.context
        || authority.ty.origin() != authority.code.origin()
    {
        return Err(LocalExecutionAdmissionError::Invalid(
            "foreign object authority",
        ));
    }
    let view: VerifiedPublicationInterface = interface
        .for_origin(authority.code.origin())
        .map_err(|_| LocalExecutionAdmissionError::Invalid("authority code outside closure"))?;
    if !reference_matches(&authority.code, &view) {
        return Err(LocalExecutionAdmissionError::Invalid(
            "authority exact code mismatch",
        ));
    }
    Ok(())
}

/// Verifies immutable instance selectors, original context and complete code closure.
#[allow(clippy::too_many_arguments)]
pub fn query_local_instance<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    chain: &ChainId,
    creator: [u8; 32],
    seed: [u8; 32],
) -> AdmissionResult<Option<InstanceRecord>> {
    if chain != resolver.chain_id() {
        return Err(LocalExecutionAdmissionError::Invalid(
            "instance query chain",
        ));
    }
    let key: Vec<u8> = instance_record_key(chain, &creator, &seed)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    let Some(bytes) = observed.value() else {
        return if observed.revision() == StateRevision::INITIAL {
            Ok(None)
        } else {
            Err(LocalExecutionAdmissionError::Invalid("tombstoned instance"))
        };
    };
    let record: InstanceRecord = decode_instance_record(bytes)?;
    if record.context.chain_id() != chain
        || record.creator != creator
        || record.seed != seed
        || encode_instance_record(&record)? != bytes
    {
        return Err(LocalExecutionAdmissionError::Invalid(
            "instance selector mismatch",
        ));
    }
    instance_target(
        original_resolver(resolver, history, &record.context)?,
        &record,
    )?;
    let loaded: VerifiedDurablePublication = load_verified_publication(
        store,
        context,
        domain,
        resolver,
        history,
        record.code.origin(),
    )?
    .ok_or(LocalExecutionAdmissionError::Invalid(
        "instance code absent",
    ))?;
    validate_closure(resolver, history, &loaded.interface)?;
    if !reference_matches(&record.code, &loaded.interface)
        || loaded
            .interface
            .executable_abi(record.code.origin())
            .and_then(|a| a.initializer.as_ref())
            != Some(&record.initializer)
    {
        return Err(LocalExecutionAdmissionError::Invalid(
            "instance code mismatch",
        ));
    }
    Ok(Some(record))
}

/// Authenticates then reconciles replay before any application reads. New requests
/// atomically commit objects, immutable authority, nonce and receipt, with no outbox.
#[allow(clippy::too_many_arguments)]
pub fn handle_local_execution<
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    policy: &LocalExecutionPolicy,
    engine: &E,
    signed_bytes: &[u8],
    created_checkpoint: u64,
) -> AdmissionResult<NodeOutput> {
    let authenticated: AuthenticatedLocalExecutionIntent =
        authenticate_local_execution(resolver, policy, signed_bytes)?;
    let intent: &LocalExecutionIntent = authenticated.intent();
    let call = &intent.call;
    let event_digest: Digest32 = local_execution_event_digest(resolver, authenticated.signed())?;
    let request_id: RequestId = RequestId::new(call.request_id)?;
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
    {
        return Ok(output);
    }
    let layout: PersistenceLayout = PersistenceLayout::new(
        call.context.chain_id().clone(),
        call.context.protocol_version(),
    );
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce(
        store,
        context,
        domain,
        &layout,
        SenderNonceReservation {
            sender: call.sender,
            epoch: call.context.epoch(),
            nonce: call.nonce,
        },
    )?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let observed: VersionedStateValue = read_state(
        store,
        context,
        domain,
        execution_policy_key_for_profile(policy.context(), policy.profile())?,
        &mut reads,
    )?;
    if observed.value() != Some(policy.encode()?.as_slice()) {
        return Err(LocalExecutionAdmissionError::Invalid(
            "execution policy absent or different",
        ));
    }
    let mut publication_budget: publication::PublicationLoadBudget =
        publication::PublicationLoadBudget::default();
    let loaded: VerifiedDurablePublication = publication::load_verified_publication_with_budget(
        store,
        context,
        domain,
        resolver,
        history,
        call.code.origin(),
        &mut publication_budget,
    )?
    .ok_or(LocalExecutionAdmissionError::Invalid("code absent"))?;
    validate_closure(resolver, history, &loaded.interface)?;
    if !reference_matches(&call.code, &loaded.interface) {
        return Err(LocalExecutionAdmissionError::Invalid("exact code mismatch"));
    }
    for assertion in loaded.reads {
        if let Some(old) = reads.insert(assertion.key().to_vec(), assertion.expected_revision())
            && old != assertion.expected_revision()
        {
            return Err(NodeCoreError::StateConflict.into());
        }
    }
    let interface: VerifiedPublicationInterface = loaded.interface;
    let binding = bind_local_execution(&authenticated, &interface)?;
    let key: Vec<u8> = instance_record_key(
        call.context.chain_id(),
        &call.instance.creator,
        &call.instance.seed,
    )?;
    let instance_observed: VersionedStateValue =
        read_state(store, context, domain, key.clone(), &mut reads)?;
    let instance: InstanceRecord = match intent.mode {
        LocalExecutionMode::Instantiate => {
            if instance_observed.value().is_some()
                || instance_observed.revision() != StateRevision::INITIAL
            {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "instance already reserved",
                ));
            }
            InstanceRecord {
                context: call.context.clone(),
                creator: call.sender,
                seed: call.instance.seed,
                code: call.code.clone(),
                revision: 1,
                initializer: call.entrypoint.clone(),
            }
        }
        LocalExecutionMode::Call => decode_instance_record(
            instance_observed
                .value()
                .ok_or(LocalExecutionAdmissionError::Invalid("instance absent"))?,
        )?,
    };
    let instance_resolver: &HashSuiteResolver =
        original_resolver(resolver, history, &instance.context)?;
    if instance.code != call.code
        || instance.context.protocol_version() != call.context.protocol_version()
        || instance.context.epoch() > call.context.epoch()
        || instance.context.chain_id() != call.context.chain_id()
        || instance_target(instance_resolver, &instance)? != call.instance
        || interface
            .executable_abi(call.code.origin())
            .and_then(|a| a.initializer.as_ref())
            != Some(&instance.initializer)
    {
        return Err(LocalExecutionAdmissionError::Invalid(
            "instance authority mismatch",
        ));
    }
    let mut inputs: Vec<ScopedResolvedObject> = Vec::new();
    // Historical records remain readable and exact receipts remain replayable;
    // this immutable execution profile does not activate cross-version migration.
    if std::iter::once(interface.candidate())
        .chain(interface.dependencies())
        .any(|candidate| {
            candidate.request().artifact().context().protocol_version()
                != call.context.protocol_version()
        })
    {
        return Err(LocalExecutionAdmissionError::Invalid(
            "cross-version execution requires explicit migration",
        ));
    }
    let scopes: Vec<ResolvedExecutionScope> = scopes::admit(
        store,
        context,
        domain,
        resolver,
        history,
        policy,
        &authenticated,
        ResolvedExecutionScope {
            instance: instance.clone(),
            target: call.instance.clone(),
            interface: interface.clone(),
        },
        &mut reads,
        &mut publication_budget,
    )?;
    let mut snapshots: BTreeMap<ObjectId, object_snapshots::ObjectSnapshot> = BTreeMap::new();
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut total_bytes: usize = 0;
    for (entry, param) in call.access.entries.iter().zip(binding.objects()) {
        let snapshot: object_snapshots::ObjectSnapshot = object_snapshots::load_object_snapshot(
            store,
            blob_store,
            context,
            domain,
            call.context.chain_id(),
            &entry.object_ref,
            &mut total_bytes,
        )?;
        if snapshot.object.owner != Owner::Address(Address::new(call.sender)) {
            return Err(LocalExecutionAdmissionError::Invalid(
                "local inputs require sender address ownership",
            ));
        }
        let observed: VersionedStateValue = read_state(
            store,
            context,
            domain,
            object_authority_key(snapshot.object.id),
            &mut reads,
        )?;
        let authority: ObjectAuthority = decode_object_authority(observed.value().ok_or(
            LocalExecutionAdmissionError::Invalid("object authority absent"),
        )?)?;
        let scope: &ResolvedExecutionScope = scopes::for_authority(&scopes, &authority)?;
        validate_authority(&authority, &scope.instance, &scope.target, &scope.interface)?;
        if authority.object_id != snapshot.object.id || &authority.ty != param.ty() {
            return Err(LocalExecutionAdmissionError::Invalid(
                "object authority type mismatch",
            ));
        }
        head_reads.push(DurableObjectHeadRead::new(
            snapshot.object.id,
            snapshot.head.clone(),
        ));
        inputs.push(ScopedResolvedObject {
            resolved: ResolvedObject {
                object: snapshot.object.clone(),
                mode: entry.mode,
            },
            authority,
        });
        if snapshots.insert(snapshot.object.id, snapshot).is_some() {
            return Err(LocalExecutionAdmissionError::Invalid("duplicate object"));
        }
    }
    let resolved: Vec<ResolvedObject> = inputs.iter().map(|i| i.resolved.clone()).collect();
    execution::publication::validate_object_input_bodies(
        &binding,
        resolver,
        call.context.epoch(),
        &call.access,
        &resolved,
    )
    .map_err(|_| LocalExecutionAdmissionError::Invalid("input body mismatch"))?;
    scopes::validate_inputs(&authenticated, &scopes, &inputs, resolver)?;
    let outcome: LocalExecutionOutcome = engine.execute(LocalExecutionRequest {
        scopes: &scopes,
        intent: &authenticated,
        resolver,
        policy,
        event_digest,
        inputs: &inputs,
    })?;
    let result: LocalExecutionResult = LocalExecutionResult {
        request_id: call.request_id,
        instance: instance.clone(),
        mode: intent.mode,
        effects: outcome.effects.clone(),
    };
    validate_local_execution_result(resolver, instance_resolver, authenticated.signed(), &result)?;
    let result_bytes: Vec<u8> = encode_local_execution_result(&result)?;
    let success: bool = outcome.effects.status == ExecutionStatus::Success;
    if !success && !outcome.created_authorities.is_empty() {
        return Err(LocalExecutionAdmissionError::Invalid(
            "trapped creation authority",
        ));
    }
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    let object_mutations: Vec<DurableObjectMutationEntry> = effects::translate(
        store,
        context,
        domain,
        resolver,
        &scopes,
        &authenticated,
        created_checkpoint,
        &inputs,
        &snapshots,
        &outcome,
        &mut reads,
        &mut head_reads,
        &mut mutations,
    )?;
    if success && intent.mode == LocalExecutionMode::Instantiate {
        mutations.push(StateMutationEntry::new(
            key,
            StateMutation::Put(encode_instance_record(&instance)?),
        )?);
    }
    reads.insert(nonce.key.clone(), nonce.read_revision);
    mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(k, r)| StateReadAssertion::new(k, r))
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
        DurableRequestId::new(call.request_id)
            .map_err(|_| LocalExecutionAdmissionError::Invalid("request id"))?,
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
