//! Private ordered execution and exact retained registration-root validation.
use super::*;
use crate::admission_profile::fence_verified_admission_profile;
use crate::ordered_economics::{
    OrderedCandidate, OrderedEconomicsEnvironment, OrderedEconomicsPolicy,
};
use abi::call_values::CallValue;
use execution::ObjectEffect;
use runtime::VersionedStateReader;

fn record_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    value: &VersionedStateValue,
) -> Result<(), BondRegistrationError> {
    if reads
        .insert(key, value.revision())
        .is_some_and(|revision| revision != value.revision())
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

/// A fully authenticated registered root can be inspected without granting
/// any execution, membership or live signing authority. Later transition
/// records use the unchanged old chain walker, rooted in this signed row.
pub fn verify_registered_bond_chain<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    root: &crate::genesis::VerifiedGenesisRoot,
    history: &[HashSuiteResolver],
    validator_id: ValidatorId,
) -> Result<FastPathBondRecord, BondRegistrationError> {
    let scope: RegistrationScope<'_> = RegistrationScope::for_genesis(root);
    let leg_policy: LocalExecutionPolicy = scope.leg_policy();
    verify_chain(
        store,
        context,
        domain,
        history,
        &scope,
        &leg_policy,
        validator_id,
    )
}

/// The committed anchor of `validator_id` in Existing mode under `scope`,
/// whose live context the anchor context must equal, then its unchanged
/// bond chain. Public routes use the genesis scope; same-epoch registrant
/// owner resolution uses the policy scope.
pub(crate) fn verify_chain<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    history: &[HashSuiteResolver],
    scope: &RegistrationScope<'_>,
    leg_policy: &LocalExecutionPolicy,
    validator_id: ValidatorId,
) -> Result<FastPathBondRecord, BondRegistrationError> {
    let resolver: &HashSuiteResolver = scope.resolver;
    let chain: &ChainId = scope.live_context().chain_id();
    let key: Vec<u8> = bond_registration_anchor_key(chain, &validator_id)?;
    let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
    let anchor: BondRegistrationAnchor = decode_bond_registration_anchor(observed.value().ok_or(
        BondRegistrationError::Prerequisite("registration anchor missing"),
    )?)?;
    authenticate_anchor(scope, leg_policy, &anchor, validator_id)?;
    let first_transition: Vec<u8> =
        local_instance_state::fastpath_bond_transition_key(chain, &validator_id, 1)?;
    let first: VersionedStateValue =
        store.read_versioned_state(context, domain, &first_transition)?;
    if first.value().is_some() || first.revision() != StateRevision::INITIAL {
        return Err(BondRegistrationError::Prerequisite(
            "registration generation-one transition slot is not pristine",
        ));
    }
    let bond_key: Vec<u8> = local_instance_state::fastpath_bond_record_key(chain, &validator_id)?;
    crate::genesis::verify_fastpath_bond_chain(
        store,
        context,
        domain,
        resolver,
        history,
        &bond_key,
        &anchor.resulting_row,
    )
    .map_err(|_| BondRegistrationError::Prerequisite("registered bond chain missing or corrupt"))?;
    let installed: VersionedStateValue = store.read_versioned_state(context, domain, &bond_key)?;
    Ok(decode_fastpath_bond_record(installed.value().ok_or(
        BondRegistrationError::Prerequisite("registered current bond missing"),
    )?)?)
}

/// The one Existing-mode authentication of a committed anchor: its signed
/// envelope, natural identity, independently validated generation-one row
/// and that row's signed digest. Shared by [`verify_chain`] and the DR-0191
/// owner registry so the two cannot drift. Reads nothing.
fn authenticate_anchor(
    scope: &RegistrationScope<'_>,
    leg_policy: &LocalExecutionPolicy,
    anchor: &BondRegistrationAnchor,
    validator_id: ValidatorId,
) -> Result<(SignedBondRegistrationIntent, FastPathBondRecord), BondRegistrationError> {
    let resolver: &HashSuiteResolver = scope.resolver;
    let economics: &FastPathEconomicsPolicy = scope.economics();
    let (signed, leg) = authenticate_registration(
        scope,
        RegistrationMode::Existing(anchor),
        leg_policy,
        &anchor.signed_registration,
    )?;
    if anchor.context != *scope.live_context()
        || anchor.validator_id != validator_id
        || signed.intent.validator_id != validator_id
        || signed.intent.context != anchor.context
    {
        return Err(BondRegistrationError::Prerequisite(
            "registration anchor natural identity differs",
        ));
    }
    let root: FastPathBondRecord = decode_fastpath_bond_record(&anchor.resulting_row)?;
    validate_initial_row(
        &signed.intent,
        &root,
        &leg,
        initial_resource(economics, &signed.intent)?,
    )?;
    if bond_row_digest(resolver, root.lifecycle_epoch, &anchor.resulting_row)?
        != signed.intent.expected_initial_row_digest
    {
        return Err(BondRegistrationError::Prerequisite(
            "registration anchor resulting digest differs",
        ));
    }
    Ok((signed, root))
}

/// DR-0191 Section 2 owner provenance of one committed registration anchor,
/// recomputed from the anchor bytes alone. Never a membership stand-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegisteredOwnerIdentity {
    pub(crate) validator_id: ValidatorId,
    pub(crate) key: [u8; 32],
    pub(crate) anchor_epoch: Epoch,
    pub(crate) intent_digest: Digest32,
    pub(crate) initial_row_digest: Digest32,
}

/// Existing-mode identity of one committed anchor at its own epoch: the
/// genesis scope at e_0, otherwise the verified committee and owner history
/// at the anchor epoch. Exactly the anchor half of
/// [`verify_registered_bond_chain`], without any store read, because the
/// owner registry must not depend on later transitions of the same bond.
pub(crate) fn verify_registration_identity(
    root: &crate::genesis::VerifiedGenesisRoot,
    history: Option<(
        &crate::serving_authority::VerifiedCommitteeHistory,
        &crate::serving_authority::VerifiedOwnerRegistry,
    )>,
    anchor_bytes: &[u8],
) -> Result<RegisteredOwnerIdentity, BondRegistrationError> {
    let anchor: BondRegistrationAnchor = decode_bond_registration_anchor(anchor_bytes)?;
    let scope: RegistrationScope<'_> = match history {
        Some((committees, owners)) => {
            RegistrationScope::for_epoch(root, committees, owners, anchor.context.epoch())?
        }
        None => RegistrationScope::for_genesis(root),
    };
    let leg_policy: LocalExecutionPolicy = scope.leg_policy();
    let (signed, _row): (SignedBondRegistrationIntent, FastPathBondRecord) =
        authenticate_anchor(&scope, &leg_policy, &anchor, anchor.validator_id)?;
    Ok(RegisteredOwnerIdentity {
        validator_id: signed.intent.validator_id,
        key: signed.intent.authorization_key,
        anchor_epoch: anchor.context.epoch(),
        intent_digest: bond_registration_intent_digest(root.genesis_resolver(), &signed.intent)?,
        initial_row_digest: signed.intent.expected_initial_row_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn require_pristine<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    history: &[HashSuiteResolver],
    policy: &OrderedEconomicsPolicy,
    leg_policy: &LocalExecutionPolicy,
    intent: &BondRegistrationIntent,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), BondRegistrationError> {
    let chain: &ChainId = intent.context.chain_id();
    let bond_key: Vec<u8> =
        local_instance_state::fastpath_bond_record_key(chain, &intent.validator_id)?;
    let anchor_key: Vec<u8> = bond_registration_anchor_key(chain, &intent.validator_id)?;
    let transition_key: Vec<u8> =
        local_instance_state::fastpath_bond_transition_key(chain, &intent.validator_id, 1)?;
    let bond: VersionedStateValue = store.read_versioned_state(context, domain, &bond_key)?;
    let anchor: VersionedStateValue = store.read_versioned_state(context, domain, &anchor_key)?;
    let transition: VersionedStateValue =
        store.read_versioned_state(context, domain, &transition_key)?;
    record_read(reads, bond_key, &bond)?;
    record_read(reads, anchor_key, &anchor)?;
    record_read(reads, transition_key, &transition)?;
    if transition.value().is_some() || transition.revision() != StateRevision::INITIAL {
        return Err(BondRegistrationError::Prerequisite(
            "registration initial transition slot was previously written",
        ));
    }
    match (bond.value(), anchor.value()) {
        (None, None)
            if bond.revision() == StateRevision::INITIAL
                && anchor.revision() == StateRevision::INITIAL =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => {
            let scope: RegistrationScope<'_> = RegistrationScope::for_policy(policy)?;
            verify_chain(
                store,
                context,
                domain,
                history,
                &scope,
                leg_policy,
                intent.validator_id,
            )?;
            Err(BondRegistrationError::Refused(
                BondRegistrationRefusal::AlreadyRegistered,
            ))
        }
        _ => Err(BondRegistrationError::Prerequisite(
            "registration bond or anchor is partial, deleted or noninitial",
        )),
    }
}

/// Owning preflight; exact reads are also captured by the ordered observation
/// scope. Refusal never authorizes overwriting a registered root.
pub(crate) fn preflight_registration<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), BondRegistrationError> {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    verify_registration_admission(store, context, env, candidate, &mut reads)
}

/// Owning pristine-slot observations join fresh signing's exact CAS. A
/// healthy existing registered root remains a prefix-derived refusal, never
/// a tombstone/noninitial absence silently reused as a fresh identity.
pub(crate) fn verify_registration_admission<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), BondRegistrationError> {
    let scope: RegistrationScope<'_> = RegistrationScope::for_policy(env.policy)?;
    let (signed, _) = authenticate_registration(
        &scope,
        RegistrationMode::Admit,
        env.leg_policy,
        &candidate.intent,
    )?;
    require_pristine(
        store,
        context,
        env.policy.domain(),
        env.history,
        env.policy,
        env.leg_policy,
        &signed.intent,
        reads,
    )
}

fn validate_effects(
    admitted: &AdmittedLeg,
    source: ObjectId,
    owner_before: &Owner,
    owner_after: &Owner,
    minimum: logical_generation::ObjectMinimum,
) -> Result<(Object, u64), BondRegistrationError> {
    if !admitted.success || admitted.effects.status != ExecutionStatus::Success {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::Trapped,
        ));
    }
    if !admitted.created_authorities.is_empty() || !admitted.effects.events.is_empty() {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::ForbiddenEffects,
        ));
    }
    let snapshot = admitted
        .snapshots
        .get(&source)
        .ok_or(BondRegistrationError::Prerequisite(
            "registration source snapshot missing",
        ))?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == source)
        .ok_or(BondRegistrationError::Prerequisite(
            "registration source authority missing",
        ))?;
    if snapshot.object.owner != *owner_before || !minimum.admits(snapshot.created_checkpoint) {
        return Err(BondRegistrationError::Prerequisite(
            "registration source owner or generation differs",
        ));
    }
    let expected_version: u64 =
        snapshot
            .object
            .version
            .checked_add(1)
            .ok_or(BondRegistrationError::Prerequisite(
                "registration object version overflow",
            ))?;
    let [
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        },
    ] = admitted.effects.object_effects.as_slice()
    else {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::ForbiddenEffects,
        ));
    };
    if *previous_version != snapshot.object.version
        || new_object.id != source
        || new_object.version != expected_version
        || new_object.type_hash != snapshot.object.type_hash
        || new_object.schema_version != snapshot.object.schema_version
        || new_object.data != snapshot.object.data
        || new_object.owner != *owner_after
    {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::ForbiddenEffects,
        ));
    }
    // An undecodable input body is missing healthy producer material, not a
    // caller-invalid amount. The output body is already byte-exact input.
    let value: CallValue = execution::publication::observe_nominal_value(
        &admitted.interface,
        &input.authority.ty,
        snapshot.object.schema_version,
        &snapshot.object.data,
    )
    .map_err(|_| BondRegistrationError::Prerequisite("registration nominal input body corrupt"))?;
    let amount: u64 = match value {
        CallValue::U64(amount) if amount > 0 => amount,
        _ => {
            return Err(BondRegistrationError::Refused(
                BondRegistrationRefusal::InvalidAmount,
            ));
        }
    };
    Ok((new_object.clone(), amount))
}

/// Only the committed ordered dispatcher obtains the precise reservation
/// capability. There is deliberately no public standalone writer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_bond_registration_ordered<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    ordered: Option<&ordered_economics::OrderedLegAdmission<'_>>,
) -> Result<InvocationPreparation, BondRegistrationError> {
    let policy: &OrderedEconomicsPolicy = env.policy;
    let domain: AtomicityDomainId = policy.domain();
    let scope: RegistrationScope<'_> = RegistrationScope::for_policy(policy)?;
    let (profile, economics): (&VerifiedAdmissionProfile, &FastPathEconomicsPolicy) =
        (scope.profile(), scope.economics());
    let (signed, leg) = authenticate_registration(
        &scope,
        RegistrationMode::Admit,
        env.leg_policy,
        &candidate.intent,
    )?;
    let intent: &BondRegistrationIntent = &signed.intent;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(BondRegistrationError::Invalid(
            "registration candidate identity differs",
        ));
    }
    let request: RequestId = RequestId::new(intent.request_id)?;
    let event: Digest32 =
        bond_registration_receipt_digest(env.resolver(), &intent.context, &candidate.intent)?;
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request, event)?
    {
        return Ok(InvocationPreparation::Retained(output));
    }
    let admission = ordered
        .filter(|admission| admission.request_id == intent.request_id)
        .ok_or(BondRegistrationError::Prerequisite(
            "registration requires committed ordered admission",
        ))?;
    let mut configuration: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    mutation_fence::fence_direct_or_ordered_writer(
        store,
        context,
        domain,
        policy.context(),
        &intent.request_id,
        Some(admission),
        &mut configuration,
    )?;
    fence_verified_admission_profile(store, context, domain, profile, &mut configuration)?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch = mutation_fence::fence_current_epoch(
        store,
        context,
        domain,
        intent.context.chain_id(),
        intent.context.epoch(),
        &mut reads,
    )?;
    let current: ValidatorSet = fast_path::load_validator_set(
        store,
        context,
        domain,
        env.resolver(),
        &intent.context,
        &epoch,
        &mut reads,
    )
    .map_err(|_| {
        BondRegistrationError::Prerequisite("registration live validator set unavailable")
    })?;
    if current.get(intent.validator_id).is_some() {
        return Err(BondRegistrationError::Prerequisite(
            "registration identity is already in current committee",
        ));
    }
    require_pristine(
        store,
        context,
        domain,
        env.history,
        policy,
        env.leg_policy,
        intent,
        &mut reads,
    )?;
    let policy_key: Vec<u8> =
        local_instance_state::fastpath_economics_policy_key(&intent.resource_context)?;
    let installed: VersionedStateValue =
        store.read_versioned_state(context, domain, &policy_key)?;
    record_read(&mut reads, policy_key, &installed)?;
    let actual_economics: FastPathEconomicsPolicy =
        decode_fastpath_economics_policy(installed.value().ok_or(
            BondRegistrationError::Prerequisite("registration economics policy missing"),
        )?)?;
    if actual_economics != *economics {
        return Err(BondRegistrationError::Prerequisite(
            "registration economics policy differs from signed genesis",
        ));
    }
    let resource: &FastPathEconomicsResourcePolicy = initial_resource(economics, intent)?;
    let config: &BondResourceConfig =
        resource
            .bond
            .as_ref()
            .ok_or(BondRegistrationError::Prerequisite(
                "registration bond policy absent",
            ))?;
    let scope: ProtocolCustodyScope = custody_scope(
        &intent.resource_context,
        intent.validator_id,
        *intent.resource.value(),
    );
    let (capability, source, leg_event) = deposit_capability(
        env.resolver(),
        &intent.context,
        resource,
        scope.clone(),
        &leg,
    )
    .map_err(|_| BondRegistrationError::Prerequisite("registration custody capability failed"))?;
    let call = &leg.intent().call;
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce_range(
        store,
        context,
        domain,
        &PersistenceLayout::new(
            intent.context.chain_id().clone(),
            intent.context.protocol_version(),
        ),
        SenderNonceReservation {
            sender: call.sender,
            epoch: intent.context.epoch(),
            nonce: call.nonce,
        },
        1,
    )?;
    let installed_profile = logical_generation::fence_commitment_profile(
        store,
        context,
        domain,
        intent.context.chain_id(),
        &mut reads,
    )?;
    let logical_generation::InstalledCommitmentProfile::Logical(profile_record) =
        &installed_profile
    else {
        return Err(BondRegistrationError::Prerequisite(
            "registration requires logical generation provenance",
        ));
    };
    let generation_scope: logical_generation::GenerationScope =
        admission.gate.generation_scope(profile_record);
    let minimum = logical_generation::ObjectMinimum::for_scope(
        &installed_profile,
        candidate.created_checkpoint,
        &generation_scope,
    )?;
    let mut heads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    let admitted: AdmittedLeg = admit_and_execute_leg(
        store,
        env.blobs,
        context,
        domain,
        env.resolver(),
        env.history,
        env.leg_policy,
        env.engine,
        &leg,
        leg_event,
        Some(&capability),
        CustodyEffectMode::CallerValidated,
        candidate.created_checkpoint,
        &mut reads,
        &mut heads,
        &mut mutations,
        Some(admission),
    )?;
    let (object, amount) = validate_effects(
        &admitted,
        source,
        &Owner::Address(Address::new(call.sender)),
        &Owner::ProtocolCustody(scope),
        minimum,
    )?;
    if !config.enabled || amount < config.min_bond.get() {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::BelowMinimum,
        ));
    }
    if config
        .max_validator_exposure
        .is_some_and(|maximum| amount > maximum.get())
    {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::AboveMaximum,
        ));
    }
    let snapshot = admitted
        .snapshots
        .get(&source)
        .ok_or(BondRegistrationError::Prerequisite(
            "registration source missing after execution",
        ))?;
    let (object_mutation, digest) = effects::build_mutation_entry(
        env.resolver(),
        &intent.context,
        candidate.created_checkpoint,
        snapshot,
        &object,
    )
    .map_err(|_| {
        BondRegistrationError::Prerequisite("registration custody mutation construction")
    })?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == source)
        .ok_or(BondRegistrationError::Prerequisite(
            "registration admitted authority absent",
        ))?;
    let slashable_from: u64 =
        intent
            .context
            .epoch()
            .get()
            .checked_add(1)
            .ok_or(BondRegistrationError::Prerequisite(
                "registration liability epoch overflow",
            ))?;
    let bond: FastPathBondRecord = FastPathBondRecord {
        context: intent.resource_context.clone(),
        validator_id: intent.validator_id,
        resource_domain: intent.resource.domain(),
        resource: *intent.resource.value(),
        custody_object: ObjectRef {
            id: object.id,
            version: object.version,
            digest,
        },
        custody_object_epoch: intent.context.epoch(),
        authority: input.authority.clone(),
        amount,
        committed_at_checkpoint: candidate.created_checkpoint,
        generation: 1,
        lifecycle_epoch: intent.context.epoch(),
        slashable_from_epoch: Epoch::new(slashable_from),
        required_minimum: config.min_bond.get(),
        state: FastPathBondState::Active,
        authorization_scheme: intent.authorization_scheme,
        authorization_key: intent.authorization_key,
    };
    let bytes: Vec<u8> = encode_fastpath_bond_record(&bond)?;
    if bytes.len() > MAX_BOND_REGISTRATION_ROW_BYTES {
        return Err(BondRegistrationError::Prerequisite(
            "registration resulting row bound",
        ));
    }
    if bond_row_digest(env.resolver(), bond.lifecycle_epoch, &bytes)?
        != intent.expected_initial_row_digest
    {
        return Err(BondRegistrationError::Refused(
            BondRegistrationRefusal::InitialRowMismatch,
        ));
    }
    let anchor: BondRegistrationAnchor = BondRegistrationAnchor {
        context: intent.context.clone(),
        validator_id: intent.validator_id,
        signed_registration: candidate.intent.clone(),
        resulting_row: bytes.clone(),
    };
    let bond_key: Vec<u8> = local_instance_state::fastpath_bond_record_key(
        intent.context.chain_id(),
        &intent.validator_id,
    )?;
    let anchor_key: Vec<u8> =
        bond_registration_anchor_key(intent.context.chain_id(), &intent.validator_id)?;
    reads_insert_nonce(&mut reads, &nonce);
    mutations.push(StateMutationEntry::new(
        nonce.key.clone(),
        StateMutation::Put(nonce.record.encode()?),
    )?);
    mutations.push(StateMutationEntry::new(
        bond_key,
        StateMutation::Put(bytes.clone()),
    )?);
    mutations.push(StateMutationEntry::new(
        anchor_key,
        StateMutation::Put(encode_bond_registration_anchor(&anchor)?),
    )?);
    let object_mutations: Vec<DurableObjectMutationEntry> = vec![object_mutation];
    logical_generation::admit_application_gated(
        admission.gate,
        store,
        context,
        domain,
        env.resolver(),
        intent.context.chain_id(),
        intent.context.epoch(),
        &heads,
        &object_mutations,
        Some(&nonce),
        &mut mutations,
        &mut reads,
    )?;
    mutation_fence::merge_configuration_reads(&mut reads, configuration)?;
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    let state: DurableStateTransaction =
        DurableStateTransaction::new(domain, AtomicStateReadSet::new(assertions)?, mutations)?;
    let output: NodeOutput = NodeOutput::new(
        vec![NodeResponse::new(
            request,
            NodeResponseStatus::Accepted,
            Some(bytes),
        )?],
        Vec::new(),
    )?;
    let dedup: NodeDedupRecord = NodeDedupRecord::new(request, event, output.responses().to_vec())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(intent.request_id)
            .map_err(|_| BondRegistrationError::Invalid("registration durable request"))?,
        event,
        dedup.encode()?,
    )?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(heads, object_mutations)?,
        receipt,
        None,
    )?;
    Ok(InvocationPreparation::Prepared(Box::new(
        PreparedBusinessInvocation::new(transaction, output)?,
    )))
}

/// Test-only real-store wrapper for original receipt replay regressions.
/// Production has no standalone registration writer: its dispatcher owns
/// the actual ordered completion around the shared preparation above.
#[cfg(test)]
pub(crate) fn handle_bond_registration_ordered<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    ordered: Option<&ordered_economics::OrderedLegAdmission<'_>>,
) -> Result<NodeOutput, BondRegistrationError> {
    Ok(
        prepare_bond_registration_ordered(store, context, env, candidate, ordered)?
            .commit(store, context)?,
    )
}
