//! Independent bounded effect validation and immutable authority persistence.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn translate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    instance: &InstanceRecord,
    authenticated: &AuthenticatedLocalExecutionIntent,
    interface: &VerifiedPublicationInterface,
    checkpoint: u64,
    inputs: &[ScopedResolvedObject],
    snapshots: &BTreeMap<ObjectId, object_snapshots::ObjectSnapshot>,
    outcome: &LocalExecutionOutcome,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    head_reads: &mut Vec<DurableObjectHeadRead>,
    state: &mut Vec<StateMutationEntry>,
) -> AdmissionResult<Vec<DurableObjectMutationEntry>> {
    let call = &authenticated.intent().call;
    if outcome.created_authorities.len() > MAX_LOCAL_CREATED_OBJECTS as usize {
        return Err(LocalExecutionAdmissionError::Invalid("creation count"));
    }
    let mut created: BTreeMap<ObjectId, &CreatedObjectAuthority> = BTreeMap::new();
    let mut ordinals: BTreeSet<u32> = BTreeSet::new();
    for entry in &outcome.created_authorities {
        if !ordinals.insert(entry.creation_ordinal)
            || created.insert(entry.authority.object_id, entry).is_some()
        {
            return Err(LocalExecutionAdmissionError::Invalid(
                "duplicate creation authority",
            ));
        }
        validate_authority(&entry.authority, instance, &call.instance, interface)?;
        let id: ObjectId = derive_local_created_object_id(
            resolver,
            &call.context,
            &instance.context,
            &call.instance,
            &entry.authority.code,
            outcome.effects.tx_hash,
            entry.creation_ordinal,
        )?;
        if id != entry.authority.object_id {
            return Err(LocalExecutionAdmissionError::Invalid(
                "created identity mismatch",
            ));
        }
    }
    let mut seen: BTreeSet<ObjectId> = BTreeSet::new();
    let mut mutations: Vec<DurableObjectMutationEntry> = Vec::new();
    let mut bytes: usize = 0;
    for effect in &outcome.effects.object_effects {
        let (object, is_creation, previous): (
            &Object,
            bool,
            Option<&object_snapshots::ObjectSnapshot>,
        ) = match effect {
            ObjectEffect::Created(object) => (object, true, None),
            ObjectEffect::Mutated {
                previous_version,
                new_object,
            } => {
                let prior: &object_snapshots::ObjectSnapshot = snapshots
                    .get(&new_object.id)
                    .ok_or(LocalExecutionAdmissionError::Invalid("unknown mutation"))?;
                let input: &ScopedResolvedObject = inputs
                    .iter()
                    .find(|i| i.resolved.object.id == new_object.id)
                    .ok_or(LocalExecutionAdmissionError::Invalid("missing input"))?;
                if input.resolved.mode == AccessMode::Read
                    || *previous_version != prior.object.version
                    || new_object.version
                        != previous_version.checked_add(1).ok_or(
                            LocalExecutionAdmissionError::Invalid("object version overflow"),
                        )?
                    || new_object.type_hash != prior.object.type_hash
                    || new_object.schema_version != prior.object.schema_version
                    || checkpoint < prior.created_checkpoint
                {
                    return Err(LocalExecutionAdmissionError::Invalid(
                        "invalid object mutation",
                    ));
                }
                if new_object.owner != prior.object.owner {
                    let metadata = interface
                        .executable_abi(input.authority.code.origin())
                        .ok_or(LocalExecutionAdmissionError::Invalid(
                            "missing executable metadata",
                        ))?;
                    if !metadata
                        .transferable_constructors
                        .contains(&input.authority.ty.constructor())
                    {
                        return Err(LocalExecutionAdmissionError::Invalid(
                            "unauthorized transfer",
                        ));
                    }
                }
                (new_object, false, Some(prior))
            }
            ObjectEffect::Deleted { id, version } => {
                let input: &ScopedResolvedObject = inputs
                    .iter()
                    .find(|i| i.resolved.object.id == *id)
                    .ok_or(LocalExecutionAdmissionError::Invalid("unknown deletion"))?;
                if !seen.insert(*id)
                    || input.resolved.mode != AccessMode::Consume
                    || input.resolved.object.version != *version
                {
                    return Err(LocalExecutionAdmissionError::Invalid(
                        "unauthorized deletion",
                    ));
                }
                mutations.push(DurableObjectMutationEntry::new(
                    *id,
                    DurableObjectMutation::Delete,
                ));
                continue;
            }
        };
        if !seen.insert(object.id) {
            return Err(LocalExecutionAdmissionError::Invalid("duplicate effect"));
        }
        let authority: &ObjectAuthority = if is_creation {
            &created
                .remove(&object.id)
                .ok_or(LocalExecutionAdmissionError::Invalid(
                    "missing creation authority",
                ))?
                .authority
        } else {
            &inputs
                .iter()
                .find(|i| i.resolved.object.id == object.id)
                .ok_or(LocalExecutionAdmissionError::Invalid(
                    "missing mutation authority",
                ))?
                .authority
        };
        let Owner::Address(owner) = &object.owner else {
            return Err(LocalExecutionAdmissionError::Invalid(
                "non-address output owner",
            ));
        };
        validate_ed25519_owner_address(
            owner.as_bytes(),
            Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )
        .map_err(|_| LocalExecutionAdmissionError::Invalid("invalid output owner"))?;
        execution::publication::validate_nominal_body(
            interface,
            &authority.ty,
            object.schema_version,
            &object.data,
        )
        .map_err(|_| LocalExecutionAdmissionError::Invalid("output body mismatch"))?;
        if !abi::package_types::verify_scoped_type_id(
            resolver,
            &object.type_hash,
            call.context.epoch(),
            &authority.ty,
        )
        .map_err(|_| LocalExecutionAdmissionError::Invalid("output type fingerprint"))?
        {
            return Err(LocalExecutionAdmissionError::Invalid(
                "output type fingerprint",
            ));
        }
        let canonical: Vec<u8> = objects::encode_object(object)
            .map_err(|_| LocalExecutionAdmissionError::Invalid("invalid output encoding"))?;
        bytes = bytes
            .checked_add(canonical.len())
            .ok_or(LocalExecutionAdmissionError::Invalid("output overflow"))?;
        if bytes > MAX_LOCAL_EXECUTION_OUTPUT_BYTES
            || canonical.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES
        {
            return Err(LocalExecutionAdmissionError::Invalid("output body limit"));
        }
        let digest: Digest32 =
            resolver.hash_for_purpose(call.context.epoch(), HashPurpose::Object, &canonical)?;
        let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
            object.clone(),
            digest,
            runtime::DurableObjectProvenance::new(
                call.context.chain_id().clone(),
                call.context.protocol_version(),
            ),
            checkpoint,
        )?;
        let owner_projection: DurableObjectOwnerProjection =
            DurableObjectOwnerProjection::from_owner(object.owner.clone())?;
        let mutation: DurableObjectMutation = if is_creation {
            if object.version != 1 {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "initial object version",
                ));
            }
            let head: DurableObjectHead = store.get_object_head(context, domain, object.id)?;
            if head != DurableObjectHead::Absent {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "created object exists",
                ));
            }
            head_reads.push(DurableObjectHeadRead::new(object.id, head));
            let key: Vec<u8> = object_authority_key(object.id);
            let observed: VersionedStateValue =
                read_state(store, context, domain, key.clone(), reads)?;
            if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "created authority exists",
                ));
            }
            state.push(StateMutationEntry::new(
                key,
                StateMutation::Put(encode_object_authority(authority)?),
            )?);
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection: runtime::DurableObjectRoutingProjection::default(),
            }
        } else {
            let routing_projection = match &previous
                .ok_or(LocalExecutionAdmissionError::Invalid("missing previous"))?
                .head
            {
                DurableObjectHead::Current {
                    routing_projection, ..
                } => routing_projection.clone(),
                _ => return Err(LocalExecutionAdmissionError::Invalid("non-live previous")),
            };
            DurableObjectMutation::Update {
                version,
                owner_projection,
                routing_projection,
            }
        };
        mutations.push(DurableObjectMutationEntry::new(object.id, mutation));
    }
    if !created.is_empty() {
        return Err(LocalExecutionAdmissionError::Invalid(
            "extra creation authority",
        ));
    }
    for event in &outcome.effects.events {
        let ty = abi::package_types::decode_scoped_type_tag(&event.type_tag)
            .map_err(|_| LocalExecutionAdmissionError::Invalid("event type"))?;
        let constructor = interface
            .executable_abi(ty.origin())
            .and_then(|a| {
                a.call
                    .objects
                    .constructors
                    .iter()
                    .find(|c| c.local_id == ty.constructor())
            })
            .ok_or(LocalExecutionAdmissionError::Invalid("event constructor"))?;
        execution::publication::validate_nominal_body(
            interface,
            &ty,
            constructor.schema,
            &event.data,
        )
        .map_err(|_| LocalExecutionAdmissionError::Invalid("event body"))?;
    }
    Ok(mutations)
}
