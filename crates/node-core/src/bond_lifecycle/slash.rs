//! DR-0137 implementation unit 3: one-time evidence-driven bond forfeiture.
//!
//! [`handle_bond_slash`] consumes exactly one already-verified DR-0133
//! equivocation-evidence row (any of the three families:
//! [`consensus::FastVoteEquivocationEvidence`],
//! [`consensus::FastVoteObjectConflictEvidence`] or
//! [`consensus::EpochTransitionEquivocationEvidence`]) and, in one atomic
//! commit, moves the validator's complete live collateral into
//! `ForfeitedCollateral`, advances the bond generation, and records
//! [`FastPathBondState::Jailed`]. Unlike every [`super`] lifecycle
//! operation, this transition is authorized by evidence, not by the
//! committed validator's own signature -- [`SlashIntent`] (`0x6434/v1`) is
//! therefore deliberately unsigned; its authority is the evidence itself,
//! independently re-verified here against the chain-anchored historical
//! validator set (DR-0133 §7), plus one exact `ExecuteLocalContract`
//! signature from whichever account submits/invokes the embedded forfeiture
//! leg (that submitter signs only to spend its own nonce and relay the
//! call; it proves no ownership or authority over the bond).
//!
//! One evidence digest may be consumed once: presence of the
//! [`EvidenceConsumptionRecord`] (`0x6432/v1`) at
//! [`local_instance_state::fastpath_evidence_consumed_key`] is CAS-asserted
//! absent before commit, exactly like every other reserved-namespace
//! first-writer-wins fence in this crate. An exact replay (identical
//! request id and signed bytes) returns the original receipt through the
//! ordinary [`durable_reconciliation::reconcile_receipt`] path before this
//! fence is ever reached; a *different* request attempting to consume the
//! same evidence fails closed at the fence instead of forfeiting a second
//! time.
use super::*;

const EVIDENCE_CONSUMPTION_RECORD_TYPE: u16 = 0x6432;
const SLASH_INTENT_TYPE: u16 = 0x6434;
const ENCODING_VERSION: u16 = 1;
/// Bounds the complete unsigned slash intent, including its one embedded leg.
const MAX_SLASH_INTENT_BYTES: usize = MAX_LOCAL_EXECUTION_INTENT_BYTES + 4_096;

/// Frame `0x6432/v1`: the permanent absence-fence marker binding one
/// consumed DR-0133 evidence digest to the exact bond generation it
/// produced. Keyed by
/// [`local_instance_state::fastpath_evidence_consumed_key`], exactly
/// mirroring the evidence row's own selector under a distinct prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceConsumptionRecord {
    /// Validator the consumed evidence named.
    pub validator_id: ValidatorId,
    /// Evidence epoch the consumed evidence claimed.
    pub evidence_epoch: Epoch,
    /// Normalized-identity `conflict_digest` of the consumed evidence row.
    pub conflict_digest: Digest32,
    /// The resulting `Jailed` generation this consumption produced.
    pub generation: u64,
    /// Local-per-node checkpoint marker, informational only.
    pub consumed_at_checkpoint: u64,
}

/// Encodes Frame `0x6432/v1`.
pub fn encode_evidence_consumption_record(
    record: &EvidenceConsumptionRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    if record.generation == 0 {
        return Err(NodeCoreError::PersistenceInvariant(
            "invalid evidence consumption record",
        ));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(EVIDENCE_CONSUMPTION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, record.validator_id.as_bytes().to_vec())?;
    frame.field_u64(2, record.evidence_epoch.get())?;
    frame.field_bytes(3, encode_digest32(&record.conflict_digest)?)?;
    frame.field_u64(4, record.generation)?;
    frame.field_u64(5, record.consumed_at_checkpoint)?;
    Ok(frame.finish()?)
}

/// Strictly decodes Frame `0x6432/v1`.
pub fn decode_evidence_consumption_record(
    bytes: &[u8],
) -> Result<EvidenceConsumptionRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(EVIDENCE_CONSUMPTION_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let validator_bytes: [u8; 32] = frame.required_field(1)?.try_into().map_err(|_| {
        NodeCoreError::PersistenceInvariant("evidence consumption validator length")
    })?;
    let record: EvidenceConsumptionRecord = EvidenceConsumptionRecord {
        validator_id: ValidatorId::new(validator_bytes),
        evidence_epoch: Epoch::new(frame.required_u64(2)?),
        conflict_digest: decode_digest32(frame.required_field(3)?)?,
        generation: frame.required_u64(4)?,
        consumed_at_checkpoint: frame.required_u64(5)?,
    };
    if record.generation == 0 || encode_evidence_consumption_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical evidence consumption record",
        ));
    }
    Ok(record)
}

/// Unsigned payload authorizing one evidence-driven bond forfeiture. There is
/// no signature over this frame: the authority is the referenced evidence
/// itself (re-verified in full by [`handle_bond_slash`]), never a signer's
/// say-so over this envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashIntent {
    /// Expected replay context; also the epoch this transition commits at.
    pub context: PublicationContext,
    /// Exact replay identity. The embedded leg's own
    /// `CallIntent::request_id` must equal this exact value too.
    pub request_id: [u8; 32],
    /// Validator this operation is committed against.
    pub validator_id: ValidatorId,
    /// Exact resource identity the caller expects the committed bond row to
    /// carry.
    pub resource_id: BondResourceId,
    /// Exact current (pre-transition) generation the caller expects the
    /// committed bond row to carry.
    pub expected_generation: u64,
    /// Evidence epoch the referenced evidence row claims.
    pub evidence_epoch: Epoch,
    /// Normalized-identity `conflict_digest` selecting the permanent
    /// DR-0133 evidence row to consume.
    pub conflict_digest: Digest32,
    /// The signed local-execution forfeiture leg (raw canonical bytes).
    pub leg: Vec<u8>,
}

/// Encodes unsigned slash intent `0x6434/v1`.
pub fn encode_slash_intent(intent: &SlashIntent) -> Result<Vec<u8>, BondLifecycleError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(SLASH_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        execution::publication::encode_publication_context(&intent.context)
            .map_err(|_| BondLifecycleError::Invalid("invalid slash intent context"))?,
    )?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(3, intent.validator_id.as_bytes().to_vec())?;
    frame.field_bytes(
        4,
        bonds::encode_bond_resource_id(intent.resource_id)
            .map_err(|_| BondLifecycleError::Invalid("slash intent resource id"))?,
    )?;
    frame.field_u64(5, intent.expected_generation)?;
    frame.field_u64(6, intent.evidence_epoch.get())?;
    frame.field_bytes(7, encode_digest32(&intent.conflict_digest)?)?;
    frame.field_bytes(8, intent.leg.clone())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_SLASH_INTENT_BYTES {
        return Err(BondLifecycleError::Invalid("slash intent bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes unsigned slash intent `0x6434/v1`.
pub fn decode_slash_intent(bytes: &[u8]) -> Result<SlashIntent, BondLifecycleError> {
    if bytes.len() > MAX_SLASH_INTENT_BYTES {
        return Err(BondLifecycleError::Invalid("slash intent bytes"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SLASH_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    let context: PublicationContext =
        execution::publication::decode_publication_context(frame.required_field(1)?)
            .map_err(|_| BondLifecycleError::Invalid("invalid slash intent context"))?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| BondLifecycleError::Invalid("slash intent request id length"))?;
    let validator_bytes: [u8; 32] = frame
        .required_field(3)?
        .try_into()
        .map_err(|_| BondLifecycleError::Invalid("slash intent validator id length"))?;
    let resource_id: BondResourceId = decode_bond_resource_id(frame.required_field(4)?)
        .map_err(|_| BondLifecycleError::Invalid("slash intent resource id"))?;
    let intent: SlashIntent = SlashIntent {
        context,
        request_id,
        validator_id: ValidatorId::new(validator_bytes),
        resource_id,
        expected_generation: frame.required_u64(5)?,
        evidence_epoch: Epoch::new(frame.required_u64(6)?),
        conflict_digest: decode_digest32(frame.required_field(7)?)?,
        leg: frame.required_field(8)?.to_vec(),
    };
    if encode_slash_intent(&intent)? != bytes {
        return Err(BondLifecycleError::Invalid("noncanonical slash intent"));
    }
    Ok(intent)
}

/// Digest of the exact canonical slash-intent bytes: the receipt/replay
/// idempotency key. Because the embedded leg's own signature is already
/// part of `intent_bytes`, a resubmission carrying a differently-signed leg
/// over an otherwise identical intent hashes differently and is treated as a
/// conflicting replay, exactly like
/// [`super::bond_lifecycle_receipt_digest`] achieves for the signed
/// lifecycle envelope.
fn slash_receipt_digest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    intent_bytes: &[u8],
) -> Result<Digest32, BondLifecycleError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(BondLifecycleError::Invalid("slash intent hash context"));
    }
    Ok(resolver.hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, intent_bytes)?)
}

/// Builds the `ForfeitedCollateral` scope matching `scope`'s chain/subject/
/// resource but a different purpose.
fn forfeited_scope(
    resource_context: &PublicationContext,
    validator_id: ValidatorId,
    resource: [u8; 32],
) -> ProtocolCustodyScope {
    ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::ForfeitedCollateral,
        chain_id: resource_context.chain_id().clone(),
        subject: *validator_id.as_bytes(),
        resource,
    }
}

/// Constructs the forfeiture-direction capability for the exact current
/// custody object, moving it from `source_scope` to `target_scope`.
fn forfeit_capability(
    resolver: &HashSuiteResolver,
    current_context: &PublicationContext,
    resource: &FastPathEconomicsResourcePolicy,
    source_scope: ProtocolCustodyScope,
    target_scope: ProtocolCustodyScope,
    custody: ObjectId,
    leg: &AuthenticatedLocalExecutionIntent,
) -> Result<(ProtocolCustodyCapability, Digest32), BondLifecycleError> {
    let call = &leg.intent().call;
    if call.context != *current_context
        || call.access.entries.len() != 1
        || call.access.entries[0].mode != AccessMode::Write
        || call.access.entries[0].object_ref.id != custody
        || call.entrypoint != resource.transfer_entrypoint
        || call.code != resource.code
        || call.instance != resource.instance
    {
        return Err(BondLifecycleError::Invalid("bond forfeiture leg target"));
    }
    let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
        resource.instance.clone(),
        resource.code.clone(),
        resource.ty.clone(),
        resource.schema,
        resource.transfer_entrypoint.clone(),
    )?;
    let event_digest: Digest32 = local_execution_event_digest(resolver, leg.signed())?;
    let capability: ProtocolCustodyCapability = ProtocolCustodyCapability::new(
        resolver,
        current_context.clone(),
        target,
        ProtocolCustodyDirection::Forfeit {
            custody,
            source_scope,
            target_scope,
        },
        call.sender,
        event_digest,
    )?;
    Ok((capability, event_digest))
}

/// Consumes one already-verified DR-0133 equivocation-evidence row and
/// atomically forfeits the named validator's complete live bond collateral.
///
/// Order: bounded decode; the caller-supplied leg policy must equal
/// `LocalExecutionPolicy::generic_object_results(intent.context)`, matching
/// what restart independently reconstructs; authenticate the embedded leg;
/// leg/outer request-id equality; reserved-id guards; the exact intent-bytes
/// receipt digest and replay reconciliation; the committed-epoch fence; the
/// committed bond row (resource/generation cross-checked against the
/// intent's own pins); the named permanent evidence row (read, decoded,
/// cross-checked against its own key selector and normalized identity);
/// class (b)'s mandatory preimage-hash-to-signed-digest checks; full
/// re-verification against the chain-anchored historical validator set;
/// live-collateral and slashable-from-epoch-vs-evidence-epoch requirements
/// (gated on [`fast_path::records::FastPathBondRecord::slashable_from_epoch`],
/// never on `lifecycle_epoch`, so `Unbond`/`Replace` can never launder away
/// liability for pre-existing collateral by merely advancing
/// `lifecycle_epoch`); the evidence-consumed absence fence; the committed
/// economics policy (read without requiring it currently accept new bonds);
/// the forfeiture leg run through the shared local-execution admission
/// pipeline under a `Forfeit` capability; generic whole-object effect
/// validation; and one atomic commit of the forfeited object, the `Jailed`
/// bond row, the permanent transition record, the evidence-consumed marker,
/// the sender nonce range, stale lock cleanup and the one outer receipt.
#[allow(clippy::too_many_arguments)]
pub fn handle_bond_slash<S, E>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    leg_policy: &LocalExecutionPolicy,
    engine: &E,
    intent_bytes: &[u8],
    created_checkpoint: u64,
) -> Result<NodeOutput, BondLifecycleError>
where
    S: StructuredDurableDomainStateStore,
    E: LocalContractEngine + ?Sized,
{
    if history.len() > publication::MAX_PUBLICATION_HISTORY {
        return Err(BondLifecycleError::Invalid("resolver history bound"));
    }
    // 1. bounded canonical decode.
    let intent: SlashIntent = decode_slash_intent(intent_bytes)?;
    if intent.context != *expected {
        return Err(BondLifecycleError::Invalid("slash intent context"));
    }

    // The caller-supplied leg policy must be exactly the one restart
    // (`genesis::verify_fastpath_bond_chain`) independently reconstructs
    // from nothing but the retained transition context
    // (`LocalExecutionPolicy::generic_object_results(transition.context)`):
    // any divergence here would authenticate the forfeiture leg under a
    // policy restart could never reproduce, permanently stranding this
    // transition as unverifiable at restart.
    if *leg_policy != LocalExecutionPolicy::generic_object_results(intent.context.clone()) {
        return Err(BondLifecycleError::Invalid("slash leg policy mismatch"));
    }

    // 2. authenticate the embedded local-execution forfeiture leg through
    // the exact existing `ExecuteLocalContract` domain, before any storage
    // read.
    let leg: AuthenticatedLocalExecutionIntent =
        authenticate_local_execution(resolver, leg_policy, &intent.leg)?;

    // 3. the leg's own signed request id must equal the outer intent's.
    if leg.intent().call.request_id != intent.request_id {
        return Err(BondLifecycleError::Invalid("slash leg request id mismatch"));
    }

    // 4. reject reserved request id -- outer intent and leg.
    local_instance_state::reject_reserved_request_id(&intent.request_id)
        .map_err(BondLifecycleError::Invalid)?;
    local_instance_state::reject_reserved_request_id(&leg.intent().call.request_id)
        .map_err(BondLifecycleError::Invalid)?;

    // 5. hash the exact canonical intent bytes (which already embed the
    // leg's own signed bytes) for receipt/replay idempotency, then
    // reconcile exact/conflicting replay before any epoch/policy/object/
    // ABI/storage read.
    let receipt_digest: Digest32 = slash_receipt_digest(resolver, &intent.context, intent_bytes)?;
    let request_id: RequestId = RequestId::new(intent.request_id)?;
    if let Some(output) = durable_reconciliation::reconcile_receipt(
        store,
        context,
        domain,
        request_id,
        receipt_digest,
    )? {
        return Ok(output);
    }

    // 6. current epoch fence.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    mutation_fence::fence_current_epoch(
        store,
        context,
        domain,
        intent.context.chain_id(),
        intent.context.epoch(),
        &mut reads,
    )?;

    // 7. read the committed bond row and cross-check the intent's pins.
    let bond_key: Vec<u8> = local_instance_state::fastpath_bond_record_key(
        intent.context.chain_id(),
        &intent.validator_id,
    )?;
    let bond_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &bond_key)?;
    let bond_row_revision: StateRevision = bond_observed.revision();
    reads.insert(bond_key.clone(), bond_row_revision);
    let previous_bond_bytes: Vec<u8> = bond_observed
        .value()
        .ok_or(BondLifecycleError::Invalid(
            "slash requires an existing committed bond row",
        ))?
        .to_vec();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(&previous_bond_bytes)?;
    if bond.context.chain_id() != intent.context.chain_id()
        || bond.validator_id != intent.validator_id
    {
        return Err(BondLifecycleError::Invalid("bond row identity mismatch"));
    }
    let resource_id: BondResourceId = BondResourceId::new(bond.resource_domain, bond.resource)
        .map_err(|_| BondLifecycleError::Invalid("bond resource invalid"))?;
    if intent.resource_id != resource_id {
        return Err(BondLifecycleError::Invalid(
            "slash intent resource mismatch",
        ));
    }
    if intent.expected_generation != bond.generation {
        return Err(BondLifecycleError::Invalid(
            "slash intent stale expected generation",
        ));
    }

    // 8. read and decode the named permanent DR-0133 evidence row.
    let evidence_key: Vec<u8> = local_instance_state::fastpath_equivocation_evidence_key(
        intent.context.chain_id(),
        intent.evidence_epoch,
        *intent.validator_id.as_bytes(),
        intent.conflict_digest,
    )?;
    let evidence_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &evidence_key)?;
    reads.insert(evidence_key, evidence_observed.revision());
    let evidence_record: equivocation::FastPathEquivocationEvidenceRecord =
        equivocation::decode_fastpath_equivocation_evidence_record(
            evidence_observed
                .value()
                .ok_or(BondLifecycleError::Invalid(
                    "no evidence recorded for the claimed selector",
                ))?,
        )?;
    let decoded: equivocation::DecodedEquivocationEvidence =
        equivocation::decode_dispatched(&evidence_record.evidence_bytes)
            .map_err(|_| BondLifecycleError::Invalid("evidence row does not decode"))?;

    // 9. cross-check the decoded evidence's own identity/context against the
    // exact key selector it was read at, and against the bond being slashed.
    if decoded.chain_id() != intent.context.chain_id()
        || decoded.epoch() != intent.evidence_epoch
        || decoded.validator() != intent.validator_id
    {
        return Err(BondLifecycleError::Invalid(
            "evidence identity does not match the claimed selector",
        ));
    }
    let recomputed_digest: Digest32 = equivocation::normalized_identity_digest(resolver, &decoded)
        .map_err(|_| BondLifecycleError::Invalid("evidence normalized identity recomputation"))?;
    if recomputed_digest != intent.conflict_digest {
        return Err(BondLifecycleError::Invalid(
            "evidence record does not match its own key digest",
        ));
    }

    // 10. class (b)'s mandatory preimage-hash-to-signed-digest checks,
    // independently re-run: an attached preimage is untrusted bytes until
    // proven to hash to the exact digest its own vote signed.
    if let equivocation::DecodedEquivocationEvidence::ObjectConflict(evidence) = &decoded {
        let low_hash: Digest32 = resolver.hash_for_purpose(
            evidence.low.epoch,
            HashPurpose::ExecutionEffects,
            &consensus::encode_locked_object_set_preimage(&evidence.low_preimage)
                .map_err(|_| BondLifecycleError::Invalid("evidence preimage encoding"))?,
        )?;
        if low_hash != evidence.low.locked_objects_digest {
            return Err(BondLifecycleError::Invalid(
                "attached preimage does not hash to its FastVote locked_objects_digest",
            ));
        }
        let high_hash: Digest32 = resolver.hash_for_purpose(
            evidence.high.epoch,
            HashPurpose::ExecutionEffects,
            &consensus::encode_locked_object_set_preimage(&evidence.high_preimage)
                .map_err(|_| BondLifecycleError::Invalid("evidence preimage encoding"))?,
        )?;
        if high_hash != evidence.high.locked_objects_digest {
            return Err(BondLifecycleError::Invalid(
                "attached preimage does not hash to its FastVote locked_objects_digest",
            ));
        }
    }

    // 11. full re-verification against the chain-anchored historical
    // validator set (DR-0133 §7) -- never merely trusting a stored row.
    let validator_set: ValidatorSet = equivocation::load_historical_validator_set(
        store,
        context,
        domain,
        resolver,
        intent.context.chain_id(),
        intent.context.protocol_version(),
        intent.evidence_epoch,
    )
    .map_err(|_| BondLifecycleError::Invalid("historical validator set unavailable"))?;
    match &decoded {
        equivocation::DecodedEquivocationEvidence::FastVote(evidence) => {
            consensus::verify_fast_vote_equivocation_evidence(
                evidence,
                validator_set,
                &fast_path::FastPathEd25519Verifier,
            )
            .map_err(|_| BondLifecycleError::Invalid("evidence reverification failed"))?;
        }
        equivocation::DecodedEquivocationEvidence::ObjectConflict(evidence) => {
            consensus::verify_fast_vote_object_conflict_evidence(
                evidence,
                validator_set,
                &fast_path::FastPathEd25519Verifier,
            )
            .map_err(|_| BondLifecycleError::Invalid("evidence reverification failed"))?;
        }
        equivocation::DecodedEquivocationEvidence::EpochTransition(evidence) => {
            consensus::verify_epoch_transition_equivocation_evidence(
                evidence,
                validator_set,
                &fast_path::FastPathEd25519Verifier,
            )
            .map_err(|_| BondLifecycleError::Invalid("evidence reverification failed"))?;
        }
    }

    // 12. live collateral and liability-floor-vs-evidence-epoch
    // requirements. Gating on `slashable_from_epoch` -- never on
    // `lifecycle_epoch` -- is the exact fix for the economic hole a naive
    // `lifecycle_epoch` comparison opens: `Replace` and `Unbond` both stamp
    // `lifecycle_epoch` to their own committing epoch while carrying
    // forward the *same* live collateral (or, for `Replace`, freshly
    // re-posted collateral covering the identical liability window) a
    // validator was already liable for. Gating on `lifecycle_epoch` would
    // let a validator launder away old equivocation evidence for free by
    // merely unbonding or replacing after misbehaving but before evidence
    // lands. `slashable_from_epoch` instead tracks exactly when *this*
    // collateral actually became liable, independent of how many no-op
    // (`Unbond`) or provenance-preserving (`Replace`) transitions have
    // since moved `lifecycle_epoch` forward.
    let (custody_object, live_amount): (&ObjectRef, u64) = bond.live_collateral().ok_or(
        BondLifecycleError::Invalid("bond has no live collateral to forfeit"),
    )?;
    let custody: ObjectId = custody_object.id;
    if intent.evidence_epoch.get() < bond.slashable_from_epoch.get() {
        return Err(BondLifecycleError::Invalid(
            "evidence epoch predates the bond's slashable-from epoch",
        ));
    }

    // 13. absence-fence the evidence-consumed marker: one evidence digest
    // may be consumed once. A different request attempting to consume the
    // same evidence fails closed here; an exact replay already returned at
    // step 5 and never reaches this fence.
    let consumed_key: Vec<u8> = local_instance_state::fastpath_evidence_consumed_key(
        intent.context.chain_id(),
        intent.evidence_epoch,
        *intent.validator_id.as_bytes(),
        intent.conflict_digest,
    )?;
    let consumed_observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &consumed_key)?;
    if consumed_observed.value().is_some() || consumed_observed.revision() != StateRevision::INITIAL
    {
        return Err(BondLifecycleError::Invalid("evidence already consumed"));
    }
    reads.insert(consumed_key.clone(), consumed_observed.revision());

    // 14. read the committed economics policy without requiring the
    // resource still accept new bonds: a since-disabled resource must not
    // strand an already-committed bond as unslashable.
    let resource_context: PublicationContext = bond.context.clone();
    let policy: FastPathEconomicsPolicy =
        read_economics_policy(store, context, domain, &resource_context, &mut reads)?;
    let resource: &FastPathEconomicsResourcePolicy =
        resource_policy(&policy, bond.resource_domain, bond.resource)?;
    // Structural check only (the resource must support bonds at all);
    // deliberately does not require `BondResourceConfig::enabled`, unlike
    // `deposit`/`replace`/`reactivate`: a since-disabled resource must not
    // strand an already-committed bond as unslashable.
    let _: &BondResourceConfig = bond_config(resource)?;

    // 15. run the forfeiture transfer entrypoint through the exact existing
    // local-execution admission pipeline under a narrowly scoped `Forfeit`
    // capability.
    let source_scope: ProtocolCustodyScope =
        custody_scope(&resource_context, bond.validator_id, bond.resource);
    let target_scope: ProtocolCustodyScope =
        forfeited_scope(&resource_context, bond.validator_id, bond.resource);
    let (capability, leg_event_digest) = forfeit_capability(
        resolver,
        &intent.context,
        resource,
        source_scope.clone(),
        target_scope.clone(),
        custody,
        &leg,
    )?;
    let call = leg.intent().call.clone();
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
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    let mut state_mutations: Vec<StateMutationEntry> = Vec::new();
    let admitted: AdmittedLeg = admit_and_execute_leg(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        leg_policy,
        engine,
        &leg,
        leg_event_digest,
        Some(&capability),
        created_checkpoint,
        &mut reads,
        &mut head_reads,
        &mut state_mutations,
    )?;
    if !admitted.success {
        return Err(BondLifecycleError::Invalid("bond forfeiture leg trapped"));
    }
    if !admitted.created_authorities.is_empty() {
        return Err(BondLifecycleError::Invalid(
            "bond forfeiture leg created an object",
        ));
    }

    // 16. generic whole-object effect validation: exactly the expected
    // `BondCollateral -> ForfeitedCollateral` owner transition, observed
    // only through the signed executable ABI.
    let owner_before: Owner = Owner::ProtocolCustody(source_scope);
    let owner_after: Owner = Owner::ProtocolCustody(target_scope);
    let snapshot: &object_snapshots::ObjectSnapshot =
        admitted
            .snapshots
            .get(&custody)
            .ok_or(BondLifecycleError::Invalid(
                "bond forfeiture custody missing",
            ))?;
    let input = admitted
        .inputs
        .iter()
        .find(|input| input.resolved.object.id == custody)
        .ok_or(BondLifecycleError::Invalid("bond forfeiture input missing"))?;
    let (new_object, forfeited_amount) = effects::validate(
        &admitted.interface,
        &input.authority,
        &effects::ExpectedCustodyTransfer {
            object_id: custody,
            owner_before: &owner_before,
            owner_after: &owner_after,
        },
        created_checkpoint,
        snapshot,
        &admitted.effects,
    )?;
    if forfeited_amount != live_amount {
        return Err(BondLifecycleError::Invalid(
            "forfeited amount does not match the bond's recorded live collateral",
        ));
    }
    let (mutation_entry, digest) = effects::build_mutation_entry(
        resolver,
        &intent.context,
        created_checkpoint,
        snapshot,
        &new_object,
    )?;
    // Retain the exact canonical previous/resulting object bytes so restart
    // (`genesis::verify_fastpath_bond_chain`) can independently re-derive
    // both `ObjectRef` digests and cross-check them against the committed
    // bond rows, rather than trusting `new_bond.custody_object` alone.
    let previous_object_bytes: Vec<u8> = objects::encode_object(&snapshot.object)
        .map_err(|_| BondLifecycleError::Invalid("bond forfeiture previous object encoding"))?;
    let resulting_object_bytes: Vec<u8> = objects::encode_object(&new_object)
        .map_err(|_| BondLifecycleError::Invalid("bond forfeiture resulting object encoding"))?;
    if previous_object_bytes.len() > fast_path::records::MAX_BOND_TRANSITION_OBJECT_BYTES
        || resulting_object_bytes.len() > fast_path::records::MAX_BOND_TRANSITION_OBJECT_BYTES
    {
        return Err(BondLifecycleError::Invalid(
            "bond forfeiture object body limit",
        ));
    }
    reads.insert(nonce.key.clone(), nonce.read_revision);
    state_mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);

    // 17. one atomic commit: the forfeited object, the `Jailed` bond row,
    // the permanent transition record, the evidence-consumed marker, the
    // sender nonce range, stale lock cleanup and the one outer receipt.
    let new_generation: u64 = bond
        .generation
        .checked_add(1)
        .ok_or(BondLifecycleError::Invalid("bond generation overflow"))?;
    let new_bond: FastPathBondRecord = FastPathBondRecord {
        context: bond.context.clone(),
        validator_id: bond.validator_id,
        resource_domain: bond.resource_domain,
        resource: bond.resource,
        custody_object: ObjectRef {
            id: new_object.id,
            version: new_object.version,
            digest,
        },
        // The forfeiture leg mints the resulting `ForfeitedCollateral`
        // object ref at exactly this transition's own epoch.
        custody_object_epoch: intent.context.epoch(),
        authority: input.authority.clone(),
        // Historical amount/minimum preserved exactly: this row is now a
        // permanent forfeiture audit record, not a live balance.
        amount: bond.amount,
        committed_at_checkpoint: created_checkpoint,
        generation: new_generation,
        lifecycle_epoch: intent.context.epoch(),
        // Preserved exactly as audit data: a `Jailed` row is no longer live
        // collateral, so the liability floor no longer gates anything, but
        // it remains part of the permanent forfeiture record.
        slashable_from_epoch: bond.slashable_from_epoch,
        required_minimum: bond.required_minimum,
        state: FastPathBondState::Jailed {
            evidence_digest: intent.conflict_digest,
        },
        authorization_scheme: bond.authorization_scheme,
        authorization_key: bond.authorization_key,
    };
    let consumption_record: EvidenceConsumptionRecord = EvidenceConsumptionRecord {
        validator_id: intent.validator_id,
        evidence_epoch: intent.evidence_epoch,
        conflict_digest: intent.conflict_digest,
        generation: new_generation,
        consumed_at_checkpoint: created_checkpoint,
    };
    state_mutations.push(StateMutationEntry::new(
        consumed_key,
        StateMutation::Put(encode_evidence_consumption_record(&consumption_record)?),
    )?);
    commit_bond_transition(
        store,
        context,
        domain,
        resolver,
        request_id,
        receipt_digest,
        bond_key,
        bond_row_revision,
        previous_bond_bytes,
        bond,
        created_checkpoint,
        reads,
        intent.context.clone(),
        FastPathBondLifecycleOperation::Slash,
        BondTransitionAuthorization::ConsumedEvidence {
            evidence_bytes: evidence_record.evidence_bytes,
            evidence_epoch: intent.evidence_epoch,
            evidence_digest: intent.conflict_digest,
            forfeiture_leg: intent.leg,
            previous_object: previous_object_bytes,
            resulting_object: resulting_object_bytes,
        },
        None,
        new_bond,
        head_reads,
        vec![mutation_entry],
        state_mutations,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn vector_context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("dr0137-unit3-vectors").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(9),
        )
        .unwrap()
    }

    fn vector_resource_id() -> BondResourceId {
        BondResourceId::new(7, [0x79; 32]).unwrap()
    }

    #[test]
    fn evidence_consumption_record_frame_0x6432_round_trips_and_rejects_zero_generation() {
        let record = EvidenceConsumptionRecord {
            validator_id: ValidatorId::new([0x41; 32]),
            evidence_epoch: Epoch::new(3),
            conflict_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x42; 32]),
            generation: 5,
            consumed_at_checkpoint: 12,
        };
        let bytes = encode_evidence_consumption_record(&record).unwrap();
        assert_eq!(decode_evidence_consumption_record(&bytes).unwrap(), record);
        assert_eq!(
            hex(&bytes),
            "534e524532640100050001002000000041414141414141414141414141414141414141414141414141414141414141410200080000000300000000000000030038000000534e52450301010002000100020000000100020020000000424242424242424242424242424242424242424242424242424242424242424204000800000005000000000000000500080000000c00000000000000"
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_evidence_consumption_record(&trailing).is_err());

        let mut zero_generation = record;
        zero_generation.generation = 0;
        assert!(encode_evidence_consumption_record(&zero_generation).is_err());
    }

    #[test]
    fn slash_intent_frame_0x6434_round_trips_and_rejects_a_bit_flip() {
        let intent = SlashIntent {
            context: vector_context(),
            request_id: [0x51; 32],
            validator_id: ValidatorId::new([0x52; 32]),
            resource_id: vector_resource_id(),
            expected_generation: 3,
            evidence_epoch: Epoch::new(2),
            conflict_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x53; 32]),
            leg: vec![0x54, 0x55, 0x56],
        };
        let bytes = encode_slash_intent(&intent).unwrap();
        assert_eq!(decode_slash_intent(&bytes).unwrap(), intent);
        assert_eq!(
            hex(&bytes),
            "534e524534640100080001003c000000534e52450163010003000100140000006472303133372d756e6974332d766563746f727302000400000003000000030008000000090000000000000002002000000051515151515151515151515151515151515151515151515151515151515151510300200000005252525252525252525252525252525252525252525252525252525252525252040038000000534e52450880010002000100020000000700020020000000797979797979797979797979797979797979797979797979797979797979797905000800000003000000000000000600080000000200000000000000070038000000534e524503010100020001000200000001000200200000005353535353535353535353535353535353535353535353535353535353535353080003000000545556"
        );

        // A corrupted frame header (never a bit flip inside an opaque
        // byte-vector field, which re-encodes identically and is not, by
        // itself, structurally detectable) must fail closed.
        let mut tampered_header = bytes.clone();
        tampered_header[0] ^= 0xFF;
        assert!(decode_slash_intent(&tampered_header).is_err());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_slash_intent(&trailing).is_err());
    }
}
