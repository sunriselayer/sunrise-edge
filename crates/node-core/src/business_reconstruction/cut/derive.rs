use super::super::{
    ReconstructionEd25519Verifier,
    projection::{SemanticProjection, SemanticRecord},
};
use super::*;
use crate::logical_generation::{
    LogicalSubject, decode_logical_profile_record, decode_logical_provenance_record,
    is_logical_profile_key, is_logical_provenance_key, logical_profile_key,
};
use crate::ordered_economics::OrderedEconomicsPolicy;
use crate::ordered_economics::{
    DrainSetRecord, OrderedCandidate, OrderedHistoryComponentKind, OrderedOperationKind,
    admission_closure_key, decode_admission_closure_record, decode_drain_set_record,
    decode_ordered_candidate, drain_set_record_key, engine, verified_committed_block,
};
use consensus::{
    AvailabilityIdentity, DrainUnionAccumulator, FrozenFrontierCertifier, FrozenFrontierIdentity,
    FrozenFrontierPageVerifier, verify_frozen_frontier_quorum,
};
use runtime::portable::{DurablePayloadDescriptor, DurableRecordKey};
use runtime::{DurableDomainStateStore, DurableRequestId, StructuredDurableDomainStateStore};
use std::collections::BTreeSet;

fn required_state(
    overlay: &BusinessReconstructionOverlay<'_>,
    key: &[u8],
) -> Result<Vec<u8>, BusinessCutError> {
    overlay
        .store
        .get_versioned_durable(&overlay.plan.operation_context, overlay.plan.domain, key)
        .map_err(|_| invalid("private cut state read refused"))?
        .value()
        .map(<[u8]>::to_vec)
        .ok_or(invalid(
            "required privately reconstructed cut state is absent",
        ))
}
fn component(
    material: &OrderedHistoryHeightMaterial,
    kind: OrderedHistoryComponentKind,
) -> Result<&[u8], BusinessCutError> {
    material
        .components
        .iter()
        .find(|(key, _)| *key == kind)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or(invalid("cut history required component is absent"))
}

/// Re-derives the selected signed union, not a source or local ready/count flag.
fn complete_drain(
    overlay: &BusinessReconstructionOverlay<'_>,
    ordered: &[OrderedHistoryHeightMaterial],
    controls: &[DrainSetControlMaterial],
) -> Result<(DrainSetRecord, Digest32, BTreeSet<Vec<u8>>), BusinessCutError> {
    let plan = &overlay.plan;
    let context: &PublicationContext = plan.genesis_root.manifest().context();
    let freeze_key: Vec<u8> = admission_closure_key(context.chain_id(), context.epoch())
        .map_err(|_| invalid("cut Freeze key"))?;
    let freeze = decode_admission_closure_record(&required_state(overlay, &freeze_key)?)
        .map_err(|_| invalid("cut actual Freeze schema"))?;
    let drain_key: Vec<u8> = drain_set_record_key(context.chain_id(), context.epoch())
        .map_err(|_| invalid("cut DrainSet key"))?;
    let drain: DrainSetRecord = decode_drain_set_record(&required_state(overlay, &drain_key)?)
        .map_err(|_| invalid("cut actual DrainSet schema"))?;
    if drain.closed_epoch != context.epoch()
        || freeze.closed_epoch != context.epoch()
        || drain.drain_union_identity.closure_request_id != freeze.request_id
        || drain.drain_union_identity.closure_height != freeze.closed_at_block_height
    {
        return Err(invalid("cut reconstructed Freeze/DrainSet differs"));
    }
    let material: &OrderedHistoryHeightMaterial = ordered
        .iter()
        .find(|height| height.descriptor.height == drain.committed_at_block_height)
        .ok_or(invalid("committed DrainSet lies outside cut history"))?;
    let candidate: OrderedCandidate =
        decode_ordered_candidate(component(material, OrderedHistoryComponentKind::Candidate)?)
            .map_err(|_| invalid("committed cut DrainSet candidate schema"))?;
    if candidate.kind != OrderedOperationKind::DrainSet || candidate.request_id != drain.request_id
    {
        return Err(invalid(
            "cut DrainSet does not name its original ordered candidate",
        ));
    }
    let candidate_digest: Digest32 = plan
        .ordered_policy
        .candidate_digest(&candidate)
        .map_err(|_| invalid("cut DrainSet candidate digest"))?;
    let intent = crate::ordered_economics::decode_drain_set_intent(&candidate.intent)
        .map_err(|_| invalid("cut DrainSet intent schema"))?;
    if intent.selected_votes != drain.selected_votes
        || intent.drain_union_identity != drain.drain_union_identity
    {
        return Err(invalid("cut DrainSet original selection/union differs"));
    }
    let closure: &DrainSetControlMaterial = controls
        .iter()
        .find(|value| value.candidate_digest == candidate_digest)
        .ok_or(invalid(
            "committed DrainSet complete selected streams are absent",
        ))?;
    if closure.selected_votes != drain.selected_votes
        || closure.signer_frontiers.len() != drain.selected_votes.len()
    {
        return Err(invalid("cut selected stream roster differs"));
    }
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        plan.ordered_policy.engine().validator_set().clone(),
    )
    .map_err(|_| invalid("cut frontier authority"))?;
    verify_frozen_frontier_quorum(
        &certifier,
        &drain.selected_votes,
        plan.domain,
        freeze.request_id,
        freeze.closed_at_block_height,
        &ReconstructionEd25519Verifier,
    )
    .map_err(|_| invalid("cut signed selection lacks the exact frozen quorum"))?;
    let mut members: BTreeMap<[u8; 32], AvailabilityIdentity> = BTreeMap::new();
    for (vote, frontier) in drain.selected_votes.iter().zip(&closure.signer_frontiers) {
        if frontier.signer != vote.validator {
            return Err(invalid("cut frontier signer order differs"));
        }
        let mut verifier: FrozenFrontierPageVerifier = FrozenFrontierPageVerifier::new(
            plan.genesis_root.genesis_resolver(),
            &certifier,
            vote.clone(),
            &ReconstructionEd25519Verifier,
        )
        .map_err(|_| invalid("cut frontier signature differs"))?;
        for page in &frontier.pages {
            verifier
                .push_page(plan.genesis_root.genesis_resolver(), page)
                .map_err(|_| invalid("cut selected frontier page differs"))?;
            for entry in &page.entries {
                if let Some(previous) = members.insert(entry.request_id, entry.clone())
                    && previous != *entry
                {
                    return Err(invalid("contradictory selected cut union member"));
                }
            }
        }
        verifier
            .finish()
            .map_err(|_| invalid("cut selected frontier is not terminal"))?;
    }
    let selected: Vec<(protocol_types::ValidatorId, FrozenFrontierIdentity)> = drain
        .selected_votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let mut union: DrainUnionAccumulator = DrainUnionAccumulator::new(
        plan.genesis_root.genesis_resolver(),
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        plan.domain,
        freeze.request_id,
        freeze.closed_at_block_height,
        &selected,
    )
    .map_err(|_| invalid("cut selected union seed"))?;
    for identity in members.values() {
        union
            .push_member(plan.genesis_root.genesis_resolver(), identity)
            .map_err(|_| invalid("cut selected union accumulation"))?;
    }
    if union.identity() != &drain.drain_union_identity {
        return Err(invalid(
            "cut complete union differs from committed DrainSet",
        ));
    }
    let catalog = overlay
        .publication_catalog
        .as_deref()
        .ok_or(invalid("cut authenticated producer catalog absent"))?;
    for (request, identity) in &members {
        let producer = catalog
            .iter()
            .find(|producer| &producer.request_id == request)
            .ok_or(invalid(
                "cut selected member full publication closure absent",
            ))?;
        if &producer.identity != identity || !producer.applied {
            return Err(invalid(
                "cut selected member original is not independently complete",
            ));
        }
        let request_id: DurableRequestId =
            DurableRequestId::new(*request).map_err(|_| invalid("cut member request identity"))?;
        let receipt = overlay
            .store
            .get_request_receipt(&plan.operation_context, plan.domain, request_id)
            .map_err(|_| invalid("private cut member receipt read"))?
            .ok_or(invalid(
                "cut member independently executed original receipt absent",
            ))?;
        let decoded = crate::NodeDedupRecord::decode(receipt.canonical_bytes())
            .map_err(|_| invalid("cut member receipt schema"))?;
        let (event, result) =
            crate::fast_path::publication::decode_certified_execution_witness(&producer.witness)
                .map_err(|_| invalid("cut member certified original result"))?;
        if decoded.request_id().as_bytes() != request_id.as_bytes()
            || decoded.event_digest() != event
            || receipt.event_digest() != event
            || decoded.responses().len() != 1
            || decoded.responses()[0].payload()
                != Some(
                    execution::paid_execution::encode_paid_execution_result(&result)
                        .map_err(|_| invalid("cut member original result encoding"))?
                        .as_slice(),
                )
        {
            return Err(invalid(
                "cut member exact independently executed original outcome differs",
            ));
        }
    }
    for producer in catalog.iter().filter(|producer| producer.applied) {
        if members.get(&producer.request_id) != Some(&producer.identity) {
            return Err(invalid(
                "cut independently applied owned original is outside committed union",
            ));
        }
    }
    Ok((
        drain,
        candidate_digest,
        [freeze_key, drain_key].into_iter().collect(),
    ))
}

fn terminal(
    ordered: &[OrderedHistoryHeightMaterial],
    identity: &OrderedHistoryIdentity,
) -> Result<(), BusinessCutError> {
    let last: &OrderedHistoryHeightMaterial = ordered
        .last()
        .ok_or(invalid("cut authenticated ordered prefix is empty"))?;
    if last.descriptor.height != identity.through_height || last.descriptor.identity != *identity {
        return Err(invalid("cut terminal proof is not the fixed target"));
    }
    // Private reconstruction already authenticated this exact proof. All three
    // proposals, not just the target, must be candidate-free for this candidate.
    let proof: consensus::CommittedBlockProof = consensus::decode_committed_block_proof(component(
        last,
        OrderedHistoryComponentKind::CommitProof,
    )?)
    .map_err(|_| invalid("cut terminal proof schema"))?;
    if [&proof.committed, &proof.child, &proof.grandchild]
        .iter()
        .any(|proposal| !proposal.transactions.is_empty())
    {
        return Err(invalid(
            "cut fixed target three-chain still contains a candidate",
        ));
    }
    Ok(())
}

/// The private acceptance-only candidate this Seal terminal substitution
/// verifies, named explicitly rather than inferred from any source claim.
pub(super) struct SealAcceptanceCandidate<'a> {
    pub(super) candidate: &'a OrderedCandidate,
    pub(super) candidate_digest: Digest32,
}

/// DR-0187 private acceptance-only terminal: substitutes exactly the
/// ordinary terminal three-empty-proposal rule. The authenticated prior
/// tip at identity.through_height must be committed with an empty proposal,
/// its direct child must be exactly this accepted Seal candidate as its
/// sole transaction, and its grandchild must be empty. Acceptance is the
/// one place a forged header must not be trusted on shape alone, so the
/// terminal three-chain is additionally cryptographically re-verified here,
/// not merely structurally decoded.
fn seal_terminal(
    ordered: &[OrderedHistoryHeightMaterial],
    identity: &OrderedHistoryIdentity,
    policy: &OrderedEconomicsPolicy,
    candidate: &OrderedCandidate,
    candidate_digest: Digest32,
) -> Result<(), BusinessCutError> {
    if candidate.kind != OrderedOperationKind::Seal {
        return Err(invalid("seal acceptance candidate is not a Seal operation"));
    }
    // Pure candidate authentication binds created_checkpoint to the exact
    // intent cut. Acceptance uses the later, independently authenticated prior
    // applied tip: empty-prefix progress may extend the intent's old anchor.
    // Do not conflate those two heights or reject a valid extension here.
    if candidate.created_checkpoint > identity.through_height {
        return Err(invalid(
            "seal claimed cut lies beyond the prior applied tip",
        ));
    }
    let last: &OrderedHistoryHeightMaterial = ordered
        .last()
        .ok_or(invalid("cut authenticated ordered prefix is empty"))?;
    if last.descriptor.height != identity.through_height || last.descriptor.identity != *identity {
        return Err(invalid("cut terminal proof is not the fixed target"));
    }
    let proof: consensus::CommittedBlockProof = consensus::decode_committed_block_proof(component(
        last,
        OrderedHistoryComponentKind::CommitProof,
    )?)
    .map_err(|_| invalid("cut terminal proof schema"))?;
    let block = verified_committed_block(policy, &proof)
        .map_err(|_| invalid("cut seal acceptance terminal proof authentication"))?;
    if block.height != last.descriptor.height
        || block.digest != last.descriptor.block_digest
        || block.view != last.descriptor.view
    {
        return Err(invalid(
            "cut seal acceptance terminal proof disagrees with the prior tip",
        ));
    }
    // Defense in depth beyond verify_committed_block_proof own justify-chain
    // linkage: the committed/child/grandchild heights this exact genuinely
    // authenticated proof names must be the consecutive h-1/h/h+1 sequence
    // this terminal rule is defined over, not merely a structurally
    // decodable three-chain at an unrelated height.
    let seal_height: u64 = block
        .height
        .checked_add(1)
        .ok_or(invalid("cut seal acceptance height overflow"))?;
    let grandchild_height: u64 = seal_height
        .checked_add(1)
        .ok_or(invalid("cut seal acceptance height overflow"))?;
    if proof.child.height != seal_height || proof.grandchild.height != grandchild_height {
        return Err(invalid(
            "cut seal acceptance three-chain heights are not the consecutive h-1/h/h+1 sequence",
        ));
    }
    if !proof.committed.transactions.is_empty() || !proof.grandchild.transactions.is_empty() {
        return Err(invalid(
            "cut seal acceptance three-chain is not prior/empty/empty",
        ));
    }
    if proof.child.transactions.as_slice() != [candidate_digest] {
        return Err(invalid(
            "cut seal acceptance child is not exactly the accepted seal candidate",
        ));
    }
    Ok(())
}

fn companion_keys(
    overlay: &BusinessReconstructionOverlay<'_>,
    ordered: &[OrderedHistoryHeightMaterial],
    controls: &BTreeSet<Vec<u8>>,
    projection: &SemanticProjection,
) -> Result<BTreeSet<DurableRecordKey>, BusinessCutError> {
    let context: &PublicationContext = overlay.plan.genesis_root.manifest().context();
    let chain = context.chain_id();
    let mut keys: BTreeSet<DurableRecordKey> = controls
        .iter()
        .cloned()
        .map(DurableRecordKey::State)
        .collect();
    keys.insert(DurableRecordKey::State(
        engine::ordered_applied_height_key(chain).map_err(|_| invalid("cut applied height key"))?,
    ));
    for material in ordered {
        keys.insert(DurableRecordKey::State(
            engine::ordered_committed_proof_key(chain, context.epoch(), material.descriptor.height)
                .map_err(|_| invalid("cut proof key"))?,
        ));
        if let Some((_, bytes)) = material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
        {
            let candidate: OrderedCandidate = decode_ordered_candidate(bytes)
                .map_err(|_| invalid("cut original candidate schema"))?;
            let digest: Digest32 = overlay
                .plan
                .ordered_policy
                .candidate_digest(&candidate)
                .map_err(|_| invalid("cut original candidate digest"))?;
            for key in [
                engine::ordered_candidate_record_key(chain, digest),
                engine::ordered_request_header_key(chain, &candidate.request_id),
                engine::ordered_outcome_key(chain, &candidate.request_id),
            ] {
                keys.insert(DurableRecordKey::State(
                    key.map_err(|_| invalid("cut ordered companion key"))?,
                ));
            }
            if matches!(
                candidate.kind,
                OrderedOperationKind::Freeze | OrderedOperationKind::DrainSet
            ) {
                keys.insert(DurableRecordKey::Receipt(
                    DurableRequestId::new(candidate.request_id)
                        .map_err(|_| invalid("cut control original identity"))?,
                ));
            }
        }
    }
    for (key, record) in projection {
        if let (DurableRecordKey::State(key), SemanticRecord::State(Some(_))) = (key, record)
            && is_logical_provenance_key(key)
            && !is_logical_profile_key(key)
        {
            // Audit comparison subjects may normalize certificate provenance.
            // Decode only this exact key's independently executed private row,
            // never the comparison-only bytes or any source-provided row.
            let provenance = decode_logical_provenance_record(&required_state(overlay, key)?)
                .map_err(|_| invalid("cut private provenance schema"))?;
            if let LogicalSubject::StateKey(subject) = provenance.subject
                && controls.contains(&subject)
            {
                keys.insert(DurableRecordKey::State(key.clone()));
            }
        }
    }
    // These audit-only subjects are not restorable State. Exact independently
    // applied catalog entries, never prefixes, select their companion keys.
    for producer in overlay
        .publication_catalog
        .as_deref()
        .ok_or(invalid("cut carrier catalog absent"))?
        .iter()
        .filter(|producer| producer.applied)
    {
        keys.insert(DurableRecordKey::State(
            crate::local_instance_state::fastpath_certificate_key(chain, &producer.request_id)
                .map_err(|_| invalid("cut exact Fast carrier key"))?,
        ));
        if producer.availability_identity.is_some() {
            keys.insert(DurableRecordKey::State(
                crate::fast_path::records::fastpath_availability_certificate_key(
                    chain,
                    &producer.request_id,
                )
                .map_err(|_| invalid("cut exact AV carrier key"))?,
            ));
        }
    }
    for key in &keys {
        if !projection.contains_key(key) {
            return Err(invalid("cut exact required authority companion is absent"));
        }
    }
    Ok(keys)
}

fn generation_floor(
    overlay: &BusinessReconstructionOverlay<'_>,
    projection: &SemanticProjection,
) -> Result<ExecutionGeneration, BusinessCutError> {
    let key: Vec<u8> =
        logical_profile_key(overlay.plan.genesis_root.manifest().context().chain_id())
            .map_err(|_| invalid("cut logical profile key"))?;
    let profile = decode_logical_profile_record(&required_state(overlay, &key)?)
        .map_err(|_| invalid("cut logical profile schema"))?;
    let mut floor: ExecutionGeneration = profile.genesis_floor;
    for (key, record) in projection {
        if let (DurableRecordKey::State(key), SemanticRecord::State(Some(_))) = (key, record)
            && is_logical_provenance_key(key)
            && !is_logical_profile_key(key)
        {
            floor = floor.max(
                decode_logical_provenance_record(&required_state(overlay, key)?)
                    .map_err(|_| invalid("cut provenance floor schema"))?
                    .generation,
            );
        }
    }
    for item in overlay
        .publication_catalog
        .as_deref()
        .ok_or(invalid("cut generation catalog absent"))?
        .iter()
        .filter(|item| item.applied)
    {
        let witness = canonical_encoding::decode_canonical_frame(&item.witness)?;
        witness.require_type(0x6424)?;
        witness.require_version(2)?;
        floor = floor.max(ExecutionGeneration::new(witness.required_u64(11)?));
    }
    Ok(floor)
}

pub(super) fn insert(
    overlay: &BusinessReconstructionOverlay<'_>,
    components: &mut BTreeMap<(BusinessCutCollection, Vec<u8>), SavedBusinessCutComponent>,
    collection: BusinessCutCollection,
    key: Vec<u8>,
    metadata: Vec<u8>,
    bytes: Vec<u8>,
) -> Result<(), BusinessCutError> {
    let descriptor: BusinessCutComponentDescriptor = BusinessCutComponentDescriptor {
        collection,
        key: key.clone(),
        metadata,
        length: u64::try_from(bytes.len()).map_err(|_| invalid("cut component length overflow"))?,
        digest: business_cut_component_digest(
            overlay.plan.genesis_root.genesis_resolver(),
            overlay.plan.genesis_root.manifest().context(),
            &bytes,
        )?,
    };
    encode_business_cut_descriptor(&descriptor)?;
    let item: SavedBusinessCutComponent = SavedBusinessCutComponent { descriptor, bytes };
    if let Some(old) = components.insert((collection, key), item.clone())
        && old != item
    {
        return Err(invalid("contradictory cut component natural key"));
    }
    Ok(())
}

fn natural_key(key: &DurableRecordKey) -> Vec<u8> {
    match key {
        DurableRecordKey::State(key) => key.clone(),
        DurableRecordKey::Receipt(id) => id.as_bytes().to_vec(),
        DurableRecordKey::ObjectHead(id) => id.as_bytes().to_vec(),
        DurableRecordKey::ObjectVersion(id, version) => {
            let mut key: Vec<u8> = id.as_bytes().to_vec();
            key.extend_from_slice(&version.get().to_be_bytes());
            key
        }
    }
}
fn semantic_record(record: &SemanticRecord) -> Result<(Vec<u8>, Vec<u8>), BusinessCutError> {
    let mut metadata: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
    let bytes: Vec<u8> = match record {
        SemanticRecord::State(value) => {
            metadata.field_u16(1, 1)?;
            metadata.field_u16(2, u16::from(value.is_some()))?;
            value.clone().unwrap_or_default()
        }
        SemanticRecord::Receipt(event, bytes) => {
            metadata.field_u16(1, 2)?;
            metadata.field_bytes(2, encode_digest32(event)?)?;
            bytes.clone()
        }
        SemanticRecord::Head {
            live,
            version,
            digest,
            owner,
            routing,
        } => {
            metadata.field_u16(1, 3)?;
            metadata.field_u16(2, u16::from(*live))?;
            metadata.field_u64(3, *version)?;
            metadata.field_bytes(
                4,
                digest
                    .as_ref()
                    .map(encode_digest32)
                    .transpose()?
                    .unwrap_or_default(),
            )?;
            metadata.field_u16(5, u16::from(owner.is_some()))?;
            metadata.field_bytes(6, owner.clone().unwrap_or_default())?;
            metadata.field_u16(7, u16::from(routing.is_some()))?;
            metadata.field_bytes(8, routing.clone().unwrap_or_default())?;
            Vec::new()
        }
        SemanticRecord::ObjectVersion {
            digest,
            schema,
            provenance,
            payload,
            bytes,
        } => {
            metadata.field_u16(1, 4)?;
            metadata.field_bytes(2, encode_digest32(digest)?)?;
            metadata.field_u32(3, *schema)?;
            metadata.field_bytes(
                4,
                canonical_encoding::encode_chain_id(provenance.chain_id())?,
            )?;
            metadata.field_u32(5, provenance.protocol_version().get())?;
            match payload {
                DurablePayloadDescriptor::Inline(_) => {
                    metadata.field_u16(6, 1)?;
                    metadata.field_bytes(7, Vec::new())?;
                }
                DurablePayloadDescriptor::BlobReference(digest) => {
                    metadata.field_u16(6, 2)?;
                    metadata.field_bytes(7, encode_digest32(digest)?)?;
                }
            }
            bytes.clone()
        }
    };
    Ok((metadata.finish()?, bytes))
}

pub(super) fn from_overlay(
    overlay: &BusinessReconstructionOverlay<'_>,
    owned: &[OwnedPublicationMaterial],
    ordered: &[OrderedHistoryHeightMaterial],
    controls: &[DrainSetControlMaterial],
    carriers: &BTreeMap<[u8; 32], Vec<u8>>,
    seal: Option<SealAcceptanceCandidate<'_>>,
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    if !overlay.reconstruction_complete {
        return Err(invalid("cut private execution is incomplete"));
    }
    match &seal {
        None => terminal(ordered, overlay.plan.ordered_history_identity)?,
        Some(seal) => seal_terminal(
            ordered,
            overlay.plan.ordered_history_identity,
            overlay.plan.ordered_policy,
            seal.candidate,
            seal.candidate_digest,
        )?,
    }
    let (drain, drain_digest, control_keys) = complete_drain(overlay, ordered, controls)?;
    let projection: SemanticProjection =
        super::super::projection::independently_derived_projection(overlay)?;
    let floor: ExecutionGeneration = generation_floor(overlay, &projection)?;
    let companions: BTreeSet<DurableRecordKey> =
        companion_keys(overlay, ordered, &control_keys, &projection)?;
    let mut components: BTreeMap<(BusinessCutCollection, Vec<u8>), SavedBusinessCutComponent> =
        BTreeMap::new();
    for (key, record) in &projection {
        let mut natural: Vec<u8> = natural_key(key);
        let collection: BusinessCutCollection = if companions.contains(key) {
            let tag: u8 = match key {
                DurableRecordKey::State(_) => 1,
                DurableRecordKey::Receipt(_) => 2,
                _ => return Err(invalid("object cannot be an authority companion")),
            };
            natural.insert(0, tag);
            BusinessCutCollection::AuthorityCompanions
        } else {
            match key {
                DurableRecordKey::State(_) => BusinessCutCollection::State,
                DurableRecordKey::Receipt(_) => BusinessCutCollection::Receipts,
                DurableRecordKey::ObjectHead(_) => BusinessCutCollection::ObjectHeads,
                DurableRecordKey::ObjectVersion(_, _) => BusinessCutCollection::ObjectVersions,
            }
        };
        let (metadata, bytes) = semantic_record(record)?;
        insert(
            overlay,
            &mut components,
            collection,
            natural,
            metadata,
            bytes,
        )?;
    }
    for producer in overlay
        .publication_catalog
        .as_deref()
        .ok_or(invalid("cut producer catalog absent"))?
        .iter()
        .filter(|producer| producer.applied)
    {
        for artifact in &producer.artifacts {
            let mut metadata: CanonicalStruct = CanonicalStruct::new(0x64B9, 1);
            metadata.field_u16(1, 5)?;
            metadata.field_u16(2, artifact.kind.as_u16())?;
            metadata.field_bytes(3, encode_digest32(&artifact.digest)?)?;
            let mut key: Vec<u8> = artifact.kind.as_u16().to_be_bytes().to_vec();
            key.extend(encode_digest32(&artifact.digest)?);
            insert(
                overlay,
                &mut components,
                BusinessCutCollection::Artifacts,
                key,
                metadata.finish()?,
                artifact.bytes.clone(),
            )?;
        }
    }
    proof::verify_application_carriers(overlay, carriers)?;
    proof::add_material(overlay, &mut components, owned, ordered, controls, carriers)?;
    let context: PublicationContext = overlay.plan.genesis_root.manifest().context().clone();
    let streams: [BusinessCutCollectionRoot; 7] = transfer::roots(
        overlay.plan.genesis_root.genesis_resolver(),
        &context,
        overlay.genesis_digest,
        overlay.plan.domain,
        &components,
    )?;
    let identity: BusinessCutIdentity = BusinessCutIdentity {
        context: context.clone(),
        domain: overlay.plan.domain,
        genesis_digest: overlay.genesis_digest,
        validator_set_digest: overlay
            .plan
            .ordered_policy
            .engine()
            .validator_set()
            .digest(overlay.plan.genesis_root.genesis_resolver())
            .map_err(|_| invalid("cut committee digest"))?,
        ordered_history: overlay.plan.ordered_history_identity.clone(),
        drain_request_id: drain.request_id,
        drain_block_height: drain.committed_at_block_height,
        drain_candidate_digest: drain_digest,
        drain_union: drain.drain_union_identity,
        generation_floor: floor,
        business: [
            streams[0].clone(),
            streams[1].clone(),
            streams[2].clone(),
            streams[3].clone(),
        ],
        artifacts: streams[5].clone(),
    };
    let cut_digest: Digest32 =
        business_cut_identity_digest(overlay.plan.genesis_root.genesis_resolver(), &identity)?;
    let mut accumulator: Digest32 = transfer::seed(
        overlay.plan.genesis_root.genesis_resolver(),
        &context,
        identity.genesis_digest,
        identity.domain,
        8,
        Some(cut_digest),
    )?;
    let mut component_count: u64 = 0;
    for item in components.values() {
        accumulator = transfer::fold(
            overlay.plan.genesis_root.genesis_resolver(),
            &context,
            accumulator,
            &item.descriptor,
        )?;
        component_count = component_count
            .checked_add(1)
            .ok_or(invalid("cut exact package count overflow"))?;
    }
    let package: BusinessCutPackageIdentity = BusinessCutPackageIdentity {
        cut_digest,
        streams,
        component_count,
        accumulator,
    };
    let mut prefix_accumulators: BTreeMap<(BusinessCutCollection, Vec<u8>), Digest32> =
        BTreeMap::new();
    for stream in BUSINESS_CUT_STREAMS {
        let mut prefix: Digest32 = transfer::seed(
            overlay.plan.genesis_root.genesis_resolver(),
            &context,
            identity.genesis_digest,
            identity.domain,
            stream as u16,
            None,
        )?;
        for (key, item) in &components {
            if key.0 == stream {
                prefix = transfer::fold(
                    overlay.plan.genesis_root.genesis_resolver(),
                    &context,
                    prefix,
                    &item.descriptor,
                )?;
                prefix_accumulators.insert(key.clone(), prefix);
            }
        }
    }
    let package_digest: Digest32 = business_cut_package_digest(
        overlay.plan.genesis_root.genesis_resolver(),
        &identity,
        &package,
    )?;
    Ok(VerifiedBusinessCut {
        identity,
        package,
        cut_digest,
        package_digest,
        source_token: None,
        components,
        prefix_accumulators,
    })
}

/// DR-0187 private acceptance-only entry point: identical to `from_overlay`
/// in every respect except the one substituted terminal rule (see
/// `seal_terminal`). It reuses the exact same source capture, independent
/// execution, source comparison, drain/body closure, generation floor and
/// business/artifact root derivations as the ordinary pre-Seal producer.
pub(super) fn from_overlay_for_seal_acceptance(
    overlay: &BusinessReconstructionOverlay<'_>,
    owned: &[OwnedPublicationMaterial],
    ordered: &[OrderedHistoryHeightMaterial],
    controls: &[DrainSetControlMaterial],
    carriers: &BTreeMap<[u8; 32], Vec<u8>>,
    seal_candidate: &OrderedCandidate,
    seal_candidate_digest: Digest32,
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    from_overlay(
        overlay,
        owned,
        ordered,
        controls,
        carriers,
        Some(SealAcceptanceCandidate {
            candidate: seal_candidate,
            candidate_digest: seal_candidate_digest,
        }),
    )
}
