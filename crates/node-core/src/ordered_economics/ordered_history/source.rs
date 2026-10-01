//! Read-only bounded source operations. Immutable per-height materials permit
//! a fixed target to remain exportable while the live chain advances. No source
//! snapshot token, whole-history CAS or caller locator is consensus authority.
use super::*;

fn read_required<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    key: &[u8],
) -> Result<Vec<u8>, OrderedEconomicsError> {
    let observed: VersionedStateValue =
        store.get_versioned_durable(context, env.policy.domain(), key)?;
    observed.value().map(<[u8]>::to_vec).ok_or(invalid(
        "ordered history required archive/material is missing or tombstoned",
    ))
}

fn read_proof<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    height: u64,
) -> Result<(Vec<u8>, CommittedBlock), OrderedEconomicsError> {
    if height == 0 {
        return Err(invalid("genesis has no archived committed proposal"));
    }
    let key: Vec<u8> = engine::ordered_committed_proof_key(
        env.policy.context().chain_id(),
        env.policy.context().epoch(),
        height,
    )?;
    let bytes: Vec<u8> = read_required(store, context, env, &key)?;
    let proof: CommittedBlockProof = decode_committed_block_proof(&bytes)
        .map_err(|_| invalid("ordered history archived proof encoding"))?;
    let block: CommittedBlock = verified_committed_block(env.policy, &proof)?;
    if block.height != height {
        return Err(invalid("ordered history archived proof height mismatch"));
    }
    Ok((bytes, block))
}

/// Advertises the source's current applied tip. Consumers must verify the entire
/// genesis-to-target stream, and must not infer network freshness.
pub fn query_ordered_history_summary<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<OrderedHistorySummary, OrderedEconomicsError> {
    let status: OrderedStatus = engine::query_status(store, context, env)?;
    let (applied, _, _): (u64, Vec<u8>, StateRevision) =
        engine::load_applied_height(store, context, env)?;
    if applied != status.committed_height {
        return Err(invalid(
            "ordered history applied prefix does not match committed tip",
        ));
    }
    let (through_view, through_digest): (u64, Digest32) = if applied == 0 {
        (0, env.policy.anchor())
    } else {
        let (_, block): (Vec<u8>, CommittedBlock) = read_proof(store, context, env, applied)?;
        (block.view, block.digest)
    };
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: env.policy.context().clone(),
        domain: env.policy.domain(),
        genesis_digest: env.policy.genesis_digest(),
        anchor: env.policy.anchor(),
        through_height: applied,
        through_view,
        through_digest,
    };
    identity.validate(env.policy)?;
    Ok(OrderedHistorySummary { identity })
}

fn read_material<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    identity: &OrderedHistoryIdentity,
    height: u64,
) -> Result<OrderedHistoryHeightMaterial, OrderedEconomicsError> {
    use OrderedHistoryComponentKind as Kind;
    identity.validate(env.policy)?;
    if height == 0 || height > identity.through_height {
        return Err(invalid(
            "ordered history requested height outside fixed target",
        ));
    }
    // The target locator is not authoritative: independently reverify it.
    let (_, target): (Vec<u8>, CommittedBlock) =
        read_proof(store, context, env, identity.through_height)?;
    if target.view != identity.through_view || target.digest != identity.through_digest {
        return Err(invalid(
            "ordered history target does not match source archive",
        ));
    }
    let (proof_bytes, block): (Vec<u8>, CommittedBlock) = read_proof(store, context, env, height)?;
    let mut components: Vec<(Kind, Vec<u8>)> = vec![(Kind::CommitProof, proof_bytes)];
    if let Some(digest) = block.transactions.first() {
        let chain: &ChainId = env.policy.context().chain_id();
        let candidate_key: Vec<u8> = engine::ordered_candidate_record_key(chain, *digest)?;
        let candidate_bytes: Vec<u8> = read_required(store, context, env, &candidate_key)?;
        let candidate: OrderedCandidate = decode_ordered_candidate(&candidate_bytes)?;
        let header_key: Vec<u8> = engine::ordered_request_header_key(chain, &candidate.request_id)?;
        let header_bytes: Vec<u8> = read_required(store, context, env, &header_key)?;
        let outcome_key: Vec<u8> = engine::ordered_outcome_key(chain, &candidate.request_id)?;
        let outcome_bytes: Vec<u8> = read_required(store, context, env, &outcome_key)?;
        let outcome: OrderedOutcome = engine::decode_retained_outcome(&outcome_bytes)?;
        let request_id: DurableRequestId = DurableRequestId::new(candidate.request_id)
            .map_err(|_| invalid("ordered history invalid original request identity"))?;
        let receipt: DurableRequestReceipt = store
            .get_request_receipt(context, env.policy.domain(), request_id)?
            .ok_or(invalid("ordered history original receipt is missing"))?;
        let record: NodeDedupRecord = NodeDedupRecord::decode(receipt.canonical_bytes())?;
        if receipt.request_id() != request_id
            || record.request_id().as_bytes() != &candidate.request_id
            || record.event_digest() != receipt.event_digest()
        {
            return Err(invalid(
                "ordered history durable original receipt metadata mismatch",
            ));
        }
        components.push((Kind::Candidate, candidate_bytes));
        components.push((Kind::RequestHeader, header_bytes));
        components.push((Kind::RetainedOutcome, outcome_bytes));
        components.push((Kind::OriginalReceipt, receipt.canonical_bytes().to_vec()));
        if outcome.block_height < height {
            let (origin, _): (Vec<u8>, CommittedBlock) =
                read_proof(store, context, env, outcome.block_height)?;
            components.push((Kind::ReplayOriginProof, origin));
        }
    }
    let mut references: Vec<OrderedHistoryComponentRef> = Vec::with_capacity(components.len());
    for (kind, bytes) in &components {
        let length: u64 = u64::try_from(bytes.len())
            .map_err(|_| invalid("ordered history component length overflow"))?;
        references.push(OrderedHistoryComponentRef {
            kind: *kind,
            length,
            digest: ordered_history_component_digest(env.policy, bytes)?,
        });
    }
    let descriptor: OrderedHistoryHeightDescriptor = OrderedHistoryHeightDescriptor {
        identity: identity.clone(),
        height: block.height,
        view: block.view,
        block_digest: block.digest,
        components: references,
    };
    let material: OrderedHistoryHeightMaterial = OrderedHistoryHeightMaterial {
        descriptor,
        components,
    };
    verify_material(env.policy, &material)?;
    Ok(material)
}

/// Reads one independently reverified small descriptor. No scan or mutation.
pub fn read_ordered_history_height_descriptor<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    identity: &OrderedHistoryIdentity,
    height: u64,
) -> Result<OrderedHistoryHeightDescriptor, OrderedEconomicsError> {
    Ok(read_material(store, context, env, identity, height)?.descriptor)
}

/// Reads at most one MiB under an exact independently checked descriptor.
/// Immutable rows must still match the previously selected digest/length.
/// Offset equal to length is not an implicit empty terminal chunk.
#[allow(clippy::too_many_arguments)]
pub fn read_ordered_history_component_chunk<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    identity: &OrderedHistoryIdentity,
    height: u64,
    descriptor_digest: Digest32,
    kind: OrderedHistoryComponentKind,
    offset: u64,
    limit: u32,
) -> Result<Vec<u8>, OrderedEconomicsError> {
    let limit: usize =
        usize::try_from(limit).map_err(|_| invalid("ordered history chunk limit overflow"))?;
    if limit == 0 || limit > MAX_ORDERED_HISTORY_CHUNK_BYTES {
        return Err(invalid("ordered history chunk limit"));
    }
    let material: OrderedHistoryHeightMaterial =
        read_material(store, context, env, identity, height)?;
    if ordered_history_descriptor_digest(env.policy, &material.descriptor)? != descriptor_digest {
        return Err(invalid("ordered history descriptor changed"));
    }
    let bytes: &[u8] = component(&material, kind)?;
    let start: usize =
        usize::try_from(offset).map_err(|_| invalid("ordered history chunk offset overflow"))?;
    if start >= bytes.len() {
        return Err(invalid("ordered history chunk offset outside component"));
    }
    let end: usize = start
        .checked_add(limit)
        .ok_or(invalid("ordered history chunk end overflow"))?
        .min(bytes.len());
    Ok(bytes[start..end].to_vec())
}
