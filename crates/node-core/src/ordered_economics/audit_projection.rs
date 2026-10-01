//! Typed validation of replica-local rows for the read-only semantic audit.
//! Committed headers, outcomes, candidate bytes and per-height proofs are not
//! discarded: they remain exact comparison facts of independent execution.
use super::{
    OrderedCandidate, OrderedEconomicsPolicy, OrderedHistoryIdentity, drain_union, engine, freeze,
    frontier, identity, policy::Ed25519ConsensusVerifier, reservation,
};
use crate::NodeCoreError;
use crate::business_reconstruction::SourceSnapshotRecord;
use canonical_encoding::encode_chain_id;
use consensus::{
    DrainUnionAccumulator, FrozenFrontierCertifier, FrozenFrontierIdentity, FrozenFrontierVote,
    decode_availability_identity, decode_consensus_state, verify_frozen_frontier_quorum,
};
use hashing::HashSuiteResolver;
use protocol_types::{Digest32, ValidatorId};
use runtime::portable::{DurableRecordKey, DurableRecordMetadata};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct AuditLocalRows {
    pub(crate) excluded: BTreeSet<Vec<u8>>,
    pub(crate) internal_receipts: BTreeMap<[u8; 32], Digest32>,
}

fn invalid(reason: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(reason)
}

fn tail<'a>(
    key: &'a [u8],
    family: &[u8],
    chain: &[u8],
    width: usize,
) -> Result<Option<&'a [u8]>, NodeCoreError> {
    let Some(suffix) = key.strip_prefix(engine::ORDERED_ECONOMICS_STATE_PREFIX) else {
        return Ok(None);
    };
    let Some(suffix) = suffix.strip_prefix(family) else {
        return Ok(None);
    };
    let suffix: &[u8] = suffix
        .strip_prefix(chain)
        .ok_or(invalid("ordered local key names another chain"))?;
    if suffix.len() != width {
        return Err(invalid("ordered local key has an unknown suffix"));
    }
    Ok(Some(suffix))
}

fn present(row: &SourceSnapshotRecord) -> Result<&[u8], NodeCoreError> {
    row.value
        .as_deref()
        .ok_or(invalid("deleted immutable ordered local row"))
}

fn validate_frontier(
    policy: &OrderedEconomicsPolicy,
    closure: &freeze::AdmissionClosureRecord,
    frontier: &FrozenFrontierIdentity,
) -> Result<(), NodeCoreError> {
    if frontier.chain_id != *policy.context().chain_id()
        || frontier.protocol_version != policy.context().protocol_version()
        || frontier.epoch != policy.context().epoch()
        || frontier.domain != policy.domain()
        || frontier.closure_request_id != closure.request_id
        || frontier.closure_height != closure.closed_at_block_height
    {
        return Err(invalid(
            "local frontier differs from exact committed Freeze",
        ));
    }
    Ok(())
}

fn validate_selection(
    policy: &OrderedEconomicsPolicy,
    resolver: &HashSuiteResolver,
    closure: &freeze::AdmissionClosureRecord,
    votes: &[FrozenFrontierVote],
    selection: Digest32,
) -> Result<(), NodeCoreError> {
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        policy.context().chain_id().clone(),
        policy.context().protocol_version(),
        policy.context().epoch(),
        policy.engine().validator_set().clone(),
    )
    .map_err(|_| invalid("local frontier authority"))?;
    verify_frozen_frontier_quorum(
        &certifier,
        votes,
        policy.domain(),
        closure.request_id,
        closure.closed_at_block_height,
        &Ed25519ConsensusVerifier,
    )
    .map_err(|_| invalid("local union frontier selection lacks a genuine quorum"))?;
    let pairs: Vec<(ValidatorId, FrozenFrontierIdentity)> = votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let seed: DrainUnionAccumulator = DrainUnionAccumulator::new(
        resolver,
        policy.context().chain_id().clone(),
        policy.context().protocol_version(),
        policy.context().epoch(),
        policy.domain(),
        closure.request_id,
        closure.closed_at_block_height,
        &pairs,
    )
    .map_err(|_| invalid("local union selection seed"))?;
    if seed.identity().entries_digest != selection {
        return Err(invalid("local union selection digest differs"));
    }
    Ok(())
}

/// All source-local exclusions are typed, exact-key checked and inert. The
/// reconstructed key set identifies which immutable admission header/candidate
/// actually belongs to the independently certified committed prefix.
pub(crate) fn validate_local_rows(
    policy: &OrderedEconomicsPolicy,
    target: &OrderedHistoryIdentity,
    resolver: &HashSuiteResolver,
    records: &[SourceSnapshotRecord],
    reconstructed: BTreeSet<Vec<u8>>,
    is_source: bool,
) -> Result<AuditLocalRows, NodeCoreError> {
    let chain: Vec<u8> = encode_chain_id(policy.context().chain_id())?;
    let rows: BTreeMap<Vec<u8>, &SourceSnapshotRecord> = records
        .iter()
        .filter_map(|row| match row.descriptor.key() {
            DurableRecordKey::State(key) => Some((key.clone(), row)),
            _ => None,
        })
        .collect();
    let mut result: AuditLocalRows = AuditLocalRows {
        excluded: BTreeSet::new(),
        internal_receipts: BTreeMap::new(),
    };
    let closure_key: Vec<u8> =
        freeze::admission_closure_key(policy.context().chain_id(), policy.context().epoch())?;
    let closure: Option<freeze::AdmissionClosureRecord> = rows
        .get(&closure_key)
        .map(|row| freeze::decode_admission_closure_record(present(row)?))
        .transpose()?;
    if closure.as_ref().is_some_and(|closure| {
        closure.closed_epoch != policy.context().epoch()
            || closure.closed_at_block_height > target.through_height
    }) {
        return Err(invalid("local progress Freeze lies outside fixed history"));
    }
    let mut candidates: BTreeMap<Digest32, OrderedCandidate> = BTreeMap::new();
    let mut views: Vec<(reservation::OrderedAdmissionStage, u64, Option<Digest32>)> = Vec::new();
    let mut source_state_seen: bool = false;
    // Build authenticated candidate identities before checking their local
    // header/receipt associations; input enumeration order is not authority.
    for (key, row) in &rows {
        if let Some(bytes) = tail(key, b"candidate/", &chain, 32)? {
            let candidate: OrderedCandidate = super::decode_ordered_candidate(present(row)?)?;
            policy
                .authenticate_candidate(&candidate)
                .map_err(|_| invalid("local retained candidate authentication failed"))?;
            let digest: Digest32 =
                engine::candidate_digest(resolver, policy.context().epoch(), present(row)?)
                    .map_err(|_| invalid("local candidate digest"))?;
            if digest.bytes().as_slice() != bytes {
                return Err(invalid(
                    "local candidate key disagrees with authenticated bytes",
                ));
            }
            candidates.insert(digest, candidate);
            if !reconstructed.contains(key) {
                result.excluded.insert(key.clone());
            }
        }
    }
    for (key, row) in &rows {
        if tail(key, b"state/", &chain, 0)?.is_some() {
            let state = decode_consensus_state(present(row)?)
                .map_err(|_| invalid("source consensus state schema"))?;
            policy
                .engine()
                .validate_state(&state, &Ed25519ConsensusVerifier)
                .map_err(|_| invalid("source consensus state verification"))?;
            if is_source {
                source_state_seen = true;
                if state.committed_height != target.through_height
                    || (target.through_height != 0
                        && !state.contains_committed(&target.through_digest))
                {
                    return Err(invalid(
                        "source consensus committed tip differs from fixed history",
                    ));
                }
            }
            // Pacemaker times, pending QCs/votes and local last-signature
            // coordinates are validated safety state, not business effects.
            result.excluded.insert(key.clone());
        } else if let Some(request_bytes) = tail(key, b"header/", &chain, 32)? {
            let header = engine::decode_request_header(present(row)?)?;
            if engine::encode_request_header(&header)? != present(row)? {
                return Err(invalid("noncanonical local admission header"));
            }
            let candidate: &OrderedCandidate = candidates.get(&header.candidate_digest).ok_or(
                invalid("admission header lacks authenticated retained candidate"),
            )?;
            if candidate.request_id.as_slice() != request_bytes
                || candidate.kind != header.kind
                || candidate.created_checkpoint != header.created_checkpoint
            {
                return Err(invalid("local admission header differs from candidate"));
            }
            if !reconstructed.contains(key) {
                result.excluded.insert(key.clone());
            }
        } else if let Some(view_bytes) = tail(key, b"leader-proposal/", &chain, 8)? {
            let view: u64 = u64::from_be_bytes(
                view_bytes
                    .try_into()
                    .map_err(|_| invalid("local leader view"))?,
            );
            let (retained, proposal) = identity::decode_leader_proposal_record(present(row)?)?;
            policy
                .engine()
                .verify_proposal(&proposal, &Ed25519ConsensusVerifier)
                .map_err(|_| invalid("local leader proposal signature"))?;
            if retained.view != view
                || retained.proposal_digest
                    != policy
                        .engine()
                        .proposal_digest(&proposal)
                        .map_err(|_| invalid("local proposal digest"))?
                || proposal.transactions.len() > 1
            {
                return Err(invalid("local leader key/digest/proposal shape differs"));
            }
            if let Some(digest) = proposal.transactions.first() {
                if !candidates.contains_key(digest) {
                    return Err(invalid(
                        "local leader proposal lacks authenticated candidate",
                    ));
                }
                views.push((
                    reservation::OrderedAdmissionStage::LeaderProposal,
                    view,
                    Some(*digest),
                ));
            }
            result.excluded.insert(key.clone());
        } else if let Some(view_bytes) = tail(key, b"vote/", &chain, 8)? {
            let view: u64 = u64::from_be_bytes(
                view_bytes
                    .try_into()
                    .map_err(|_| invalid("local vote view"))?,
            );
            let (retained, vote) = identity::decode_local_vote_record(present(row)?)?;
            policy
                .engine()
                .verify_vote(&vote, &Ed25519ConsensusVerifier)
                .map_err(|_| invalid("local retained vote signature"))?;
            if retained.view != view {
                return Err(invalid("local vote key differs"));
            }
            // Old votes can outlive their pruned consensus proposal. Their
            // empty admission receipt still binds its own authenticated
            // candidate digest and exact view through the dedicated preimage.
            views.push((reservation::OrderedAdmissionStage::Vote, view, None));
            result.excluded.insert(key.clone());
        } else if tail(key, b"vote-high/", &chain, 0)?.is_some() {
            identity::decode_vote_high_water(present(row)?)?;
            result.excluded.insert(key.clone());
        } else if let Some(request) = tail(key, b"reservation/", &chain, 32)? {
            let request: [u8; 32] = request
                .try_into()
                .map_err(|_| invalid("local reservation id"))?;
            let held = row
                .value
                .as_deref()
                .map(reservation::decode_ordered_reservation)
                .transpose()?;
            if reservation::ordered_reservation_key(policy.context().chain_id(), &request)? != *key
                || request[0] & 0x80 == 0
                || crate::local_instance_state::is_reserved_paid_request_id(&request)
                || held
                    .as_ref()
                    .and_then(|held| held.nonce)
                    .is_some_and(|nonce| nonce.epoch != policy.context().epoch())
            {
                return Err(invalid("local reservation key/lane differs"));
            }
            result.excluded.insert(key.clone());
        } else if tail(key, b"frontier-progress/", &chain, 8)?.is_some() {
            let closure = closure
                .as_ref()
                .ok_or(invalid("frontier progress has no committed Freeze"))?;
            let cursor = frontier::decode_cursor(present(row)?)
                .map_err(|_| invalid("frontier progress schema"))?;
            validate_frontier(policy, closure, &cursor.identity)?;
            if cursor.last_request_id == [0; 32]
                || frontier::key(
                    policy.context().chain_id(),
                    policy.context().epoch(),
                    b"frontier-progress/",
                )
                .map_err(|_| invalid("frontier progress key"))?
                    != *key
            {
                return Err(invalid("frontier progress key/cursor differs"));
            }
            result.excluded.insert(key.clone());
        } else if tail(key, b"frontier/", &chain, 8)?.is_some() {
            let closure = closure
                .as_ref()
                .ok_or(invalid("frontier has no committed Freeze"))?;
            let final_record = frontier::decode_final(present(row)?)
                .map_err(|_| invalid("final frontier schema"))?;
            validate_frontier(policy, closure, &final_record.identity)?;
            let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
                policy.context().chain_id().clone(),
                policy.context().protocol_version(),
                policy.context().epoch(),
                policy.engine().validator_set().clone(),
            )
            .map_err(|_| invalid("frontier authority"))?;
            certifier
                .verify_vote(&final_record.vote, &Ed25519ConsensusVerifier)
                .map_err(|_| invalid("final frontier vote signature"))?;
            if frontier::key(
                policy.context().chain_id(),
                policy.context().epoch(),
                b"frontier/",
            )
            .map_err(|_| invalid("frontier key"))?
                != *key
            {
                return Err(invalid("final frontier key differs"));
            }
            result.excluded.insert(key.clone());
        } else if let Some(suffix) = tail(key, b"drain-signer-progress/", &chain, 40)? {
            let closure = closure
                .as_ref()
                .ok_or(invalid("signer progress has no committed Freeze"))?;
            let record = drain_union::decode_signer_progress(present(row)?)
                .map_err(|_| invalid("drain signer progress schema"))?;
            validate_frontier(policy, closure, &record.vote.identity)?;
            validate_frontier(policy, closure, &record.confirmed_identity)?;
            let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
                policy.context().chain_id().clone(),
                policy.context().protocol_version(),
                policy.context().epoch(),
                policy.engine().validator_set().clone(),
            )
            .map_err(|_| invalid("drain signer authority"))?;
            certifier
                .verify_vote(&record.vote, &Ed25519ConsensusVerifier)
                .map_err(|_| invalid("drain signer vote signature"))?;
            if record.vote.validator.as_bytes().as_slice() != &suffix[8..]
                || drain_union::drain_signer_progress_key(
                    policy.context().chain_id(),
                    policy.context().epoch(),
                    record.vote.validator,
                )
                .map_err(|_| invalid("signer progress key"))?
                    != *key
            {
                return Err(invalid("signer progress key/identity differs"));
            }
            result.excluded.insert(key.clone());
        } else if let Some(suffix) = tail(key, b"drain-signer-entry/", &chain, 72)? {
            let _closure = closure
                .as_ref()
                .ok_or(invalid("signer entry has no committed Freeze"))?;
            let signer: ValidatorId = ValidatorId::new(
                suffix[8..40]
                    .try_into()
                    .map_err(|_| invalid("signer entry signer"))?,
            );
            let identity = decode_availability_identity(present(row)?)
                .map_err(|_| invalid("signer entry availability schema"))?;
            if policy.registered_validator(signer).is_none()
                || identity.request_id.as_slice() != &suffix[40..]
                || identity.domain != policy.domain()
                || identity.chain_id != *policy.context().chain_id()
                || identity.protocol_version != policy.context().protocol_version()
                || identity.epoch != policy.context().epoch()
                || drain_union::drain_signer_entry_key(
                    policy.context().chain_id(),
                    policy.context().epoch(),
                    signer,
                    &identity.request_id,
                )
                .map_err(|_| invalid("signer entry key"))?
                    != *key
            {
                return Err(invalid("signer entry key/context differs"));
            }
            result.excluded.insert(key.clone());
        } else if let Some(suffix) = tail(key, b"drain-possession/", &chain, 40)? {
            let _closure = closure
                .as_ref()
                .ok_or(invalid("possession has no committed Freeze"))?;
            let identity = decode_availability_identity(present(row)?)
                .map_err(|_| invalid("possession availability schema"))?;
            if identity.request_id.as_slice() != &suffix[8..]
                || identity.domain != policy.domain()
                || identity.chain_id != *policy.context().chain_id()
                || identity.protocol_version != policy.context().protocol_version()
                || identity.epoch != policy.context().epoch()
                || crate::fast_path::drain_publication::drain_possession_key(
                    policy.context().chain_id(),
                    policy.context().epoch(),
                    &identity.request_id,
                )
                .map_err(|_| invalid("possession key"))?
                    != *key
            {
                return Err(invalid("possession key/context differs"));
            }
            result.excluded.insert(key.clone());
        } else {
            let progress = tail(key, b"drain-union-progress/", &chain, 40)?;
            let ready = tail(key, b"drain-union-ready/", &chain, 40)?;
            if progress.is_some() || ready.is_some() {
                let closure = closure
                    .as_ref()
                    .ok_or(invalid("union has no committed Freeze"))?;
                let (identity, selection, votes) = if progress.is_some() {
                    let record = drain_union::decode_union_progress(present(row)?)
                        .map_err(|_| invalid("local union progress schema"))?;
                    (
                        record.identity,
                        record.selection_digest,
                        record.selected_votes,
                    )
                } else {
                    let record = drain_union::decode_union_ready(present(row)?)
                        .map_err(|_| invalid("local union ready schema"))?;
                    (
                        record.identity,
                        record.selection_digest,
                        record.selected_votes,
                    )
                };
                validate_selection(policy, resolver, closure, &votes, selection)?;
                let expected_key: Vec<u8> = if progress.is_some() {
                    drain_union::drain_union_progress_key(
                        policy.context().chain_id(),
                        policy.context().epoch(),
                        &selection,
                    )
                } else {
                    drain_union::drain_union_ready_key(
                        policy.context().chain_id(),
                        policy.context().epoch(),
                        &selection,
                    )
                }
                .map_err(|_| invalid("local union key"))?;
                if expected_key != *key
                    || identity.chain_id != *policy.context().chain_id()
                    || identity.protocol_version != policy.context().protocol_version()
                    || identity.epoch != policy.context().epoch()
                    || identity.domain != policy.domain()
                    || identity.closure_request_id != closure.request_id
                    || identity.closure_height != closure.closed_at_block_height
                    || identity.signer_count != votes.len() as u64
                {
                    return Err(invalid("local union key/identity differs"));
                }
                result.excluded.insert(key.clone());
            }
        }
    }
    if is_source && !source_state_seen {
        return Err(invalid(
            "source has no independently validated consensus tip",
        ));
    }
    // An internal receipt is excluded only when its own digest selects one
    // authenticated candidate and a retained exact-view local signing record
    // explains the dedicated stage-specific synthetic identity. No business
    // response may be hidden inside it (the projection checks that separately).
    for row in records {
        let (
            DurableRecordKey::Receipt(request),
            DurableRecordMetadata::Receipt { event_digest, .. },
        ) = (row.descriptor.key(), row.descriptor.metadata())
        else {
            continue;
        };
        if !crate::local_instance_state::is_reserved_paid_request_id(request.as_bytes()) {
            continue;
        }
        let Some(candidate) = candidates.get(event_digest) else {
            continue;
        };
        for (stage, view, known_candidate) in &views {
            if known_candidate.is_some_and(|known| known != *event_digest) {
                continue;
            }
            let expected: [u8; 32] = reservation::ordered_admission_request_id(
                resolver,
                policy.context().epoch(),
                &candidate.request_id,
                *event_digest,
                *stage,
                *view,
            )?;
            if expected == *request.as_bytes() {
                result.internal_receipts.insert(expected, *event_digest);
                break;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::tail;

    #[test]
    fn local_bookkeeping_key_parser_never_ignores_unknown_suffix_or_chain() {
        let prefix: &[u8] = super::engine::ORDERED_ECONOMICS_STATE_PREFIX;
        let chain: &[u8] = b"one-locally-pinned-chain";
        let key: Vec<u8> = [prefix, b"vote/", chain, &[1; 8]].concat();
        assert_eq!(tail(&key, b"vote/", chain, 8).unwrap(), Some(&[1; 8][..]));
        let malformed: Vec<u8> = [key.as_slice(), b"extra"].concat();
        assert!(tail(&malformed, b"vote/", chain, 8).is_err());
        assert!(tail(&key, b"vote/", b"another-chain", 8).is_err());
        assert!(tail(&key, b"unknown-local/", chain, 8).unwrap().is_none());
    }
}
