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

fn live_tail<'a>(
    policy: &OrderedEconomicsPolicy,
    key: &'a [u8],
    family: &[u8],
    chain: &[u8],
    width: usize,
) -> Result<Option<&'a [u8]>, NodeCoreError> {
    let Some(scope) = policy.key_scope().successor_scope_bytes()? else {
        return tail(key, family, chain, width);
    };
    let prefix: Vec<u8> = [
        engine::ORDERED_ECONOMICS_STATE_PREFIX,
        b"epoch-",
        family,
        chain,
        &scope,
    ]
    .concat();
    let Some(suffix) = key.strip_prefix(prefix.as_slice()) else {
        return Ok(None);
    };
    if suffix.len() != width {
        return Err(invalid("current ordered safety key suffix"));
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

fn signer_progress_for_exclusion(
    resolver: &HashSuiteResolver,
    bytes: &[u8],
) -> Result<drain_union::SignerProgressRecord, NodeCoreError> {
    let record: drain_union::SignerProgressRecord = drain_union::decode_signer_progress(bytes)
        .map_err(|_| invalid("drain signer progress schema"))?;
    drain_union::validate_signer_progress_consistency(resolver, &record)
        .map_err(|_| invalid("drain signer progress consistency differs"))?;
    Ok(record)
}

fn union_progress_for_exclusion(
    resolver: &HashSuiteResolver,
    bytes: &[u8],
) -> Result<drain_union::UnionProgressRecord, NodeCoreError> {
    let record: drain_union::UnionProgressRecord = drain_union::decode_union_progress(bytes)
        .map_err(|_| invalid("local union progress schema"))?;
    let selected: Vec<(ValidatorId, FrozenFrontierIdentity)> = record
        .selected_votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    // This is the owner's consistency check only, not authority for a remote
    // running digest. Signature/quorum/Freeze validation still follows before
    // exclusion, and no source progress is installed into reconstruction.
    DrainUnionAccumulator::resume(
        resolver,
        record.identity.clone(),
        record.last_request_id,
        &selected,
    )
    .map_err(|_| invalid("local union progress consistency differs"))?;
    Ok(record)
}

/// A source cut already owns the complete captured corpus. Validate its
/// current index as one contiguous logical prefix before excluding any of
/// that private metadata. This is not a live scan or DrainSet evidence.
fn validate_index_corpus(
    resolver: &HashSuiteResolver,
    cursor: &frontier::FrontierCursor,
    entries: &[frontier::FrontierEntry],
) -> Result<(), NodeCoreError> {
    if !cursor.indexed {
        return if entries.is_empty() {
            Ok(())
        } else {
            Err(invalid("pre-index progress cannot own index entries"))
        };
    }
    let identity: &FrozenFrontierIdentity = &cursor.identity;
    let mut accumulator: consensus::FrozenFrontierAccumulator =
        consensus::FrozenFrontierAccumulator::new(
            resolver,
            identity.chain_id.clone(),
            identity.protocol_version,
            identity.epoch,
            identity.domain,
            identity.closure_request_id,
            identity.closure_height,
        )
        .map_err(|_| invalid("frontier index corpus seed"))?;
    for entry in entries {
        let ordinal: u64 = accumulator
            .identity()
            .entry_count
            .checked_add(1)
            .ok_or(invalid("frontier index corpus ordinal overflow"))?;
        if entry.ordinal != ordinal {
            return Err(invalid(
                "frontier index corpus ordinals are not consecutive",
            ));
        }
        accumulator
            .push(resolver, &entry.publication)
            .map_err(|_| invalid("frontier index corpus publication order or scope differs"))?;
    }
    if accumulator.last_request_id() != cursor.last_request_id
        || accumulator.into_identity() != cursor.identity
    {
        return Err(invalid(
            "frontier index corpus count, tail or fold differs from progress",
        ));
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
    // Only this independently verified current policy may authenticate a
    // live epoch-scoped safety row. Earlier protected rows are separated
    // by the verified reconstruction base before this current-row audit.
    for key in rows.keys() {
        if engine::is_successor_scoped_ordered_key(key)
            && !engine::is_ordered_key_of_scope(
                key,
                policy.context().chain_id(),
                policy.key_scope(),
            )?
        {
            return Err(invalid(
                "unverified epoch-scoped ordered row cannot be audited",
            ));
        }
    }
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
    let mut frontier_cursor: Option<frontier::FrontierCursor> = None;
    let mut frontier_entries: Vec<frontier::FrontierEntry> = Vec::new();
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
        if live_tail(policy, key, b"state/", &chain, 0)?.is_some() {
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
        } else if let Some(view_bytes) = live_tail(policy, key, b"leader-proposal/", &chain, 8)? {
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
        } else if let Some(view_bytes) = live_tail(policy, key, b"vote/", &chain, 8)? {
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
        } else if live_tail(policy, key, b"vote-high/", &chain, 0)?.is_some() {
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
            consensus::FrozenFrontierAccumulator::resume(
                resolver,
                cursor.identity.clone(),
                cursor.last_request_id,
            )
            .map_err(|_| invalid("frontier progress logical tail or empty seed differs"))?;
            if frontier::key(
                policy.context().chain_id(),
                policy.context().epoch(),
                b"frontier-progress/",
            )
            .map_err(|_| invalid("frontier progress key"))?
                != *key
            {
                return Err(invalid("frontier progress key/cursor differs"));
            }
            frontier_cursor = Some(cursor);
            result.excluded.insert(key.clone());
        } else if tail(key, b"frontier-entry/", &chain, 40)?.is_some() {
            let closure = closure
                .as_ref()
                .ok_or(invalid("frontier entry has no committed Freeze"))?;
            let entry: frontier::FrontierEntry = frontier::decode_entry(present(row)?)
                .map_err(|_| invalid("frontier entry schema"))?;
            frontier::validate_entry(&entry, policy.context(), policy.domain(), closure)
                .map_err(|_| invalid("frontier entry scope or Freeze differs"))?;
            if frontier::entry_key(
                policy.context().chain_id(),
                policy.context().epoch(),
                &entry.publication.request_id,
            )
            .map_err(|_| invalid("frontier entry natural key"))?
                != *key
            {
                return Err(invalid("frontier entry exact key differs"));
            }
            let cursor_key: Vec<u8> = frontier::key(
                policy.context().chain_id(),
                policy.context().epoch(),
                b"frontier-progress/",
            )
            .map_err(|_| invalid("frontier entry progress key"))?;
            let cursor: frontier::FrontierCursor = frontier::decode_cursor(present(
                rows.get(&cursor_key)
                    .ok_or(invalid("frontier entry is orphaned"))?,
            )?)
            .map_err(|_| invalid("frontier entry progress schema"))?;
            validate_frontier(policy, closure, &cursor.identity)?;
            consensus::FrozenFrontierAccumulator::resume(
                resolver,
                cursor.identity.clone(),
                cursor.last_request_id,
            )
            .map_err(|_| invalid("frontier entry progress consistency"))?;
            if !cursor.indexed
                || entry.ordinal > cursor.identity.entry_count
                || cursor
                    .last_request_id
                    .is_none_or(|last: [u8; 32]| entry.publication.request_id > last)
                || ((entry.ordinal == cursor.identity.entry_count)
                    != (cursor.last_request_id == Some(entry.publication.request_id)))
            {
                return Err(invalid("frontier entry and indexed progress differ"));
            }
            let publication_key: Vec<u8> = crate::fast_path::publication::fastpath_publication_key(
                policy.context().chain_id(),
                &entry.publication.request_id,
            )?;
            let publication: crate::fast_path::publication::FastPathPublicationRecord =
                crate::fast_path::publication::decode_fastpath_publication_record(present(
                    rows.get(&publication_key)
                        .ok_or(invalid("frontier entry publication is absent"))?,
                )?)
                .map_err(|_| invalid("frontier entry publication schema"))?;
            if publication.context != *policy.context()
                || publication.request_id != entry.publication.request_id
                || decode_availability_identity(&publication.identity)
                    .map_err(|_| invalid("frontier entry publication identity schema"))?
                    != entry.publication
            {
                return Err(invalid("frontier entry differs from current publication"));
            }
            // `rows` is a natural-key BTreeMap. Exact current epoch/key
            // validation above means this is the index's request-ID order.
            frontier_entries.push(entry);
            result.excluded.insert(key.clone());
        } else if tail(key, b"frontier/", &chain, 8)?.is_some() {
            let closure = closure
                .as_ref()
                .ok_or(invalid("frontier has no committed Freeze"))?;
            let final_record = frontier::decode_final(present(row)?)
                .map_err(|_| invalid("final frontier schema"))?;
            validate_frontier(policy, closure, &final_record.identity)?;
            if final_record.indexed {
                let cursor_key: Vec<u8> = frontier::key(
                    policy.context().chain_id(),
                    policy.context().epoch(),
                    b"frontier-progress/",
                )
                .map_err(|_| invalid("indexed final frontier progress key"))?;
                match rows.get(&cursor_key) {
                    Some(cursor_row) => {
                        let cursor: frontier::FrontierCursor =
                            frontier::decode_cursor(present(cursor_row)?)
                                .map_err(|_| invalid("indexed final frontier progress schema"))?;
                        if !cursor.indexed || cursor.identity != final_record.identity {
                            return Err(invalid(
                                "indexed final frontier differs from its complete progress",
                            ));
                        }
                    }
                    None if final_record.identity.entry_count == 0 => {}
                    None => {
                        return Err(invalid(
                            "indexed final frontier lacks its complete progress",
                        ));
                    }
                }
            }
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
            let record = signer_progress_for_exclusion(resolver, present(row)?)?;
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
                    let record = union_progress_for_exclusion(resolver, present(row)?)?;
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
    if let Some(cursor) = frontier_cursor {
        validate_index_corpus(resolver, &cursor, &frontier_entries)?;
    } else if !frontier_entries.is_empty() {
        return Err(invalid("frontier index corpus has no progress"));
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
    use super::drain_union::{SignerProgressRecord, UnionProgressRecord};
    use super::{signer_progress_for_exclusion, tail, union_progress_for_exclusion};
    use canonical_encoding::{CanonicalStruct, encode_digest32};
    use consensus::{
        AvailabilityIdentity, ConsensusSigner, DrainUnionAccumulator, FrozenFrontierAccumulator,
        FrozenFrontierCertifier, FrozenFrontierIdentity, FrozenFrontierPage, FrozenFrontierVote,
        encode_drain_union_identity, encode_frozen_frontier_identity, encode_frozen_frontier_page,
        encode_frozen_frontier_vote,
    };
    use ed25519_zebra::{SigningKey, VerificationKey};
    use hashing::HashSuiteResolver;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion,
        SignatureSchemeId, ValidatorId,
    };
    use runtime::AtomicityDomainId;
    use validator_set::{ValidatorInfo, ValidatorSet};

    struct ProgressSigner {
        id: ValidatorId,
        key: SigningKey,
    }

    impl ConsensusSigner for ProgressSigner {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }

        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }

        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            let signature: [u8; 64] = self.key.sign(framed).into();
            Ok(signature.to_vec())
        }
    }

    // Real registered Ed25519 signature, but only a local-schema fixture: the
    // unsigned publication selector below is not certified business material.
    fn progress_fixture() -> (
        HashSuiteResolver,
        FrozenFrontierIdentity,
        FrozenFrontierVote,
        AvailabilityIdentity,
    ) {
        let chain: ChainId = ChainId::new("audit-progress-consistency").unwrap();
        let version: ProtocolVersion = ProtocolVersion::new(4);
        let epoch: Epoch = Epoch::new(0);
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain.clone(),
            version,
            vec![HashSuiteSchedule {
                activation_epoch: epoch,
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let domain: AtomicityDomainId = AtomicityDomainId::new([9; 32]).unwrap();
        let key: SigningKey = SigningKey::from([0x41; 32]);
        let public: [u8; 32] = VerificationKey::from(&key).into();
        let signer: ProgressSigner = ProgressSigner {
            id: ValidatorId::new(public),
            key,
        };
        let validators: ValidatorSet = ValidatorSet::new(
            epoch,
            vec![ValidatorInfo {
                id: signer.id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public.to_vec(),
            }],
        )
        .unwrap();
        let certifier: FrozenFrontierCertifier =
            FrozenFrontierCertifier::new(chain.clone(), version, epoch, validators).unwrap();
        let digest: Digest32 = resolver
            .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, b"inert selector")
            .unwrap();
        let member: AvailabilityIdentity = AvailabilityIdentity {
            chain_id: chain.clone(),
            protocol_version: version,
            epoch,
            domain,
            request_id: [1; 32],
            signed_intent_digest: digest,
            execution_commitment: digest,
            semantic_artifacts_digest: digest,
        };
        let mut frontier: FrozenFrontierAccumulator =
            FrozenFrontierAccumulator::new(&resolver, chain, version, epoch, domain, [0x81; 32], 5)
                .unwrap();
        let seed: FrozenFrontierIdentity = frontier.identity().clone();
        frontier.push(&resolver, &member).unwrap();
        let vote: FrozenFrontierVote = certifier
            .cast_vote(frontier.into_identity(), &signer)
            .unwrap();
        certifier
            .verify_vote(&vote, &super::Ed25519ConsensusVerifier)
            .unwrap();
        (resolver, seed, vote, member)
    }

    #[test]
    fn complete_index_corpus_refuses_duplicate_gap_missing_tail_and_changed_fold() {
        // This is only a private metadata consistency fixture. These inert
        // selectors never become certificates, cuts or verified authority.
        let (resolver, seed, _, member): (
            HashSuiteResolver,
            FrozenFrontierIdentity,
            FrozenFrontierVote,
            AvailabilityIdentity,
        ) = progress_fixture();
        let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
            &resolver,
            seed.chain_id.clone(),
            seed.protocol_version,
            seed.epoch,
            seed.domain,
            seed.closure_request_id,
            seed.closure_height,
        )
        .unwrap();
        let mut entries: Vec<super::frontier::FrontierEntry> = Vec::new();
        for index in 1u8..=3 {
            let mut publication: AvailabilityIdentity = member.clone();
            publication.request_id = [index; 32];
            accumulator.push(&resolver, &publication).unwrap();
            entries.push(super::frontier::FrontierEntry {
                closure_request_id: seed.closure_request_id,
                closure_height: seed.closure_height,
                ordinal: u64::from(index),
                publication,
            });
        }
        let cursor: super::frontier::FrontierCursor = super::frontier::FrontierCursor {
            identity: accumulator.into_identity(),
            last_request_id: Some([3; 32]),
            physical_last_request_id: [4; 32],
            indexed: true,
        };
        super::validate_index_corpus(&resolver, &cursor, &entries).unwrap();
        let mut duplicate: Vec<super::frontier::FrontierEntry> = entries.clone();
        duplicate[1].ordinal = 1;
        assert!(super::validate_index_corpus(&resolver, &cursor, &duplicate).is_err());
        let mut gap: Vec<super::frontier::FrontierEntry> = entries.clone();
        gap.remove(1);
        assert!(super::validate_index_corpus(&resolver, &cursor, &gap).is_err());
        let mut missing_tail: Vec<super::frontier::FrontierEntry> = entries.clone();
        missing_tail.pop();
        assert!(super::validate_index_corpus(&resolver, &cursor, &missing_tail).is_err());
        let mut changed: Vec<super::frontier::FrontierEntry> = entries.clone();
        changed[1].publication.execution_commitment = resolver
            .hash_for_purpose(
                seed.epoch,
                HashPurpose::ExecutionEffects,
                b"different inert selector",
            )
            .unwrap();
        assert!(super::validate_index_corpus(&resolver, &cursor, &changed).is_err());
        let mut wrong_tail: super::frontier::FrontierCursor = cursor.clone();
        wrong_tail.last_request_id = Some([2; 32]);
        assert!(super::validate_index_corpus(&resolver, &wrong_tail, &entries).is_err());
    }

    fn signer_bytes(record: &super::drain_union::SignerProgressRecord) -> Vec<u8> {
        // Independent framing lets the negative cases remain canonical even
        // when they violate the owner's separate persisted-state invariants.
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x645B, 1);
        frame
            .field_bytes(1, encode_frozen_frontier_vote(&record.vote).unwrap())
            .unwrap();
        frame
            .field_bytes(
                2,
                encode_frozen_frontier_identity(&record.confirmed_identity).unwrap(),
            )
            .unwrap();
        frame
            .field_bytes(
                3,
                record
                    .confirmed_last_request_id
                    .map_or_else(Vec::new, |id| id.to_vec()),
            )
            .unwrap();
        frame
            .field_bytes(
                4,
                record
                    .staged_page
                    .as_ref()
                    .map_or_else(Vec::new, |page| encode_frozen_frontier_page(page).unwrap()),
            )
            .unwrap();
        frame.field_u16(5, u16::from(record.complete)).unwrap();
        frame.finish().unwrap()
    }

    fn union_bytes(record: &super::drain_union::UnionProgressRecord) -> Vec<u8> {
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x645C, 1);
        frame
            .field_bytes(1, encode_drain_union_identity(&record.identity).unwrap())
            .unwrap();
        frame
            .field_bytes(
                2,
                record
                    .last_request_id
                    .map_or_else(Vec::new, |id| id.to_vec()),
            )
            .unwrap();
        frame
            .field_bytes(3, encode_digest32(&record.selection_digest).unwrap())
            .unwrap();
        assert_eq!(
            record.selected_votes.len(),
            1,
            "bounded one-signer schema fixture"
        );
        frame.field_u16(4, 1).unwrap();
        frame
            .field_bytes(
                5,
                encode_frozen_frontier_vote(&record.selected_votes[0]).unwrap(),
            )
            .unwrap();
        frame.finish().unwrap()
    }

    #[test]
    fn malformed_signer_count_cursor_and_staged_progress_refuse_exclusion() {
        let (resolver, seed, vote, member) = progress_fixture();
        let pending: super::drain_union::SignerProgressRecord =
            super::drain_union::SignerProgressRecord {
                vote: vote.clone(),
                confirmed_identity: seed,
                confirmed_last_request_id: None,
                staged_page: Some(FrozenFrontierPage {
                    after_request_id: None,
                    entries: vec![member.clone()],
                    terminal: true,
                }),
                complete: false,
            };
        assert!(signer_progress_for_exclusion(&resolver, &signer_bytes(&pending)).is_ok());
        let complete: super::drain_union::SignerProgressRecord =
            super::drain_union::SignerProgressRecord {
                vote: vote.clone(),
                confirmed_identity: vote.identity.clone(),
                confirmed_last_request_id: Some(member.request_id),
                staged_page: None,
                complete: true,
            };
        assert!(signer_progress_for_exclusion(&resolver, &signer_bytes(&complete)).is_ok());

        let mut too_many: SignerProgressRecord = complete.clone();
        too_many.complete = false;
        too_many.confirmed_identity.entry_count = too_many
            .confirmed_identity
            .entry_count
            .checked_add(1)
            .unwrap();
        let mut zero_with_cursor: SignerProgressRecord = pending.clone();
        zero_with_cursor.confirmed_last_request_id = Some(member.request_id);
        let mut nonzero_without_cursor: SignerProgressRecord = complete.clone();
        nonzero_without_cursor.confirmed_last_request_id = None;
        let mut complete_with_staged: SignerProgressRecord = complete.clone();
        complete_with_staged.staged_page = Some(FrozenFrontierPage {
            after_request_id: Some(member.request_id),
            entries: Vec::new(),
            terminal: true,
        });
        let mut changed_empty_seed: SignerProgressRecord = pending;
        changed_empty_seed.confirmed_identity.entries_digest = member.execution_commitment;
        for malformed in [
            too_many,
            zero_with_cursor,
            nonzero_without_cursor,
            complete_with_staged,
            changed_empty_seed,
        ] {
            let bytes: Vec<u8> = signer_bytes(&malformed);
            assert!(super::drain_union::decode_signer_progress(&bytes).is_ok());
            // This is the production gate run before the excluded-key insert.
            assert!(signer_progress_for_exclusion(&resolver, &bytes).is_err());
        }
    }

    #[test]
    fn malformed_union_count_cursor_and_empty_seed_refuse_exclusion() {
        let (resolver, _seed, vote, member) = progress_fixture();
        let selected: Vec<(ValidatorId, FrozenFrontierIdentity)> =
            vec![(vote.validator, vote.identity.clone())];
        let mut union: DrainUnionAccumulator = DrainUnionAccumulator::new(
            &resolver,
            vote.identity.chain_id.clone(),
            vote.identity.protocol_version,
            vote.identity.epoch,
            vote.identity.domain,
            vote.identity.closure_request_id,
            vote.identity.closure_height,
            &selected,
        )
        .unwrap();
        let empty: super::drain_union::UnionProgressRecord =
            super::drain_union::UnionProgressRecord {
                selection_digest: union.identity().entries_digest,
                identity: union.identity().clone(),
                selected_votes: vec![vote],
                last_request_id: None,
            };
        assert!(union_progress_for_exclusion(&resolver, &union_bytes(&empty)).is_ok());
        union.push_member(&resolver, &member).unwrap();
        let nonempty: super::drain_union::UnionProgressRecord =
            super::drain_union::UnionProgressRecord {
                identity: union.into_identity(),
                last_request_id: Some(member.request_id),
                ..empty.clone()
            };
        assert!(union_progress_for_exclusion(&resolver, &union_bytes(&nonempty)).is_ok());
        let mut zero_with_cursor: UnionProgressRecord = empty.clone();
        zero_with_cursor.last_request_id = Some(member.request_id);
        let mut nonzero_without_cursor: UnionProgressRecord = nonempty;
        nonzero_without_cursor.last_request_id = None;
        let mut changed_empty_seed: UnionProgressRecord = empty.clone();
        changed_empty_seed.identity.entries_digest = member.execution_commitment;
        let mut changed_signer_count: UnionProgressRecord = empty;
        changed_signer_count.identity.signer_count = changed_signer_count
            .identity
            .signer_count
            .checked_add(1)
            .unwrap();
        for malformed in [
            zero_with_cursor,
            nonzero_without_cursor,
            changed_empty_seed,
            changed_signer_count,
        ] {
            let bytes: Vec<u8> = union_bytes(&malformed);
            assert!(super::drain_union::decode_union_progress(&bytes).is_ok());
            assert!(union_progress_for_exclusion(&resolver, &bytes).is_err());
        }
    }

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
