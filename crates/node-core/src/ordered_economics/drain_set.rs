//! DR-0154 "One ordered epoch-control chain" / DR-0157: the quorum-retained
//! `DrainSet` control command.
//!
//! `DrainSet` is an [`OrderedOperationKind`] exactly like `Freeze`: it
//! occupies the same economic-height proposal slot and is committed through
//! the existing shared three-chain `ChainedHotStuff` rules. There is no
//! separate signature or parallel voting chain: a *proposed* `DrainSet`
//! changes nothing, and only a *committed* one -- decided in
//! [`super::preflight`] and applied here -- installs the durable, one-per-
//! epoch immutable [`DrainSetRecord`].
//!
//! Unlike every signed business kind, [`DrainSetIntent`] itself carries no
//! outer signature: its authority is the pinned outgoing quorum's own signed
//! [`consensus::FrozenFrontierVote`] roster plus this replica's own
//! independently reconstructed [`consensus::DrainUnionIdentity`]
//! ([`super::drain_union::verify_drain_ready_into`]), never an additional
//! signer. Pure authentication
//! ([`super::policy::authenticate_candidate`]'s `DrainSet` arm) checks the
//! candidate's own canonical bytes plus the pinned outgoing quorum's
//! signatures and voting power, with zero storage reads. Only a
//! [`preflight_drain_set`]/[`require_drain_set_readiness`] re-verification
//! through durable storage can prove this replica's own selected-quorum
//! union actually matches the declared identity.
//!
//! Scope of this slice (DR-0154/DR-0157, partial): choosing exactly one
//! `DrainSet` per epoch and installing its immutable record. It does not
//! drain, apply, cut, Seal or activate anything; see the module-level
//! remaining-integration note in [`super`].
use super::*;
use canonical_encoding::encode_chain_id;
use consensus::{
    DrainUnionIdentity, FrozenFrontierVote, decode_drain_union_identity,
    decode_frozen_frontier_vote, encode_drain_union_identity, encode_frozen_frontier_vote,
};
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS;

/// Canonical frame type of an encoded [`DrainSetIntent`] (an
/// [`OrderedCandidate::intent`] body for [`OrderedOperationKind::DrainSet`]).
///
/// Allocated from the same reserved `0x6454..` control/cut block as
/// [`super::freeze::FreezeIntent`] and [`super::drain_union`]'s progress/ready
/// records; verified free at allocation time.
const DRAIN_SET_INTENT_TYPE: u16 = 0x645E;
/// Canonical frame type of an encoded [`DrainSetRecord`]. Allocated from the
/// same reserved block as [`DRAIN_SET_INTENT_TYPE`].
const DRAIN_SET_RECORD_TYPE: u16 = 0x645F;
const ENCODING_VERSION: u16 = 1;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// The candidate body for [`OrderedOperationKind::DrainSet`].
///
/// Deliberately carries no signature: authorization is the pinned outgoing
/// quorum's own signed [`FrozenFrontierVote`] roster
/// ([`super::policy::authenticate_candidate`]'s `DrainSet` arm re-verifies
/// every vote's signature and the aggregate quorum power purely), not an
/// additional outer signer. `context` and `request_id` duplicate
/// [`OrderedCandidate::context`]/[`OrderedCandidate::request_id`] exactly
/// like [`super::freeze::FreezeIntent`] does, so pure authentication can
/// cross-check the two bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSetIntent {
    /// Chain/protocol/epoch replay boundary; must equal the candidate's own.
    pub context: PublicationContext,
    /// Replay identity; must equal the candidate's own request id.
    pub request_id: [u8; 32],
    /// The exact ascending, unique, quorum-verified frontier-vote roster this
    /// DrainSet selects. Re-verified purely (signatures/quorum power) at
    /// authentication and re-verified through durable storage
    /// (per-signer local completeness) at preflight.
    pub selected_votes: Vec<FrozenFrontierVote>,
    /// This replica's own locally reconstructed union identity for exactly
    /// `selected_votes` and the committed Freeze it is scoped to. Bound to
    /// `context` structurally; its full membership can only be re-verified
    /// through durable storage (see [`require_drain_set_readiness`]).
    pub drain_union_identity: DrainUnionIdentity,
}

/// Structural, purely-decidable validation shared by encode and pure
/// authentication: every field a caller controls before any storage read.
pub(crate) fn validate_drain_set_intent_structure(
    intent: &DrainSetIntent,
) -> Result<(), NodeCoreError> {
    if intent.request_id == [0u8; 32] {
        return Err(invalid("drain set intent request id must not be zero"));
    }
    if intent.selected_votes.is_empty()
        || intent.selected_votes.len() > MAX_FASTPATH_ACTIVE_VALIDATORS
    {
        return Err(invalid("drain set intent selected votes count"));
    }
    if intent
        .selected_votes
        .windows(2)
        .any(|pair| pair[0].validator >= pair[1].validator)
    {
        return Err(invalid(
            "drain set intent selected votes are not strictly ascending",
        ));
    }
    let identity: &DrainUnionIdentity = &intent.drain_union_identity;
    if identity.chain_id != *intent.context.chain_id()
        || identity.protocol_version != intent.context.protocol_version()
        || identity.epoch != intent.context.epoch()
    {
        return Err(invalid(
            "drain set intent union identity is not bound to its own context",
        ));
    }
    let expected_signer_count: u64 = u64::try_from(intent.selected_votes.len())
        .map_err(|_| invalid("drain set intent selected votes count overflow"))?;
    if identity.signer_count != expected_signer_count {
        return Err(invalid(
            "drain set intent union identity signer count mismatch",
        ));
    }
    for vote in &intent.selected_votes {
        if vote.identity.chain_id != identity.chain_id
            || vote.identity.protocol_version != identity.protocol_version
            || vote.identity.epoch != identity.epoch
            || vote.identity.domain != identity.domain
            || vote.identity.closure_request_id != identity.closure_request_id
            || vote.identity.closure_height != identity.closure_height
        {
            return Err(invalid(
                "drain set intent selected vote disagrees with its own union identity",
            ));
        }
    }
    Ok(())
}

/// Encodes frame `0x645E/v1`.
pub fn encode_drain_set_intent(intent: &DrainSetIntent) -> Result<Vec<u8>, NodeCoreError> {
    validate_drain_set_intent_structure(intent)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(DRAIN_SET_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&intent.context)
            .map_err(|_| invalid("invalid drain set intent context"))?,
    )?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(
        3,
        encode_drain_union_identity(&intent.drain_union_identity)
            .map_err(|_| invalid("invalid drain set intent union identity"))?,
    )?;
    let count: u16 = u16::try_from(intent.selected_votes.len())
        .map_err(|_| invalid("drain set intent vote count overflow"))?;
    frame.field_u16(4, count)?;
    for (index, vote) in intent.selected_votes.iter().enumerate() {
        let field: u16 = u16::try_from(index + 5)
            .map_err(|_| invalid("drain set intent vote field overflow"))?;
        frame.field_bytes(
            field,
            encode_frozen_frontier_vote(vote)
                .map_err(|_| invalid("invalid drain set intent vote"))?,
        )?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ORDERED_CANDIDATE_INTENT_BYTES {
        return Err(invalid("drain set intent exceeds the candidate bound"));
    }
    Ok(bytes)
}

/// Strictly decodes frame `0x645E/v1`.
pub fn decode_drain_set_intent(bytes: &[u8]) -> Result<DrainSetIntent, NodeCoreError> {
    if bytes.len() > MAX_ORDERED_CANDIDATE_INTENT_BYTES {
        return Err(invalid("drain set intent exceeds the candidate bound"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(DRAIN_SET_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("drain set intent request id length"))?;
    let count: usize = usize::from(frame.required_u16(4)?);
    if count == 0 || count > MAX_FASTPATH_ACTIVE_VALIDATORS {
        return Err(invalid("drain set intent vote count"));
    }
    let mut selected_votes: Vec<FrozenFrontierVote> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 = u16::try_from(index + 5)
            .map_err(|_| invalid("drain set intent vote field overflow"))?;
        selected_votes.push(
            decode_frozen_frontier_vote(frame.required_field(field)?)
                .map_err(|_| invalid("invalid drain set intent vote"))?,
        );
    }
    if frame.field_count() != selected_votes.len() + 4 {
        return Err(invalid("drain set intent field count"));
    }
    let intent: DrainSetIntent = DrainSetIntent {
        context: decode_publication_context(frame.required_field(1)?)
            .map_err(|_| invalid("invalid drain set intent context"))?,
        request_id,
        selected_votes,
        drain_union_identity: decode_drain_union_identity(frame.required_field(3)?)
            .map_err(|_| invalid("invalid drain set intent union identity"))?,
    };
    if encode_drain_set_intent(&intent)? != bytes {
        return Err(invalid("noncanonical drain set intent"));
    }
    Ok(intent)
}

/// The durable, per-chain-and-epoch one-per-epoch immutable record DR-0157's
/// "Choose exactly one `DrainSet`" requires.
///
/// Installed exactly once by the first committed `DrainSet` candidate in an
/// epoch. Its presence is what [`preflight_drain_set`] consults to refuse a
/// duplicate/re-selection with [`OrderedRefusal::AlreadyDrained`]. It carries
/// the exact locally reconstructed union identity that candidate's readiness
/// re-verification proved, retained for audit; never re-derived from
/// anything else. This is local progress and audit history, never a signed or
/// transferable cut fact: it authorizes no drain application, cut, Seal or
/// activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSetRecord {
    /// The epoch this DrainSet was chosen for.
    pub closed_epoch: Epoch,
    /// The committed `DrainSet` candidate's own replay identity.
    pub request_id: [u8; 32],
    /// The ordered-economics block height at which `DrainSet` committed.
    pub committed_at_block_height: u64,
    /// The exact locally reconstructed union identity this candidate's
    /// readiness re-verification proved at commit time.
    pub drain_union_identity: DrainUnionIdentity,
    /// Exact outgoing signed frontier selection committed by this decision.
    /// Later drain authorization must not reconstruct its membership from an
    /// untrusted request or from the union digest alone.
    pub selected_votes: Vec<FrozenFrontierVote>,
}

fn validate_drain_set_record_structure(record: &DrainSetRecord) -> Result<(), NodeCoreError> {
    let identity: &DrainUnionIdentity = &record.drain_union_identity;
    if record.request_id == [0u8; 32]
        || record.closed_epoch != identity.epoch
        || record.committed_at_block_height <= identity.closure_height
        || record.selected_votes.is_empty()
        || record.selected_votes.len() > MAX_FASTPATH_ACTIVE_VALIDATORS
    {
        return Err(invalid("drain set record identity or bound"));
    }
    if record
        .selected_votes
        .windows(2)
        .any(|pair| pair[0].validator >= pair[1].validator)
    {
        return Err(invalid("drain set record votes are not ascending"));
    }
    let signer_count: u64 = u64::try_from(record.selected_votes.len())
        .map_err(|_| invalid("drain set record vote count overflow"))?;
    if identity.signer_count != signer_count {
        return Err(invalid("drain set record signer count mismatch"));
    }
    for vote in &record.selected_votes {
        if vote.identity.chain_id != identity.chain_id
            || vote.identity.protocol_version != identity.protocol_version
            || vote.identity.epoch != identity.epoch
            || vote.identity.domain != identity.domain
            || vote.identity.closure_request_id != identity.closure_request_id
            || vote.identity.closure_height != identity.closure_height
        {
            return Err(invalid("drain set record vote identity mismatch"));
        }
    }
    Ok(())
}

/// Encodes frame `0x645F/v1`.
pub fn encode_drain_set_record(record: &DrainSetRecord) -> Result<Vec<u8>, NodeCoreError> {
    validate_drain_set_record_structure(record)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(DRAIN_SET_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.closed_epoch.get())?;
    frame.field_bytes(2, record.request_id.to_vec())?;
    frame.field_u64(3, record.committed_at_block_height)?;
    frame.field_bytes(
        4,
        encode_drain_union_identity(&record.drain_union_identity)
            .map_err(|_| invalid("invalid drain set record union identity"))?,
    )?;
    let count: u16 = u16::try_from(record.selected_votes.len())
        .map_err(|_| invalid("drain set record vote count overflow"))?;
    frame.field_u16(5, count)?;
    for (index, vote) in record.selected_votes.iter().enumerate() {
        let field: u16 = u16::try_from(index + 6)
            .map_err(|_| invalid("drain set record vote field overflow"))?;
        frame.field_bytes(
            field,
            encode_frozen_frontier_vote(vote)
                .map_err(|_| invalid("invalid drain set record vote"))?,
        )?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ORDERED_CANDIDATE_INTENT_BYTES {
        return Err(invalid("drain set record exceeds the candidate bound"));
    }
    Ok(bytes)
}

/// Strictly decodes frame `0x645F/v1`.
pub fn decode_drain_set_record(bytes: &[u8]) -> Result<DrainSetRecord, NodeCoreError> {
    if bytes.len() > MAX_ORDERED_CANDIDATE_INTENT_BYTES {
        return Err(invalid("drain set record exceeds the candidate bound"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(DRAIN_SET_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("drain set record request id length"))?;
    let count: usize = usize::from(frame.required_u16(5)?);
    if count == 0 || count > MAX_FASTPATH_ACTIVE_VALIDATORS {
        return Err(invalid("drain set record vote count"));
    }
    let mut selected_votes: Vec<FrozenFrontierVote> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 = u16::try_from(index + 6)
            .map_err(|_| invalid("drain set record vote field overflow"))?;
        selected_votes.push(
            decode_frozen_frontier_vote(frame.required_field(field)?)
                .map_err(|_| invalid("invalid drain set record vote"))?,
        );
    }
    if frame.field_count() != selected_votes.len() + 5 {
        return Err(invalid("drain set record field count"));
    }
    let record: DrainSetRecord = DrainSetRecord {
        closed_epoch: Epoch::new(frame.required_u64(1)?),
        request_id,
        committed_at_block_height: frame.required_u64(3)?,
        drain_union_identity: decode_drain_union_identity(frame.required_field(4)?)
            .map_err(|_| invalid("invalid drain set record union identity"))?,
        selected_votes,
    };
    if encode_drain_set_record(&record)? != bytes {
        return Err(invalid("noncanonical drain set record"));
    }
    Ok(record)
}

/// Per-chain-and-epoch key for [`DrainSetRecord`], reserved under
/// [`super::engine::ORDERED_ECONOMICS_STATE_PREFIX`] -- already covered by
/// [`local_instance_state::is_reserved`]'s generic `se/instances/` prefix
/// check, so no contract or generic transactional plan can read or write it.
pub(crate) fn drain_set_record_key(
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = super::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-set/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Reads the durable one-per-epoch record for `chain`/`epoch`, if any,
/// recording the read as a CAS precondition exactly like every other
/// ordered-economics row this module's callers observe.
pub(crate) fn read_drain_set_record<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Option<DrainSetRecord>, NodeCoreError> {
    let key: Vec<u8> = drain_set_record_key(chain, epoch)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    match observed.value() {
        Some(bytes) => {
            let record: DrainSetRecord = decode_drain_set_record(bytes)?;
            if record.closed_epoch != epoch {
                return Err(invalid("drain set record epoch disagrees with its key"));
            }
            if record.drain_union_identity.chain_id != *chain
                || record.drain_union_identity.domain != domain
            {
                return Err(invalid("drain set record context disagrees with its key"));
            }
            Ok(Some(record))
        }
        None if observed.revision() == StateRevision::INITIAL => Ok(None),
        None => Err(invalid("drain set record is tombstoned")),
    }
}

/// Classifies one [`DrainSignerError`] from
/// [`drain_union::verify_drain_ready_into`] into the module's failure
/// discipline. Only the explicit "no local ready marker yet" condition is a
/// [`OrderedEconomicsError::Prerequisite`] stop, per DR-0157: it means this
/// replica's own bounded reconstruction has not (yet) reached the exact
/// selection this candidate names, which is declared catch-up, never a
/// business-decidable refusal. Every other storage/proof-layer failure is
/// likewise a stop -- corrupted or inconsistent local progress is never a
/// candidate's own decidable defect.
fn classify_readiness_error(error: drain_union::DrainSignerError) -> OrderedEconomicsError {
    match error {
        drain_union::DrainSignerError::NotReady(_) => {
            OrderedEconomicsError::Prerequisite("drain union is not locally ready")
        }
        drain_union::DrainSignerError::Node(inner) => OrderedEconomicsError::Node(inner),
        drain_union::DrainSignerError::Frontier(_)
        | drain_union::DrainSignerError::Publication(_)
        | drain_union::DrainSignerError::Invalid(_) => OrderedEconomicsError::Prerequisite(
            "drain union readiness could not be independently reverified",
        ),
    }
}

/// Re-verifies this replica's exact local readiness for `intent.selected_votes`
/// against the exact currently committed Freeze
/// ([`drain_union::verify_drain_ready_into`]), then requires the returned,
/// independently reconstructed [`DrainUnionIdentity`] to equal
/// `intent.drain_union_identity` exactly -- a mismatch is a foreign DrainSet,
/// [`OrderedRefusal::ForeignDrainSet`]. Every read performed folds into
/// `reads`, so a caller that commits `reads` as CAS assertions in the same
/// transaction as a signed proposal/vote or the committed execution's own
/// atomic install is protected against the local ready marker or any of its
/// Freeze/epoch/set prerequisites moving afterward.
pub(crate) fn verify_and_match_readiness<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    intent: &DrainSetIntent,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), OrderedEconomicsError> {
    let identity: DrainUnionIdentity = drain_union::verify_drain_ready_into(
        store,
        context,
        env.policy.domain(),
        env.resolver,
        env.policy.context(),
        &intent.selected_votes,
        reads,
    )
    .map_err(classify_readiness_error)?;
    if identity != intent.drain_union_identity {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::ForeignDrainSet,
        ));
    }
    Ok(())
}

/// Decodes and structurally cross-checks `candidate.intent`, then calls
/// [`verify_and_match_readiness`]. Used both by the pre-vote/pre-proposal
/// check ([`super::engine::admit_candidate_for_signer`]) and by
/// [`preflight_drain_set`].
pub(crate) fn require_drain_set_readiness<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), OrderedEconomicsError> {
    let intent: DrainSetIntent = decode_drain_set_intent(&candidate.intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid drain set candidate intent")
    })?;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "drain set candidate context or request id mismatch",
        ));
    }
    verify_and_match_readiness(store, context, env, &intent, reads)
}

/// [`super::preflight::preflight`]'s `DrainSet` arm: refuses a duplicate
/// selection against the healthy, present one-per-epoch
/// [`DrainSetRecord`] with [`OrderedRefusal::AlreadyDrained`], then
/// re-verifies readiness through `staging` -- every read this performs
/// becomes a CAS assertion in the final commit exactly like every other row
/// [`super::preflight`] observes.
pub(crate) fn preflight_drain_set<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let epoch: Epoch = env.policy.context().epoch();
    if read_drain_set_record(store, context, env.policy.domain(), chain, epoch)?.is_some() {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::AlreadyDrained,
        ));
    }
    let intent: DrainSetIntent = decode_drain_set_intent(&candidate.intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid drain set candidate intent")
    })?;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "drain set candidate context or request id mismatch",
        ));
    }
    // Discarded: `store` here is the caller's staging adapter, which already
    // records every read it forwards (see `StagingStore::observed_reads`).
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    verify_and_match_readiness(store, context, env, &intent, &mut reads)
}

/// Executes a committed `DrainSet` candidate against `staging`.
///
/// [`preflight_drain_set`] already refused this candidate with
/// [`OrderedRefusal::AlreadyDrained`] if [`DrainSetRecord`] was already
/// present and re-verified readiness, so this handler only ever runs once
/// that has genuinely passed: it installs the record and returns an accepted
/// response. It never touches an object, a sender-nonce row, or any other
/// business state, and it does not itself drain, apply, cut, Seal or
/// activate anything -- exactly the same pure-control discipline
/// [`super::freeze::handle_freeze_ordered`] documents for `Freeze`.
pub(crate) fn handle_drain_set_ordered<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    candidate: &OrderedCandidate,
    block_height: u64,
) -> Result<NodeOutput, NodeCoreError> {
    let intent: DrainSetIntent = decode_drain_set_intent(&candidate.intent)?;
    let epoch: Epoch = candidate.context.epoch();
    let key: Vec<u8> = drain_set_record_key(chain, epoch)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
        // Preflight already proves this is unreachable in the ordinary
        // sequence (it would have refused with `AlreadyDrained` first); fail
        // closed rather than silently accepting a second selection.
        return Err(invalid("drain set record already installed"));
    }
    let record: DrainSetRecord = DrainSetRecord {
        closed_epoch: epoch,
        request_id: candidate.request_id,
        committed_at_block_height: block_height,
        drain_union_identity: intent.drain_union_identity,
        selected_votes: intent.selected_votes,
    };
    let mutation = StateMutationEntry::new(
        key.clone(),
        StateMutation::Put(encode_drain_set_record(&record)?),
    )?;
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![StateReadAssertion::new(key, observed.revision())?])?,
        AtomicStateMutationSet::new(vec![mutation])?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => {}
        DurableCommitOutcome::Rejected(reason) => {
            return Err(NodeCoreError::DurableCommitRejected(reason));
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            return Err(NodeCoreError::DurableCommitIndeterminate(reason));
        }
    }
    let response = NodeResponse::new(
        RequestId::new(candidate.request_id)?,
        NodeResponseStatus::Accepted,
        None,
    )?;
    NodeOutput::new(vec![response], Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion, SignatureSchemeId, ValidatorId,
    };
    use runtime::{
        DurableDomainStateStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };
    use sha2::{Digest, Sha256};

    fn context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("drain-set-tests").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(3),
        )
        .unwrap()
    }

    fn frontier_identity() -> consensus::FrozenFrontierIdentity {
        consensus::FrozenFrontierIdentity {
            chain_id: context().chain_id().clone(),
            protocol_version: context().protocol_version(),
            epoch: context().epoch(),
            domain: AtomicityDomainId::new([2; 32]).unwrap(),
            closure_request_id: [9; 32],
            closure_height: 7,
            entry_count: 0,
            entries_digest: Digest32::new(HashAlgorithmId::Blake3_256, [1; 32]),
        }
    }

    fn vote(seed: u8) -> FrozenFrontierVote {
        FrozenFrontierVote {
            identity: frontier_identity(),
            validator: ValidatorId::new([seed; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![7u8; 64],
        }
    }

    fn union_identity(votes: &[FrozenFrontierVote]) -> DrainUnionIdentity {
        DrainUnionIdentity {
            chain_id: context().chain_id().clone(),
            protocol_version: context().protocol_version(),
            epoch: context().epoch(),
            domain: AtomicityDomainId::new([2; 32]).unwrap(),
            closure_request_id: [9; 32],
            closure_height: 7,
            signer_count: votes.len() as u64,
            member_count: 0,
            entries_digest: Digest32::new(HashAlgorithmId::Blake3_256, [3; 32]),
        }
    }

    fn valid_intent() -> DrainSetIntent {
        let votes: Vec<FrozenFrontierVote> = vec![vote(1), vote(2), vote(3)];
        DrainSetIntent {
            context: context(),
            request_id: [4; 32],
            drain_union_identity: union_identity(&votes),
            selected_votes: votes,
        }
    }

    #[test]
    fn drain_set_intent_round_trips() {
        let intent: DrainSetIntent = valid_intent();
        let bytes: Vec<u8> = encode_drain_set_intent(&intent).unwrap();
        assert_eq!(decode_drain_set_intent(&bytes).unwrap(), intent);
    }

    #[test]
    fn largest_handoff_roster_fits_the_candidate_and_record_bounds() {
        let votes: Vec<FrozenFrontierVote> = (0..MAX_FASTPATH_ACTIVE_VALIDATORS)
            .map(|index: usize| vote(index as u8))
            .collect();
        let intent: DrainSetIntent = DrainSetIntent {
            context: context(),
            request_id: [4; 32],
            drain_union_identity: union_identity(&votes),
            selected_votes: votes.clone(),
        };
        assert!(
            encode_drain_set_intent(&intent).unwrap().len() <= MAX_ORDERED_CANDIDATE_INTENT_BYTES
        );
        let record: DrainSetRecord = DrainSetRecord {
            closed_epoch: context().epoch(),
            request_id: intent.request_id,
            committed_at_block_height: 10,
            drain_union_identity: intent.drain_union_identity,
            selected_votes: votes,
        };
        assert!(
            encode_drain_set_record(&record).unwrap().len() <= MAX_ORDERED_CANDIDATE_INTENT_BYTES
        );
    }

    #[test]
    fn drain_set_frames_have_stable_sha256_vectors() {
        let intent: DrainSetIntent = valid_intent();
        let intent_bytes: Vec<u8> = encode_drain_set_intent(&intent).unwrap();
        let record: DrainSetRecord = DrainSetRecord {
            closed_epoch: intent.context.epoch(),
            request_id: intent.request_id,
            committed_at_block_height: 10,
            drain_union_identity: intent.drain_union_identity,
            selected_votes: intent.selected_votes,
        };
        let record_bytes: Vec<u8> = encode_drain_set_record(&record).unwrap();
        let intent_hash: String = Sha256::digest(&intent_bytes)
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect();
        let record_hash: String = Sha256::digest(&record_bytes)
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            intent_hash,
            "05efe4af06bb7194d01013ba2d5e166f790668c7224325fb94b29814f0540186"
        );
        assert_eq!(
            record_hash,
            "9c06f45fa3de5f7056c5ddf82465f7496f2a47e4d66a4f250fddee47f7c907bc"
        );
    }

    #[test]
    fn drain_set_intent_rejects_zero_request_id() {
        let mut intent: DrainSetIntent = valid_intent();
        intent.request_id = [0; 32];
        assert!(encode_drain_set_intent(&intent).is_err());
    }

    #[test]
    fn drain_set_intent_rejects_empty_and_oversized_roster() {
        let mut intent: DrainSetIntent = valid_intent();
        intent.selected_votes.clear();
        assert!(encode_drain_set_intent(&intent).is_err());

        let mut oversized: Vec<FrozenFrontierVote> = Vec::new();
        for seed in 0..=MAX_FASTPATH_ACTIVE_VALIDATORS {
            oversized.push(vote(seed as u8));
        }
        let mut too_big: DrainSetIntent = valid_intent();
        too_big.drain_union_identity.signer_count = oversized.len() as u64;
        too_big.selected_votes = oversized;
        assert!(encode_drain_set_intent(&too_big).is_err());
    }

    #[test]
    fn drain_set_intent_rejects_nonascending_roster() {
        let mut intent: DrainSetIntent = valid_intent();
        intent.selected_votes.swap(0, 1);
        assert!(encode_drain_set_intent(&intent).is_err());
    }

    #[test]
    fn drain_set_intent_rejects_union_identity_not_bound_to_context() {
        let mut intent: DrainSetIntent = valid_intent();
        intent.drain_union_identity.epoch = Epoch::new(intent.context.epoch().get() + 1);
        assert!(encode_drain_set_intent(&intent).is_err());
    }

    #[test]
    fn drain_set_intent_rejects_signer_count_mismatch() {
        let mut intent: DrainSetIntent = valid_intent();
        intent.drain_union_identity.signer_count += 1;
        assert!(encode_drain_set_intent(&intent).is_err());
    }

    #[test]
    fn drain_set_intent_rejects_vote_disagreeing_with_union_identity() {
        let mut intent: DrainSetIntent = valid_intent();
        intent.selected_votes[0].identity.closure_height += 1;
        assert!(encode_drain_set_intent(&intent).is_err());
    }

    #[test]
    fn drain_set_intent_decode_rejects_wrong_frame_type() {
        let mut frame = CanonicalStruct::new(0x1234, ENCODING_VERSION);
        frame.field_bytes(1, vec![1, 2, 3]).unwrap();
        let bytes = frame.finish().unwrap();
        assert!(decode_drain_set_intent(&bytes).is_err());
    }

    #[test]
    fn drain_set_record_round_trips() {
        let votes: Vec<FrozenFrontierVote> = vec![vote(1), vote(2), vote(3)];
        let record: DrainSetRecord = DrainSetRecord {
            closed_epoch: Epoch::new(3),
            request_id: [5; 32],
            committed_at_block_height: 10,
            drain_union_identity: union_identity(&votes),
            selected_votes: votes,
        };
        let bytes: Vec<u8> = encode_drain_set_record(&record).unwrap();
        assert_eq!(decode_drain_set_record(&bytes).unwrap(), record);
    }

    #[test]
    fn drain_set_record_decode_rejects_truncation() {
        let votes: Vec<FrozenFrontierVote> = vec![vote(1)];
        let record: DrainSetRecord = DrainSetRecord {
            closed_epoch: Epoch::new(3),
            request_id: [5; 32],
            committed_at_block_height: 10,
            drain_union_identity: union_identity(&votes),
            selected_votes: votes,
        };
        let mut bytes: Vec<u8> = encode_drain_set_record(&record).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(decode_drain_set_record(&bytes).is_err());
    }

    #[test]
    fn drain_set_record_key_is_stable_and_chain_and_epoch_scoped() {
        let a = ChainId::new("chain-a").unwrap();
        let b = ChainId::new("chain-b").unwrap();
        assert_eq!(
            drain_set_record_key(&a, Epoch::new(4)).unwrap(),
            drain_set_record_key(&a, Epoch::new(4)).unwrap()
        );
        assert_ne!(
            drain_set_record_key(&a, Epoch::new(4)).unwrap(),
            drain_set_record_key(&b, Epoch::new(4)).unwrap()
        );
        assert_ne!(
            drain_set_record_key(&a, Epoch::new(4)).unwrap(),
            drain_set_record_key(&a, Epoch::new(5)).unwrap()
        );
    }

    fn store_context() -> (
        MemoryDurableStateStore,
        DurableOperationContext,
        AtomicityDomainId,
    ) {
        let generation = WriterFenceGeneration::new(1).unwrap();
        let store = MemoryDurableStateStore::new(generation);
        let context = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([1; 16]).unwrap(),
        );
        let domain = AtomicityDomainId::new([2; 32]).unwrap();
        (store, context, domain)
    }

    #[test]
    fn read_drain_set_record_is_absent_until_written_and_fails_closed_on_tombstone() {
        let (store, context, domain) = store_context();
        let chain = ChainId::new("read-drain-set").unwrap();
        assert_eq!(
            read_drain_set_record(&store, &context, domain, &chain, Epoch::new(0)).unwrap(),
            None
        );

        let key = drain_set_record_key(&chain, Epoch::new(0)).unwrap();
        let observed = store.get_versioned_durable(&context, domain, &key).unwrap();
        let mut votes: Vec<FrozenFrontierVote> = vec![vote(1)];
        votes[0].identity.chain_id = chain.clone();
        votes[0].identity.epoch = Epoch::new(0);
        let mut identity: DrainUnionIdentity = union_identity(&votes);
        identity.chain_id = chain.clone();
        identity.epoch = Epoch::new(0);
        identity.domain = domain;
        let record = DrainSetRecord {
            closed_epoch: Epoch::new(0),
            request_id: [1; 32],
            committed_at_block_height: 8,
            drain_union_identity: identity,
            selected_votes: votes,
        };
        let transaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    key.clone(),
                    StateMutation::Put(encode_drain_set_record(&record).unwrap()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );
        assert_eq!(
            read_drain_set_record(&store, &context, domain, &chain, Epoch::new(0))
                .unwrap()
                .unwrap(),
            record
        );

        let observed = store.get_versioned_durable(&context, domain, &key).unwrap();
        let delete = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, delete),
            DurableCommitOutcome::Committed
        );
        assert!(read_drain_set_record(&store, &context, domain, &chain, Epoch::new(0)).is_err());
    }
}
