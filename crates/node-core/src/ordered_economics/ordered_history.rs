//! DR-0169 authenticated ordering history, not business execution or cut
//! authority. QCs authenticate candidates; outcomes/receipts remain source
//! completion companions even when their exact linkage is consistent.
use super::*;
use canonical_encoding::{decode_digest32, encode_digest32};
use consensus::{CommittedBlock, CommittedBlockProof, decode_committed_block_proof};
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use std::collections::BTreeMap;

mod codec;
mod source;
pub use codec::{
    decode_ordered_history_height_descriptor, decode_ordered_history_identity,
    decode_ordered_history_summary, encode_ordered_history_height_descriptor,
    encode_ordered_history_identity, encode_ordered_history_summary,
};
pub(crate) use source::{assemble_verified_material, identity_at_height};
pub use source::{
    query_ordered_history_summary, read_ordered_history_component_chunk,
    read_ordered_history_height_descriptor,
};

/// Maximum small descriptor bytes, independent of component content size.
pub const MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES: usize = 16 * 1024;
/// Maximum bytes transferred by one chunk request.
pub const MAX_ORDERED_HISTORY_CHUNK_BYTES: usize = 1024 * 1024;
/// Closed maximum component count per height, not a history-length ceiling.
pub const MAX_ORDERED_HISTORY_COMPONENTS: usize = 6;

fn invalid(reason: &'static str) -> OrderedEconomicsError {
    OrderedEconomicsError::Prerequisite(reason)
}

/// A fixed target. These public fields are claims until independently checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryIdentity {
    pub context: PublicationContext,
    pub domain: AtomicityDomainId,
    pub genesis_digest: Digest32,
    pub anchor: Digest32,
    pub through_height: u64,
    pub through_view: u64,
    pub through_digest: Digest32,
}

impl OrderedHistoryIdentity {
    fn validate(&self, policy: &OrderedEconomicsPolicy) -> Result<(), OrderedEconomicsError> {
        if policy.minimum_freeze_block_height() == 0 {
            return Err(invalid(
                "ordered history requires signed-v3 LogicalGenerationV2 genesis",
            ));
        }
        if self.context != *policy.context()
            || self.domain != policy.domain()
            || self.genesis_digest != policy.genesis_digest()
            || self.anchor != policy.anchor()
        {
            return Err(invalid(
                "ordered history differs from pinned genesis authority",
            ));
        }
        if (self.through_height == 0
            && (self.through_view != 0 || self.through_digest != self.anchor))
            || (self.through_height != 0 && self.through_view == 0)
        {
            return Err(invalid("ordered history target shape"));
        }
        Ok(())
    }
}

/// Source-advertised applied tip, never proof of network freshness or completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistorySummary {
    pub identity: OrderedHistoryIdentity,
}

/// Closed individual transfer component, including exact source companions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum OrderedHistoryComponentKind {
    CommitProof = 1,
    Candidate = 2,
    RequestHeader = 3,
    RetainedOutcome = 4,
    OriginalReceipt = 5,
    ReplayOriginProof = 6,
}

impl OrderedHistoryComponentKind {
    pub fn from_wire(value: u16) -> Result<Self, OrderedEconomicsError> {
        match value {
            1 => Ok(Self::CommitProof),
            2 => Ok(Self::Candidate),
            3 => Ok(Self::RequestHeader),
            4 => Ok(Self::RetainedOutcome),
            5 => Ok(Self::OriginalReceipt),
            6 => Ok(Self::ReplayOriginProof),
            _ => Err(invalid("unknown ordered history component")),
        }
    }

    /// Existing legal per-component bound, not a tiny aggregate response bound.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Candidate => MAX_ORDERED_CANDIDATE_INTENT_BYTES + 1024,
            Self::RequestHeader => 1024,
            _ => canonical_encoding::MAX_CANONICAL_FRAME_BYTES,
        }
    }
}

/// Digest and length of one complete canonical component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryComponentRef {
    pub kind: OrderedHistoryComponentKind,
    pub length: u64,
    pub digest: Digest32,
}

/// No component content is nested here. Unknown, duplicate or unsorted kinds refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryHeightDescriptor {
    pub identity: OrderedHistoryIdentity,
    pub height: u64,
    pub view: u64,
    pub block_digest: Digest32,
    pub components: Vec<OrderedHistoryComponentRef>,
}

impl OrderedHistoryHeightDescriptor {
    fn validate_shape(&self) -> Result<(), OrderedEconomicsError> {
        if self.height == 0
            || self.height > self.identity.through_height
            || self.view == 0
            || self.components.is_empty()
            || self.components.len() > MAX_ORDERED_HISTORY_COMPONENTS
        {
            return Err(invalid("ordered history descriptor shape"));
        }
        let mut previous: Option<OrderedHistoryComponentKind> = None;
        for component in &self.components {
            if component.length == 0
                || component.length > component.kind.max_bytes() as u64
                || previous.is_some_and(|kind| kind >= component.kind)
            {
                return Err(invalid("ordered history component order or length"));
            }
            previous = Some(component.kind);
        }
        if self.components[0].kind != OrderedHistoryComponentKind::CommitProof {
            return Err(invalid("ordered history descriptor has no commit proof"));
        }
        Ok(())
    }
}

/// One height's bounded individual components, deliberately not a wire superframe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryHeightMaterial {
    pub descriptor: OrderedHistoryHeightDescriptor,
    pub components: Vec<(OrderedHistoryComponentKind, Vec<u8>)>,
}

/// Hashes an existing canonical component in the pinned NodeEvent domain.
/// Digest equality is transfer integrity, not result/effect authentication.
pub fn ordered_history_component_digest(
    policy: &OrderedEconomicsPolicy,
    bytes: &[u8],
) -> Result<Digest32, OrderedEconomicsError> {
    if bytes.is_empty() || bytes.len() > canonical_encoding::MAX_CANONICAL_FRAME_BYTES {
        return Err(invalid("ordered history component byte capacity"));
    }
    policy.history_component_digest(bytes)
}

/// Digest of the exact small descriptor, with fixed-target context inside it.
pub fn ordered_history_descriptor_digest(
    policy: &OrderedEconomicsPolicy,
    descriptor: &OrderedHistoryHeightDescriptor,
) -> Result<Digest32, OrderedEconomicsError> {
    descriptor.identity.validate(policy)?;
    ordered_history_component_digest(
        policy,
        &encode_ordered_history_height_descriptor(descriptor)?,
    )
}

/// `pub(crate)`: also independently re-used (never trusted structurally) by
/// the private Seal-acceptance terminal in
/// `business_reconstruction::cut::derive`, which cannot rely on a caller
/// having pre-verified the prior-tip three-chain through
/// `OrderedHistoryVerifier` first.
pub(crate) fn verified_committed_block(
    policy: &OrderedEconomicsPolicy,
    proof: &CommittedBlockProof,
) -> Result<CommittedBlock, OrderedEconomicsError> {
    let block: CommittedBlock = CommittedBlock {
        height: proof.committed.height,
        view: proof.committed.view,
        digest: policy
            .engine()
            .proposal_digest(&proof.committed)
            .map_err(|_| invalid("ordered history proposal digest"))?,
        transactions: proof.committed.transactions.clone(),
    };
    policy
        .engine()
        .verify_committed_block_proof(
            &block,
            proof,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
            ),
        )
        .map_err(|_| invalid("ordered history commit proof authentication"))?;
    for proposal in [&proof.committed, &proof.child, &proof.grandchild] {
        engine::require_profile_shape(proposal)?;
    }
    Ok(block)
}

fn component(
    material: &OrderedHistoryHeightMaterial,
    kind: OrderedHistoryComponentKind,
) -> Result<&[u8], OrderedEconomicsError> {
    material
        .components
        .iter()
        .find(|(found, _)| *found == kind)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or(invalid("ordered history component missing"))
}

fn verify_material(
    policy: &OrderedEconomicsPolicy,
    material: &OrderedHistoryHeightMaterial,
) -> Result<
    (
        CommittedBlock,
        CommittedBlockProof,
        Option<CompletionFingerprint>,
    ),
    OrderedEconomicsError,
> {
    use OrderedHistoryComponentKind as Kind;
    let descriptor: &OrderedHistoryHeightDescriptor = &material.descriptor;
    descriptor.identity.validate(policy)?;
    descriptor.validate_shape()?;
    if material.components.len() != descriptor.components.len() {
        return Err(invalid("ordered history component count mismatch"));
    }
    for (reference, (kind, bytes)) in descriptor.components.iter().zip(&material.components) {
        if *kind != reference.kind
            || bytes.len() as u64 != reference.length
            || bytes.len() > kind.max_bytes()
            || ordered_history_component_digest(policy, bytes)? != reference.digest
        {
            return Err(invalid("ordered history component changed or mismatched"));
        }
    }
    let proof: CommittedBlockProof =
        decode_committed_block_proof(component(material, Kind::CommitProof)?)
            .map_err(|_| invalid("ordered history commit proof encoding"))?;
    let block: CommittedBlock = verified_committed_block(policy, &proof)?;
    if block.height != descriptor.height
        || block.view != descriptor.view
        || block.digest != descriptor.block_digest
    {
        return Err(invalid(
            "ordered history descriptor disagrees with commit proof",
        ));
    }
    let completion: Option<CompletionFingerprint> = if block.transactions.is_empty() {
        if material.components.len() != 1 {
            return Err(invalid(
                "empty ordered history height has surplus components",
            ));
        }
        None
    } else {
        Some(verify_completion_companions(policy, material, &block)?)
    };
    Ok((block, proof, completion))
}

/// Fixed-size metadata only; canonical result bytes are not retained in the
/// streaming verifier. The fingerprints enforce source companion continuity,
/// never independently authenticate their business effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompletionFingerprint {
    request_id: [u8; 32],
    /// The candidate is a DR-0187 Seal. DR-0189 accepts it only as the
    /// first occurrence at the fixed terminal height.
    seal: bool,
    origin_height: u64,
    origin_digest: Digest32,
    candidate: Digest32,
    header: Digest32,
    outcome: Digest32,
    receipt: Digest32,
}

fn component_fingerprint(
    material: &OrderedHistoryHeightMaterial,
    kind: OrderedHistoryComponentKind,
) -> Result<Digest32, OrderedEconomicsError> {
    material
        .descriptor
        .components
        .iter()
        .find(|reference| reference.kind == kind)
        .map(|reference| reference.digest)
        .ok_or(invalid("ordered history completion fingerprint missing"))
}

fn verify_completion_companions(
    policy: &OrderedEconomicsPolicy,
    material: &OrderedHistoryHeightMaterial,
    block: &CommittedBlock,
) -> Result<CompletionFingerprint, OrderedEconomicsError> {
    use OrderedHistoryComponentKind as Kind;
    let candidate_bytes: &[u8] = component(material, Kind::Candidate)?;
    let candidate: OrderedCandidate = decode_ordered_candidate(candidate_bytes)?;
    policy.authenticate_candidate(&candidate)?;
    let digest: Digest32 = policy.candidate_digest(&candidate)?;
    if block.transactions.as_slice() != [digest] {
        return Err(invalid("ordered history candidate digest mismatch"));
    }
    let header_bytes: &[u8] = component(material, Kind::RequestHeader)?;
    let header: engine::RequestHeader = engine::decode_request_header(header_bytes)?;
    if engine::encode_request_header(&header)?.as_slice() != header_bytes
        || header.candidate_digest != digest
        || header.kind != candidate.kind
        || header.created_checkpoint != candidate.created_checkpoint
    {
        return Err(invalid("ordered history immutable header mismatch"));
    }
    let outcome: OrderedOutcome =
        engine::decode_retained_outcome(component(material, Kind::RetainedOutcome)?)?;
    let receipt: NodeDedupRecord =
        NodeDedupRecord::decode(component(material, Kind::OriginalReceipt)?)?;
    if outcome.candidate_digest != digest
        || outcome.request_id != candidate.request_id
        || receipt.request_id().as_bytes() != &candidate.request_id
        || receipt.responses() != outcome.output.responses()
        || receipt.responses().is_empty()
        || receipt
            .responses()
            .iter()
            .any(|response| response.request_id().as_bytes() != &candidate.request_id)
        || outcome.block_height == 0
        || outcome.block_height > block.height
    {
        return Err(invalid("ordered history completion companion mismatch"));
    }
    // Every retained refusal is the orchestrator's own receipt over the
    // candidate digest. An acceptance keeps the receipt its committing handler
    // wrote, so derive that handler's own receipt digest rather than reuse the
    // transfer-integrity component digest of the intent bytes.
    let rejected: bool = receipt
        .responses()
        .iter()
        .any(|response| response.status() == NodeResponseStatus::Rejected);
    let event_digest: Digest32 = if rejected {
        digest
    } else {
        policy.accepted_receipt_digest(&candidate, digest)?
    };
    if receipt.event_digest() != event_digest {
        return Err(invalid("ordered history original receipt event mismatch"));
    }
    if rejected {
        if receipt.responses().len() != 1 {
            return Err(invalid("ordered refusal companion response count"));
        }
        decode_ordered_refusal_payload(
            receipt.responses()[0]
                .payload()
                .ok_or(invalid("ordered refusal companion payload missing"))?,
        )?;
    }
    if outcome.block_height == block.height {
        if outcome.block_digest != block.digest || material.components.len() != 5 {
            return Err(invalid("ordered history completion origin mismatch"));
        }
    } else {
        if material.components.len() != 6 {
            return Err(invalid("ordered history replay origin component missing"));
        }
        let origin_proof: CommittedBlockProof =
            decode_committed_block_proof(component(material, Kind::ReplayOriginProof)?)
                .map_err(|_| invalid("ordered history replay origin proof encoding"))?;
        let origin: CommittedBlock = verified_committed_block(policy, &origin_proof)?;
        if origin.height != outcome.block_height
            || origin.digest != outcome.block_digest
            || origin.transactions.as_slice() != [digest]
        {
            return Err(invalid("ordered history replay origin proof mismatch"));
        }
    }
    Ok(CompletionFingerprint {
        request_id: candidate.request_id,
        seal: candidate.kind == OrderedOperationKind::Seal,
        origin_height: outcome.block_height,
        origin_digest: outcome.block_digest,
        candidate: component_fingerprint(material, Kind::Candidate)?,
        header: component_fingerprint(material, Kind::RequestHeader)?,
        outcome: component_fingerprint(material, Kind::RetainedOutcome)?,
        receipt: component_fingerprint(material, Kind::OriginalReceipt)?,
    })
}

/// Pure bounded streaming verifier. No store, VM, signer, clock or active membership.
/// Restart must replay independently checked saved material; no cursor decoder
/// can manufacture verified authority from a supplied height.
/// Memory grows by one fixed-size request/origin/fingerprint entry per unique
/// candidate, not by its result bytes. Callers must provision this linear
/// index; there is no arbitrary protocol ceiling on total history length.
#[derive(Clone)]
pub struct OrderedHistoryVerifier {
    policy: OrderedEconomicsPolicy,
    identity: OrderedHistoryIdentity,
    height: u64,
    view: u64,
    digest: Digest32,
    empty_three_chain: bool,
    completions: BTreeMap<[u8; 32], CompletionFingerprint>,
}

impl OrderedHistoryVerifier {
    pub fn new(
        policy: OrderedEconomicsPolicy,
        identity: OrderedHistoryIdentity,
    ) -> Result<Self, OrderedEconomicsError> {
        identity.validate(&policy)?;
        let digest: Digest32 = policy.anchor();
        Ok(Self {
            policy,
            identity,
            height: 0,
            view: 0,
            digest,
            empty_three_chain: false,
            completions: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    pub(crate) fn require_pinned_policy(
        &self,
        policy: &OrderedEconomicsPolicy,
    ) -> Result<(), OrderedEconomicsError> {
        self.identity.validate(policy)?;
        if self.policy.anchor() != policy.anchor()
            || self.policy.admission_profile() != policy.admission_profile()
        {
            return Err(invalid(
                "ordered reconstruction verifier has a different pinned policy",
            ));
        }
        Ok(())
    }

    pub fn verify_next_height(
        &mut self,
        material: &OrderedHistoryHeightMaterial,
    ) -> Result<CommittedBlock, OrderedEconomicsError> {
        if material.descriptor.identity != self.identity
            || material.descriptor.height
                != self
                    .height
                    .checked_add(1)
                    .ok_or(invalid("ordered history height overflow"))?
        {
            return Err(invalid(
                "ordered history gap, duplicate, reordering or changed target",
            ));
        }
        let (block, proof, completion): (
            CommittedBlock,
            CommittedBlockProof,
            Option<CompletionFingerprint>,
        ) = verify_material(&self.policy, material)?;
        if proof.committed.justify.height != self.height
            || proof.committed.justify.view != self.view
            || proof.committed.justify.proposal_digest != self.digest
        {
            return Err(invalid("ordered history direct prefix parent mismatch"));
        }
        if block.height == self.identity.through_height
            && (block.digest != self.identity.through_digest
                || block.view != self.identity.through_view)
        {
            return Err(invalid("ordered history fixed target mismatch"));
        }
        if let Some(completion) = &completion {
            // DR-0189 terminal Seal extension: a Seal is accepted only as
            // its own first occurrence (five components, no replay origin)
            // at the fixed target height. A Seal anywhere else, or any
            // recommit of one, refuses. There is no caller flag.
            if completion.seal
                && (block.height != self.identity.through_height
                    || completion.origin_height != block.height
                    || self.completions.contains_key(&completion.request_id))
            {
                return Err(invalid(
                    "ordered history Seal is not the terminal first occurrence",
                ));
            }
            match self.completions.get(&completion.request_id) {
                Some(original) if original != completion => {
                    return Err(invalid(
                        "ordered history recommit changed original companions or origin",
                    ));
                }
                None if completion.origin_height != block.height
                    || completion.origin_digest != block.digest =>
                {
                    return Err(invalid(
                        "ordered history first occurrence is not its completion origin",
                    ));
                }
                _ => {}
            }
        }
        // No fallible verification may follow these updates: a rejected
        // height cannot poison the first-seen index or advance the cursor.
        if let Some(completion) = completion {
            self.completions
                .entry(completion.request_id)
                .or_insert(completion);
        }
        self.height = block.height;
        self.view = block.view;
        self.digest = block.digest;
        self.empty_three_chain = proof.committed.transactions.is_empty()
            && proof.child.transactions.is_empty()
            && proof.grandchild.transactions.is_empty();
        Ok(block)
    }

    /// This result proves order only, never economic companion truth, drain
    /// completion, latest network state, cut roots, readiness, Seal or activation.
    pub fn finish(&self) -> Result<VerifiedOrderedHistory, OrderedEconomicsError> {
        if self.height != self.identity.through_height
            || self.digest != self.identity.through_digest
            || self.view != self.identity.through_view
        {
            return Err(invalid("ordered history prefix is incomplete"));
        }
        Ok(VerifiedOrderedHistory {
            identity: self.identity.clone(),
            empty_three_chain: self.empty_three_chain,
        })
    }
}

/// Private-field ordering-only result; never an importer/serving permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOrderedHistory {
    identity: OrderedHistoryIdentity,
    empty_three_chain: bool,
}
impl VerifiedOrderedHistory {
    #[must_use]
    pub const fn identity(&self) -> &OrderedHistoryIdentity {
        &self.identity
    }
    /// Only describes the proved target and descendants, not complete drain.
    #[must_use]
    pub const fn target_is_empty_three_chain(&self) -> bool {
        self.empty_three_chain
    }
}
