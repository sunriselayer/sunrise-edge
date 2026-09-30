//! Replica-local, CAS-installed pre-Seal writer barrier. This is not a
//! portable cut or a substitute for authenticated import verification.
use super::*;
use consensus::{DrainUnionIdentity, decode_drain_union_identity, encode_drain_union_identity};

// Verified unallocated across `crates/` and `docs/` at the 2026-09-30 U11
// allocation; unlike the neighbouring 0x6461/0x6462 frames this is local
// progress, never a transferable cut or signed authority.
const BARRIER_TYPE: u16 = 0x6463;
const BARRIER_VERSION: u16 = 1;
const MAX_BARRIER_BYTES: usize = 4096;

#[derive(Debug)]
pub enum BusinessFreeBarrierError {
    Node(NodeCoreError),
    Drain(DrainCompletionError),
    Suffix(SuffixPredicateError),
    NotReady(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for BusinessFreeBarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(formatter),
            Self::Drain(error) => error.fmt(formatter),
            Self::Suffix(error) => error.fmt(formatter),
            Self::NotReady(reason) | Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for BusinessFreeBarrierError {}

impl From<NodeCoreError> for BusinessFreeBarrierError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<RuntimeError> for BusinessFreeBarrierError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for BusinessFreeBarrierError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DrainCompletionError> for BusinessFreeBarrierError {
    fn from(value: DrainCompletionError) -> Self {
        Self::Drain(value)
    }
}
impl From<SuffixPredicateError> for BusinessFreeBarrierError {
    fn from(value: SuffixPredicateError) -> Self {
        Self::Suffix(value)
    }
}

fn encode_barrier(
    chain: &ChainId,
    epoch: Epoch,
    identity: &DrainUnionIdentity,
) -> Result<Vec<u8>, BusinessFreeBarrierError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(BARRIER_TYPE, BARRIER_VERSION);
    frame
        .field_bytes(
            1,
            canonical_encoding::encode_chain_id(chain)
                .map_err(|_| BusinessFreeBarrierError::Invalid("barrier chain does not encode"))?,
        )
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier chain field does not encode"))?;
    frame
        .field_u64(2, epoch.get())
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier epoch does not encode"))?;
    frame
        .field_bytes(
            3,
            encode_drain_union_identity(identity).map_err(|_| {
                BusinessFreeBarrierError::Invalid("barrier union identity does not encode")
            })?,
        )
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier union field does not encode"))?;
    let bytes: Vec<u8> = frame
        .finish()
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier does not encode"))?;
    if bytes.len() > MAX_BARRIER_BYTES {
        return Err(BusinessFreeBarrierError::Invalid(
            "barrier exceeds row bound",
        ));
    }
    Ok(bytes)
}

pub(super) fn decode_barrier(
    bytes: &[u8],
    chain: &ChainId,
    epoch: Epoch,
) -> Result<DrainUnionIdentity, BusinessFreeBarrierError> {
    if bytes.len() > MAX_BARRIER_BYTES {
        return Err(BusinessFreeBarrierError::Invalid(
            "barrier exceeds row bound",
        ));
    }
    let frame = decode_canonical_frame(bytes)
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier does not decode"))?;
    frame
        .require_type(BARRIER_TYPE)
        .and_then(|()| frame.require_version(BARRIER_VERSION))
        .and_then(|()| frame.require_only_fields(&[1, 2, 3]))
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier frame is foreign"))?;
    let stored_chain: &[u8] = frame
        .required_field(1)
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier chain is missing"))?;
    let expected_chain: Vec<u8> = canonical_encoding::encode_chain_id(chain)
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier chain does not encode"))?;
    let stored_epoch: u64 = frame
        .required_u64(2)
        .map_err(|_| BusinessFreeBarrierError::Invalid("barrier epoch is missing"))?;
    if stored_chain != expected_chain || stored_epoch != epoch.get() {
        return Err(BusinessFreeBarrierError::Invalid(
            "barrier context mismatch",
        ));
    }
    let identity: DrainUnionIdentity = decode_drain_union_identity(
        frame
            .required_field(3)
            .map_err(|_| BusinessFreeBarrierError::Invalid("barrier union is missing"))?,
    )
    .map_err(|_| BusinessFreeBarrierError::Invalid("barrier union does not decode"))?;
    if identity.chain_id != *chain || identity.epoch != epoch {
        return Err(BusinessFreeBarrierError::Invalid(
            "barrier union identity context mismatch",
        ));
    }
    if encode_barrier(chain, epoch, &identity)? != bytes {
        return Err(BusinessFreeBarrierError::Invalid("noncanonical barrier"));
    }
    Ok(identity)
}

/// Reads the retained local marker without treating it as portable authority
/// or re-deriving the conditions that originally installed it. A future Seal
/// driver must independently verify the current cut and consensus state.
pub fn read_business_free_barrier<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Option<DrainUnionIdentity>, BusinessFreeBarrierError> {
    let key: Vec<u8> = business_free_barrier_key(chain, epoch)?;
    let row: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    match row.value() {
        Some(bytes) => {
            let identity: DrainUnionIdentity = decode_barrier(bytes, chain, epoch)?;
            if identity.domain != domain {
                return Err(BusinessFreeBarrierError::Invalid("barrier domain mismatch"));
            }
            Ok(Some(identity))
        }
        None if row.revision() == StateRevision::INITIAL => Ok(None),
        None => Err(BusinessFreeBarrierError::Invalid("barrier is tombstoned")),
    }
}

/// Installs the local barrier only after the committed DrainSet is fully
/// receipt-backed and the authenticated high/locked suffix is candidate-free.
/// All observed rows, including the serving epoch and virgin barrier key,
/// are asserted in the *same* atomic commit as the marker. Exact replay
/// returns the immutable retained identity, but does not re-establish that a
/// future Seal's separate preconditions are currently satisfied.
pub fn advance_business_free_barrier<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<DrainUnionIdentity, BusinessFreeBarrierError> {
    let expected: &execution::publication::PublicationContext = env.policy.context();
    let chain: &ChainId = expected.chain_id();
    let epoch: Epoch = expected.epoch();
    let domain: AtomicityDomainId = env.policy.domain();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let serving: crate::local_instance_state::FastPathEpochRecord =
        crate::mutation_fence::fence_epoch_state(store, context, domain, chain, &mut reads)?;
    if serving.current_epoch != epoch {
        return Err(BusinessFreeBarrierError::NotReady(
            "barrier policy is not the current serving epoch",
        ));
    }
    let key: Vec<u8> = business_free_barrier_key(chain, epoch)?;
    let row: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(bytes) = row.value() {
        let retained: DrainUnionIdentity = decode_barrier(bytes, chain, epoch)?;
        if retained.domain != domain || retained.protocol_version != expected.protocol_version() {
            return Err(BusinessFreeBarrierError::Invalid(
                "barrier domain or protocol mismatch",
            ));
        }
        return Ok(retained);
    }
    if row.revision() != StateRevision::INITIAL {
        return Err(BusinessFreeBarrierError::Invalid("barrier is tombstoned"));
    }
    reads.insert(key.clone(), row.revision());
    let identity: DrainUnionIdentity =
        verify_drain_complete_into(store, context, domain, env.resolver, expected, &mut reads)?;
    verify_business_free_suffix_into(store, context, env, &mut reads)?;
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(
            key,
            StateMutation::Put(encode_barrier(chain, epoch, &identity)?),
        )?])?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(identity),
        DurableCommitOutcome::Rejected(reason) => {
            Err(NodeCoreError::DurableCommitRejected(reason).into())
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashAlgorithmId, ProtocolVersion};
    use sha2::{Digest, Sha256};

    fn fixture() -> (ChainId, Epoch, DrainUnionIdentity) {
        let chain: ChainId = ChainId::new("barrier-vector").unwrap();
        let epoch: Epoch = Epoch::new(3);
        let identity: DrainUnionIdentity = DrainUnionIdentity {
            chain_id: chain.clone(),
            protocol_version: ProtocolVersion::new(1),
            epoch,
            domain: AtomicityDomainId::new([2; 32]).unwrap(),
            closure_request_id: [9; 32],
            closure_height: 7,
            signer_count: 3,
            member_count: 2,
            entries_digest: Digest32::new(HashAlgorithmId::Blake3_256, [3; 32]),
        };
        (chain, epoch, identity)
    }

    #[test]
    fn barrier_frame_has_a_stable_sha256_vector_and_round_trips() {
        let (chain, epoch, identity): (ChainId, Epoch, DrainUnionIdentity) = fixture();
        let bytes: Vec<u8> = encode_barrier(&chain, epoch, &identity).unwrap();
        assert_eq!(decode_barrier(&bytes, &chain, epoch).unwrap(), identity);
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hash,
            "904fcb882cc657219711f53b2464d6a334e4f304435a744398d9bf62934b7a60"
        );
    }

    #[test]
    fn barrier_frame_rejects_wrong_context_truncation_and_oversize() {
        let (chain, epoch, identity): (ChainId, Epoch, DrainUnionIdentity) = fixture();
        let bytes: Vec<u8> = encode_barrier(&chain, epoch, &identity).unwrap();
        let foreign_chain: ChainId = ChainId::new("foreign-chain").unwrap();
        assert!(decode_barrier(&bytes, &foreign_chain, epoch).is_err());
        assert!(decode_barrier(&bytes, &chain, Epoch::new(4)).is_err());
        assert!(decode_barrier(&bytes[..bytes.len() - 1], &chain, epoch).is_err());
        assert!(decode_barrier(&vec![0; MAX_BARRIER_BYTES + 1], &chain, epoch).is_err());
    }
}
