//! Reserved immutable public-instance authority storage and legacy isolation.
//!
//! Key construction confers no authority. Only the fenced typed execution
//! admission may populate these rows; generic plans cannot access either root.

use super::*;
use canonical_encoding::encode_chain_id;
use execution::publication::{PublicationContext, encode_publication_context};

/// Reserved across storage-profile and protocol upgrades.
pub const INSTANCE_STATE_PREFIX: &[u8] = b"se/instances/";
/// Reserved authority provenance, including retained consumed-object sidecars.
pub const OBJECT_AUTHORITY_STATE_PREFIX: &[u8] = b"se/object-authority/";

/// Immutable logical instance key: self-framed chain followed by two bytes32
/// fields. Protocol versions, epochs and digest algorithms do not change it.
pub fn instance_record_key(
    chain: &ChainId,
    creator: &[u8; 32],
    seed: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = INSTANCE_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/records/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(creator);
    key.extend_from_slice(seed);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Immutable authority key in the same atomicity domain as its object head.
#[must_use]
pub fn object_authority_key(object_id: ObjectId) -> Vec<u8> {
    let mut key: Vec<u8> = OBJECT_AUTHORITY_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/");
    key.extend_from_slice(object_id.as_bytes());
    key
}

/// Trusted execution policy key retains the original verification context.
pub fn execution_policy_key(context: &PublicationContext) -> Result<Vec<u8>, NodeCoreError> {
    execution_policy_key_for_profile(context, 2)
}
/// Explicit profile-key activation; profile-two retains its historical key.
pub fn execution_policy_key_for_profile(
    context: &PublicationContext,
    profile: u32,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = INSTANCE_STATE_PREFIX.to_vec();
    match profile {
        2 => key.extend_from_slice(b"v1/policies/"),
        3 => key.extend_from_slice(b"v2/policies/"),
        _ => {
            return Err(NodeCoreError::PersistenceInvariant(
                "unsupported execution profile",
            ));
        }
    }
    key.extend(encode_publication_context(context).map_err(|_| {
        NodeCoreError::PersistenceInvariant("invalid local execution policy context")
    })?);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

pub(super) fn is_reserved(key: &[u8]) -> bool {
    key.starts_with(INSTANCE_STATE_PREFIX) || key.starts_with(OBJECT_AUTHORITY_STATE_PREFIX)
}

/// Absence is asserted at commit, never treated as a permanent authorization.
/// Tombstones reject too: removing a sidecar cannot downgrade a public object.
pub(super) fn legacy_absence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    object_id: ObjectId,
) -> Result<StateReadAssertion, NodeCoreError> {
    let key: Vec<u8> = object_authority_key(object_id);
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
        return Err(NodeCoreError::ReservedStateAccess(key));
    }
    Ok(StateReadAssertion::new(key, observed.revision())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{
        DurableDomainStateStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };

    #[test]
    fn executable_publication_policy_matches_independent_node_vector() {
        let chain: ChainId = ChainId::new("local-vector").unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain,
            ProtocolVersion::new(3),
            vec![protocol_types::HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: protocol_types::HashSuite::genesis(),
            }],
        )
        .unwrap();
        let semantics: Digest32 =
            publication::local_executable_publication_semantics(&resolver, &context).unwrap();
        let policy: publication::LocalPublicationPolicy =
            publication::LocalPublicationPolicy::executable(context, semantics);
        let bytes: Vec<u8> = policy.encode().unwrap();
        assert_eq!(bytes.len(), 172);
        let digest: Digest32 = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, &bytes)
            .unwrap();
        let hex: String = digest
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hex,
            "4c92b0152c43b3ee7f8269472f0c47bbfc281473198f0617f6f53937303750f1"
        );
    }

    #[test]
    fn identity_keys_are_framed_and_namespaces_are_reserved() {
        let chain: ChainId = ChainId::new("local-instances").unwrap();
        let key: Vec<u8> = instance_record_key(&chain, &[1; 32], &[2; 32]).unwrap();
        assert_ne!(
            key,
            instance_record_key(&chain, &[2; 32], &[1; 32]).unwrap()
        );
        assert!(is_reserved(&key));
        let authority: Vec<u8> = object_authority_key(ObjectId::new([7; 32]));
        assert!(is_reserved(&authority));
        assert_eq!(&authority[authority.len() - 32..], &[7; 32]);
        for prefix in [INSTANCE_STATE_PREFIX, OBJECT_AUTHORITY_STATE_PREFIX] {
            let mut future: Vec<u8> = prefix.to_vec();
            future.extend_from_slice(b"v999/arbitrary");
            let plan: NodeStateAccessPlan = NodeStateAccessPlan::new(vec![
                NodeStateAccess::new(future.clone(), NodeStateAccessMode::ReadWrite).unwrap(),
            ])
            .unwrap();
            let layout: PersistenceLayout =
                PersistenceLayout::new(chain.clone(), ProtocolVersion::new(3));
            assert!(
                matches!(validate_sender_nonce_namespace(&plan, &layout), Err(NodeCoreError::ReservedStateAccess(actual)) if actual == future)
            );
        }
    }

    #[test]
    fn legacy_absence_is_cas_bound_and_live_or_tombstoned_authority_rejects() {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new(generation);
        let context: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([3; 16]).unwrap(),
        );
        let domain: AtomicityDomainId = AtomicityDomainId::new([5; 32]).unwrap();
        let id: ObjectId = ObjectId::new([7; 32]);
        let stale: StateReadAssertion = legacy_absence(&store, &context, domain, id).unwrap();
        let key: Vec<u8> = object_authority_key(id);
        for mutation in [StateMutation::Put(vec![1]), StateMutation::Delete] {
            let observed: VersionedStateValue =
                store.get_versioned_durable(&context, domain, &key).unwrap();
            let tx: AtomicStateTransaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(key.clone(), mutation).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                store.commit_durable(&context, tx),
                DurableCommitOutcome::Committed
            );
            assert!(matches!(
                legacy_absence(&store, &context, domain, id),
                Err(NodeCoreError::ReservedStateAccess(_))
            ));
        }
        let output_key: Vec<u8> = b"legacy-output".to_vec();
        let tx: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                stale,
                StateReadAssertion::new(output_key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(output_key.clone(), StateMutation::Put(vec![9])).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.commit_durable(&context, tx),
            DurableCommitOutcome::Rejected(_)
        ));
        assert!(
            store
                .get_versioned_durable(&context, domain, &output_key)
                .unwrap()
                .value()
                .is_none()
        );
    }
}
