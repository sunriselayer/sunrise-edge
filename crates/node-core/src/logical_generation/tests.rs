//! Focused tests for authenticated causal generations (DR-0154).
use super::*;
use protocol_types::{HashSuite, HashSuiteSchedule, ProtocolVersion, ValidatorId};
use runtime::{
    DurableDomainStateStore, DurableObjectProvenance, DurableObjectRoutingProjection,
    MemoryDurableStateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};

const CHAIN: &str = "logical-generation-tests";

struct Harness {
    store: MemoryDurableStateStore,
    context: DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: HashSuiteResolver,
    profile: LogicalProfileRecord,
}

impl Harness {
    fn new(floor: u64) -> Self {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let profile: LogicalProfileRecord = LogicalProfileRecord {
            context: context(),
            profile: CommitmentProfile::LogicalGenerationV2,
            manifest_digest: digest(0x11),
            genesis_authority: [7; 32],
            genesis_floor: ExecutionGeneration::new(floor),
            minimum_freeze_block_height: 0,
        };
        Self {
            store: MemoryDurableStateStore::new(generation),
            context: DurableOperationContext::new(
                generation,
                StorageDeadline::new(u64::MAX).unwrap(),
                StorageCorrelationId::new([3; 16]).unwrap(),
            ),
            domain: AtomicityDomainId::new([5; 32]).unwrap(),
            resolver: resolver(),
            profile,
        }
    }

    fn revision(&self, key: &[u8]) -> StateRevision {
        self.store
            .get_versioned_durable(&self.context, self.domain, key)
            .unwrap()
            .revision()
    }

    fn tombstoned_head(version: u64) -> DurableObjectHead {
        DurableObjectHead::Tombstoned {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            last_object_version: DurableObjectVersion::new(version).unwrap(),
        }
    }

    fn live_head(version: u64, seed: u8) -> DurableObjectHead {
        DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::new(version).unwrap(),
            digest: digest(seed),
            owner_projection: DurableObjectOwnerProjection::default(),
            routing_projection: runtime::DurableObjectRoutingProjection::default(),
        }
    }

    fn keys(&self) -> LogicalKeySpace<'_> {
        LogicalKeySpace::new(&self.profile, &self.resolver)
    }

    fn fence_profile(
        &self,
        reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    ) -> Result<InstalledCommitmentProfile, NodeCoreError> {
        fence_commitment_profile(
            &self.store,
            &self.context,
            self.domain,
            &ChainId::new(CHAIN).unwrap(),
            reads,
        )
    }

    fn derive(
        &self,
        heads: &[DurableObjectHeadRead],
        reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    ) -> Result<LogicalDerivation, NodeCoreError> {
        self.derive_with_nonce(heads, None, reads)
    }

    fn derive_with_nonce(
        &self,
        heads: &[DurableObjectHeadRead],
        nonce: Option<&PendingSenderNonceWrite>,
        reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    ) -> Result<LogicalDerivation, NodeCoreError> {
        super::derive(
            &self.store,
            &self.context,
            self.domain,
            &self.resolver,
            &self.profile,
            heads,
            nonce,
            reads,
        )
    }
}

fn write_row(harness: &Harness, key: &[u8], mutation: StateMutation) {
    let seen: VersionedStateValue = harness
        .store
        .get_versioned_durable(&harness.context, harness.domain, key)
        .unwrap();
    let reads: AtomicStateReadSet = AtomicStateReadSet::new(vec![
        StateReadAssertion::new(key.to_vec(), seen.revision()).unwrap(),
    ])
    .unwrap();
    let writes: AtomicStateMutationSet = AtomicStateMutationSet::new(vec![
        StateMutationEntry::new(key.to_vec(), mutation).unwrap(),
    ])
    .unwrap();
    let transaction: AtomicStateTransaction =
        AtomicStateTransaction::new(harness.domain, reads, writes).unwrap();
    assert_eq!(
        harness.store.commit_durable(&harness.context, transaction),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn profile_record_round_trips_and_rejects_an_unknown_model_tag() {
    let harness: Harness = Harness::new(0);
    let bytes: Vec<u8> = encode_logical_profile_record(&harness.profile).unwrap();
    assert_eq!(
        decode_logical_profile_record(&bytes).unwrap(),
        harness.profile
    );
    assert!(CommitmentProfile::from_wire(0).is_err());
    assert!(CommitmentProfile::from_wire(4).is_err());
    assert_eq!(
        CommitmentProfile::from_wire(3).unwrap(),
        CommitmentProfile::CausalAdmission
    );
    assert_eq!(
        CommitmentProfile::from_wire(1).unwrap(),
        CommitmentProfile::PhysicalCheckpointV1
    );
    assert!(!CommitmentProfile::PhysicalCheckpointV1.is_logical());
    assert!(CommitmentProfile::LogicalGenerationV2.is_logical());
    assert!(CommitmentProfile::CausalAdmission.is_logical());
}

#[test]
fn causal_profile_uses_existing_v2_record_shape_but_never_zero_minimum() {
    let harness: Harness = Harness::new(0);
    let mut profile: LogicalProfileRecord = harness.profile;
    profile.profile = CommitmentProfile::CausalAdmission;
    assert!(encode_logical_profile_record(&profile).is_err());
    profile.minimum_freeze_block_height = 3;
    let bytes: Vec<u8> = encode_logical_profile_record(&profile).unwrap();
    let frame: CanonicalFrame<'_> = decode_canonical_frame(&bytes).unwrap();
    assert_eq!(frame.version(), LOGICAL_PROFILE_FREEZE_RECORD_VERSION);
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(decode_logical_profile_record(&bytes).unwrap(), profile);
}

#[test]
fn fastpath_business_history_is_not_misclassified_as_local_reservation() {
    let chain: ChainId = ChainId::new(CHAIN).unwrap();
    let validator: ValidatorId = ValidatorId::new([0x41; 32]);
    let request: [u8; 32] = [0x42; 32];
    let local: [Vec<u8>; 5] = [
        local_instance_state::fastpath_prepared_record_key(&chain, &request).unwrap(),
        local_instance_state::fastpath_lock_key(&chain, ObjectId::new([0x43; 32])).unwrap(),
        local_instance_state::fastpath_nonce_lock_key(&chain, &[0x44; 32], Epoch::new(0)).unwrap(),
        crate::fast_path::prepared_material::fastpath_prepared_witness_key(&chain, &request)
            .unwrap(),
        crate::fast_path::prepared_material::fastpath_prepared_artifact_key(
            &chain,
            &request,
            consensus::bundle::ArtifactKind::StateValue,
            &[0x49; 32],
        )
        .unwrap(),
    ];
    for key in local {
        assert_eq!(
            classify_fastpath_row(&key),
            Some(FastpathRowClass::LocalReservation)
        );
        assert!(is_excluded_subject(&key));
    }
    let availability_ack: Vec<u8> =
        crate::fast_path::publication::fastpath_availability_ack_key(&chain, &request).unwrap();
    assert_eq!(
        classify_fastpath_row(&availability_ack),
        Some(FastpathRowClass::LocalSigningSafety)
    );
    assert!(is_excluded_subject(&availability_ack));
    let history: [Vec<u8>; 15] = [
        local_instance_state::fastpath_certificate_key(&chain, &request).unwrap(),
        local_instance_state::fastpath_commitment_witness_key(&chain, &request).unwrap(),
        local_instance_state::fastpath_settlement_key(&chain, &request).unwrap(),
        local_instance_state::fastpath_fee_claim_key(&chain, &request, 1).unwrap(),
        local_instance_state::fastpath_bond_record_key(&chain, &validator).unwrap(),
        local_instance_state::fastpath_bond_transition_key(&chain, &validator, 2).unwrap(),
        local_instance_state::fastpath_evidence_consumed_key(
            &chain,
            Epoch::new(0),
            [0x45; 32],
            digest(0x46),
        )
        .unwrap(),
        local_instance_state::fastpath_epoch_record_key(&chain).unwrap(),
        local_instance_state::fastpath_validator_set_key(&context()).unwrap(),
        local_instance_state::fastpath_epoch_transition_key(&chain, Epoch::new(1)).unwrap(),
        local_instance_state::fastpath_equivocation_evidence_key(
            &chain,
            Epoch::new(0),
            [0x47; 32],
            digest(0x48),
        )
        .unwrap(),
        local_instance_state::fastpath_economics_policy_key(&context()).unwrap(),
        // DR-0154 (2026-09-28): the retained full-certificate publication
        // record and its content-addressed replay artifacts.
        crate::fast_path::publication::fastpath_publication_key(&chain, &request).unwrap(),
        crate::fast_path::publication::fastpath_publication_artifact_key(
            &chain,
            &request,
            consensus::bundle::ArtifactKind::StateValue,
            &[0x49; 32],
        )
        .unwrap(),
        crate::fast_path::records::fastpath_availability_certificate_key(&chain, &request).unwrap(),
    ];
    for key in history {
        assert_eq!(
            classify_fastpath_row(&key),
            Some(FastpathRowClass::AuthenticatedHistory)
        );
        assert!(is_excluded_subject(&key));
    }
    let unknown: Vec<u8> = [
        local_instance_state::FASTPATH_STATE_PREFIX,
        b"future-business-family/",
    ]
    .concat();
    assert_eq!(classify_fastpath_row(&unknown), None);
    assert!(!is_excluded_subject(&unknown));
}

#[test]
fn ordered_outcome_history_is_not_misclassified_as_consensus_cache() {
    let prefix: &[u8] = ordered_economics::engine::ORDERED_ECONOMICS_STATE_PREFIX;
    for suffix in [b"state/".as_slice(), b"applied-height/", b"candidate/"] {
        let key: Vec<u8> = [prefix, suffix, b"example"].concat();
        assert_eq!(
            classify_ordered_row(&key),
            Some(OrderedRowClass::ConsensusControl)
        );
        assert!(is_excluded_subject(&key));
    }
    for suffix in [b"header/".as_slice(), b"outcome/", b"freeze/"] {
        let key: Vec<u8> = [prefix, suffix, b"example"].concat();
        assert_eq!(
            classify_ordered_row(&key),
            Some(OrderedRowClass::AuthenticatedOutcomeHistory)
        );
        assert!(is_excluded_subject(&key));
    }
    for suffix in [b"frontier-progress/".as_slice(), b"frontier/"] {
        let local_progress: Vec<u8> = [prefix, suffix, b"example"].concat();
        assert_eq!(
            classify_ordered_row(&local_progress),
            Some(OrderedRowClass::LocalProgress)
        );
        assert!(is_excluded_subject(&local_progress));
    }
    let unknown: Vec<u8> = [prefix, b"future-family/"].concat();
    assert_eq!(classify_ordered_row(&unknown), None);
    assert!(!is_excluded_subject(&unknown));
}

#[test]
fn maximum_genesis_object_count_fits_logical_provenance_and_atomic_write_bounds() {
    let harness: Harness = Harness::new(0);
    let (manifest, _, _, _, _) = crate::genesis::tests::build_fixture();
    let template: Object = manifest.objects[0].object.clone();
    let mut object_mutations: Vec<DurableObjectMutationEntry> = Vec::new();
    for index in 0..crate::genesis::MAX_GENESIS_OBJECTS {
        let mut object: Object = template.clone();
        object.id = ObjectId::new([u8::try_from(index + 1).unwrap(); 32]);
        let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
        let digest: Digest32 = harness
            .resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &bytes)
            .unwrap();
        let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
            object.clone(),
            digest,
            DurableObjectProvenance::new(ChainId::new(CHAIN).unwrap(), ProtocolVersion::new(3)),
            10,
        )
        .unwrap();
        object_mutations.push(DurableObjectMutationEntry::new(
            object.id,
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(object.owner).unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        ));
    }
    let state_mutations: Vec<StateMutationEntry> = (0..32u8)
        .map(|index: u8| {
            StateMutationEntry::new(vec![b'g', index], StateMutation::Put(vec![index])).unwrap()
        })
        .collect();
    let provenance: Vec<StateMutationEntry> = genesis_provenance(
        &harness.profile,
        &harness.resolver,
        Epoch::new(0),
        &state_mutations,
        &object_mutations,
    )
    .unwrap();
    assert_eq!(provenance.len(), crate::genesis::MAX_GENESIS_OBJECTS + 32);
    let mut all_state_writes: Vec<StateMutationEntry> = state_mutations;
    all_state_writes.extend(provenance);
    assert!(all_state_writes.len() <= runtime::MAX_ATOMIC_STATE_WRITES);
    AtomicStateMutationSet::new(all_state_writes).unwrap();
}

fn install_provenance(
    harness: &Harness,
    subject: &LogicalSubject,
    generation: u64,
    observation: LogicalObservation,
) {
    let record: LogicalProvenanceRecord = LogicalProvenanceRecord {
        subject: subject.clone(),
        observed_epoch: Epoch::new(0),
        generation: ExecutionGeneration::new(generation),
        observation,
    };
    let key: Vec<u8> = harness.keys().provenance_key(subject).unwrap();
    let bytes: Vec<u8> = encode_logical_provenance_record(&record).unwrap();
    write_row(harness, &key, StateMutation::Put(bytes));
}

fn install_state(harness: &Harness, key: &[u8], value: &[u8], generation: u64) {
    write_row(harness, key, StateMutation::Put(value.to_vec()));
    let observed: Digest32 = content_digest(&harness.resolver, Epoch::new(0), value).unwrap();
    install_provenance(
        harness,
        &LogicalSubject::StateKey(key.to_vec()),
        generation,
        LogicalObservation::StatePresent {
            content_digest: observed,
        },
    );
}

/// The sender-nonce row is exactly one authenticated subject: its own
/// `NonceNext` observation. It is never also folded as a generic state key,
/// which would demand two provenance rows for one row and fail closed on the
/// very next operation.
#[test]
fn the_sender_nonce_is_one_subject_with_its_own_dependency() {
    let harness: Harness = Harness::new(2);
    let sender: [u8; 32] = [0x21; 32];
    let epoch: Epoch = Epoch::new(0);
    let layout: PersistenceLayout =
        PersistenceLayout::new(ChainId::new(CHAIN).unwrap(), ProtocolVersion::new(3));
    let key: Vec<u8> = layout.sender_nonce_key(sender, epoch);
    write_row(
        &harness,
        &key,
        StateMutation::Put(SenderNonceRecord::new(sender, epoch, 6).encode().unwrap()),
    );
    install_provenance(
        &harness,
        &LogicalSubject::SenderNonce { sender, epoch },
        8,
        LogicalObservation::NonceNext { next_nonce: 6 },
    );
    let pending: PendingSenderNonceWrite = PendingSenderNonceWrite {
        key: key.clone(),
        read_revision: harness.revision(&key),
        record: SenderNonceRecord::new(sender, epoch, 7),
    };
    // The advancing row is in `reads` exactly as every caller leaves it.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    reads.insert(key.clone(), pending.read_revision);
    let derived: LogicalDerivation = harness
        .derive_with_nonce(&[], Some(&pending), &mut reads)
        .unwrap();
    assert_eq!(derived.generation.get(), 9);
    assert_eq!(
        derived.input(&LogicalSubject::SenderNonce { sender, epoch }),
        Some(ExecutionGeneration::new(8))
    );
    assert_eq!(derived.input(&LogicalSubject::StateKey(key)), None);
}

/// Every real caller stages the sender-nonce row's own `Put` into
/// `state_mutations` *and* passes the same reservation as `nonce`, exactly
/// like every other staged mutation (see `publication.rs`, `local_execution.rs`,
/// `bond_lifecycle.rs`, `fee_claims/preparation.rs`). `staged_writes` must
/// still install exactly one provenance row for that one physical row: its
/// own semantic `NonceNext` observation, never also a generic `StateKey`
/// observation over the same encoded bytes.
#[test]
fn staged_writes_installs_one_provenance_row_for_a_prestaged_nonce_put() {
    let sender: [u8; 32] = [0x31; 32];
    let epoch: Epoch = Epoch::new(0);
    let layout: PersistenceLayout =
        PersistenceLayout::new(ChainId::new(CHAIN).unwrap(), ProtocolVersion::new(3));
    let nonce_key: Vec<u8> = layout.sender_nonce_key(sender, epoch);
    let record: SenderNonceRecord = SenderNonceRecord::new(sender, epoch, 5);
    let pending: PendingSenderNonceWrite = PendingSenderNonceWrite {
        key: nonce_key.clone(),
        read_revision: StateRevision::INITIAL,
        record,
    };
    let other_key: Vec<u8> = b"se/example/other".to_vec();
    let state_mutations: Vec<StateMutationEntry> = vec![
        StateMutationEntry::new(
            nonce_key.clone(),
            StateMutation::Put(record.encode().unwrap()),
        )
        .unwrap(),
        StateMutationEntry::new(other_key.clone(), StateMutation::Put(vec![1, 2, 3])).unwrap(),
    ];
    let hashes: HashSuiteResolver = resolver();
    let writes: Vec<LogicalWrite> =
        staged_writes(&hashes, epoch, &state_mutations, &[], &[], Some(&pending)).unwrap();
    assert_eq!(writes.len(), 2);
    let nonce_writes: Vec<&LogicalWrite> = writes
        .iter()
        .filter(|write| write.subject == LogicalSubject::SenderNonce { sender, epoch })
        .collect();
    assert_eq!(nonce_writes.len(), 1);
    assert_eq!(
        nonce_writes[0].observation,
        LogicalObservation::NonceNext { next_nonce: 5 }
    );
    assert!(
        writes
            .iter()
            .any(|write| write.subject == LogicalSubject::StateKey(other_key.clone()))
    );
    assert!(
        !writes
            .iter()
            .any(|write| write.subject == LogicalSubject::StateKey(nonce_key.clone()))
    );

    for mutation in [StateMutation::Put(vec![0xFF]), StateMutation::Delete] {
        let conflicting: Vec<StateMutationEntry> =
            vec![StateMutationEntry::new(nonce_key.clone(), mutation).unwrap()];
        assert!(matches!(
            staged_writes(&hashes, epoch, &conflicting, &[], &[], Some(&pending)),
            Err(NodeCoreError::LogicalProvenance(
                "sender nonce mutation differs from reservation"
            ))
        ));
    }
}

/// A nonce row that moved since its reservation refuses here rather than
/// producing a generation derived from a state this operation never observed.
#[test]
fn a_stale_sender_nonce_fence_refuses_before_any_derivation() {
    let harness: Harness = Harness::new(0);
    let sender: [u8; 32] = [0x22; 32];
    let epoch: Epoch = Epoch::new(0);
    let layout: PersistenceLayout =
        PersistenceLayout::new(ChainId::new(CHAIN).unwrap(), ProtocolVersion::new(3));
    let key: Vec<u8> = layout.sender_nonce_key(sender, epoch);
    write_row(
        &harness,
        &key,
        StateMutation::Put(SenderNonceRecord::new(sender, epoch, 3).encode().unwrap()),
    );
    let pending: PendingSenderNonceWrite = PendingSenderNonceWrite {
        key: key.clone(),
        read_revision: StateRevision::INITIAL,
        record: SenderNonceRecord::new(sender, epoch, 4),
    };
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.derive_with_nonce(&[], Some(&pending), &mut reads),
        Err(NodeCoreError::StateConflict)
    ));
}

/// A nonce row that exists without matching authenticated provenance is a
/// store the new profile never produced: it fails closed instead of deriving a
/// generation from an unauthenticated observation.
#[test]
fn a_nonce_row_without_provenance_fails_closed() {
    let harness: Harness = Harness::new(0);
    let sender: [u8; 32] = [0x23; 32];
    let epoch: Epoch = Epoch::new(0);
    let layout: PersistenceLayout =
        PersistenceLayout::new(ChainId::new(CHAIN).unwrap(), ProtocolVersion::new(3));
    let key: Vec<u8> = layout.sender_nonce_key(sender, epoch);
    write_row(
        &harness,
        &key,
        StateMutation::Put(SenderNonceRecord::new(sender, epoch, 2).encode().unwrap()),
    );
    let pending: PendingSenderNonceWrite = PendingSenderNonceWrite {
        key: key.clone(),
        read_revision: harness.revision(&key),
        record: SenderNonceRecord::new(sender, epoch, 3),
    };
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.derive_with_nonce(&[], Some(&pending), &mut reads),
        Err(NodeCoreError::LogicalProvenance(_))
    ));
}

/// A generation is a causal operand, not a serialized counter: two operations
/// over disjoint verified inputs legitimately derive the same generation.
#[test]
fn independent_operations_may_share_one_generation() {
    let harness: Harness = Harness::new(3);
    let left: ObjectId = ObjectId::new([0x41; 32]);
    let right: ObjectId = ObjectId::new([0x42; 32]);
    for object in [left, right] {
        install_provenance(
            &harness,
            &LogicalSubject::Object(object),
            3,
            LogicalObservation::ObjectLive {
                object_version: 1,
                digest: digest(0x51),
            },
        );
    }
    let mut first_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let first: LogicalDerivation = harness
        .derive(
            &[DurableObjectHeadRead::new(
                left,
                Harness::live_head(1, 0x51),
            )],
            &mut first_reads,
        )
        .unwrap();
    let mut second_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let second: LogicalDerivation = harness
        .derive(
            &[DurableObjectHeadRead::new(
                right,
                Harness::live_head(1, 0x51),
            )],
            &mut second_reads,
        )
        .unwrap();
    assert_eq!(first.generation, second.generation);
    assert_eq!(first.generation.get(), 4);
}

/// An unrepresentable successor is a typed refusal before anything is derived,
/// reserved or signed, never a saturating or wrapping increment.
#[test]
fn an_unrepresentable_successor_refuses() {
    let harness: Harness = Harness::new(u64::MAX);
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.derive(&[], &mut reads),
        Err(NodeCoreError::ExecutionGenerationOverflow { floor }) if floor == u64::MAX
    ));
}

/// A provenance row round-trips exactly, and a truncated, padded or empty
/// frame is refused rather than partially accepted.
#[test]
fn a_provenance_row_round_trips_and_rejects_noncanonical_bytes() {
    let honest: LogicalProvenanceRecord = LogicalProvenanceRecord {
        subject: LogicalSubject::Object(ObjectId::new([9; 32])),
        observed_epoch: Epoch::new(0),
        generation: ExecutionGeneration::new(1),
        observation: LogicalObservation::ObjectDeleted {
            last_object_version: 2,
        },
    };
    let bytes: Vec<u8> = encode_logical_provenance_record(&honest).unwrap();
    assert_eq!(decode_logical_provenance_record(&bytes).unwrap(), honest);
    assert!(decode_logical_provenance_record(&bytes[..bytes.len() - 1]).is_err());
    let mut padded: Vec<u8> = bytes.clone();
    padded.push(0);
    assert!(decode_logical_provenance_record(&padded).is_err());
    assert!(decode_logical_provenance_record(&[]).is_err());
}

/// The historical profile keeps the physical creation-checkpoint minimum; the
/// handoff-capable profile replaces it with the authenticated generation, so a
/// node whose own local checkpoint sequence restarted lower after a quorum
/// handoff is not rejected for that reason alone.
#[test]
fn the_object_minimum_follows_the_installed_profile() {
    let harness: Harness = Harness::new(0);
    let historical: ObjectMinimum =
        ObjectMinimum::for_profile(&InstalledCommitmentProfile::Historical, 7);
    assert_eq!(historical, ObjectMinimum::CreationCheckpoint(7));
    assert!(historical.admits(7));
    assert!(historical.admits(6));
    assert!(!historical.admits(8));
    let logical: ObjectMinimum = ObjectMinimum::for_profile(
        &InstalledCommitmentProfile::Logical(harness.profile.clone()),
        7,
    );
    assert_eq!(logical, ObjectMinimum::AuthenticatedGeneration);
    assert!(logical.admits(8));
    assert!(logical.admits(u64::MAX));
}

fn digest(seed: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Blake3_256, [seed; 32])
}

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new(CHAIN).unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap()
}

/// One derivation carrying no observed input, for gate-level assertions.
fn derivation(generation: u64) -> LogicalDerivation {
    LogicalDerivation {
        generation: ExecutionGeneration::new(generation),
        reads: BTreeMap::new(),
        inputs: BTreeMap::new(),
    }
}

#[test]
fn derive_folds_a_verified_object_input_above_the_floor() {
    let harness: Harness = Harness::new(9);
    let object: ObjectId = ObjectId::new([3; 32]);
    let live: LogicalObservation = LogicalObservation::ObjectLive {
        object_version: 2,
        digest: digest(0x31),
    };
    install_provenance(&harness, &LogicalSubject::Object(object), 7, live);
    let heads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        object,
        Harness::live_head(2, 0x31),
    )];
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let derived: LogicalDerivation = harness.derive(&heads, &mut reads).unwrap();
    assert_eq!(derived.generation.get(), 10);
    let chain: ChainId = ChainId::new(CHAIN).unwrap();
    let key: Vec<u8> =
        local_instance_state::instance_record_key(&chain, &[3; 32], &[4; 32]).unwrap();
    install_state(&harness, &key, b"instance-record", 12);
    reads.insert(key.clone(), harness.revision(&key));
    let again: LogicalDerivation = harness.derive(&heads, &mut reads).unwrap();
    assert_eq!(again.generation.get(), 13);
}

/// A handoff-capable store never applies without the evidence it derived, and
/// a historical store can never carry that evidence.
#[test]
fn the_application_gate_refuses_a_mismatched_pairing() {
    let harness: Harness = Harness::new(4);
    let historical: InstalledCommitmentProfile = InstalledCommitmentProfile::Historical;
    let logical: InstalledCommitmentProfile =
        InstalledCommitmentProfile::Logical(harness.profile.clone());
    let derived: LogicalDerivation = derivation(5);
    require_application_admissible(&historical, None).unwrap();
    require_application_admissible(&logical, Some(&derived)).unwrap();
    assert!(matches!(
        require_application_admissible(&historical, Some(&derived)),
        Err(NodeCoreError::LogicalProfileApplicationUnsupported)
    ));
    assert!(matches!(
        require_application_admissible(&logical, None),
        Err(NodeCoreError::LogicalProfileApplicationUnsupported)
    ));
}

/// Evidence that does not strictly exceed the authenticated genesis floor is a
/// replay, not a derivation, and is refused before anything is applied.
#[test]
fn the_application_gate_refuses_floor_level_evidence() {
    let harness: Harness = Harness::new(4);
    let logical: InstalledCommitmentProfile =
        InstalledCommitmentProfile::Logical(harness.profile.clone());
    assert!(matches!(
        require_application_admissible(&logical, Some(&derivation(4))),
        Err(NodeCoreError::ExecutionGenerationRegression {
            previous: 4,
            attempted: 4
        })
    ));
    assert!(matches!(
        require_application_admissible(&logical, Some(&derivation(3))),
        Err(NodeCoreError::ExecutionGenerationRegression {
            previous: 4,
            attempted: 3
        })
    ));
}

/// A removed profile row is not absence: a handoff-capable store cannot be
/// talked back into historical admission by deleting its own binding.
#[test]
fn a_removed_profile_row_fails_closed_instead_of_reading_as_historical() {
    let harness: Harness = Harness::new(0);
    let chain: ChainId = ChainId::new(CHAIN).unwrap();
    let key: Vec<u8> = logical_profile_key(&chain).unwrap();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    // The profile row is this module's own never-changing metadata, so the
    // signed commitment excludes it; a per-subject provenance row is not.
    assert!(is_logical_profile_key(&key));
    assert!(is_logical_provenance_key(&key));
    assert!(!is_logical_profile_key(
        &harness
            .keys()
            .provenance_key(&LogicalSubject::Object(ObjectId::new([1; 32])))
            .unwrap()
    ));
    // Both live inside the reserved instance namespace the generic path's
    // plan-access and transition-mutation checks already consult, so no
    // caller-supplied plan can install, read or overwrite a binding and walk a
    // historical store into the handoff-capable profile.
    assert!(local_instance_state::is_reserved(&key));
    assert!(local_instance_state::is_reserved(
        &harness
            .keys()
            .provenance_key(&LogicalSubject::Object(ObjectId::new([1; 32])))
            .unwrap()
    ));
    // Pristine: a store installed before DR-0154.
    assert!(matches!(
        harness.fence_profile(&mut reads).unwrap(),
        InstalledCommitmentProfile::Historical
    ));
    write_row(
        &harness,
        &key,
        StateMutation::Put(encode_logical_profile_record(&harness.profile).unwrap()),
    );
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.fence_profile(&mut reads).unwrap(),
        InstalledCommitmentProfile::Logical(_)
    ));
    write_row(&harness, &key, StateMutation::Delete);
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.fence_profile(&mut reads),
        Err(NodeCoreError::LogicalProvenance(_))
    ));
}

/// A historical (v1) admission installs no read assertion on the profile
/// row: that row can only ever be written once, by a fresh `install_genesis`
/// that refuses outright once any marker exists, so fencing it protects
/// against nothing and would only cost a slot of the bounded read set. A
/// handoff-capable admission keeps its real compare-and-swap fence on it.
#[test]
fn historical_admission_fences_no_profile_read_assertion() {
    let harness: Harness = Harness::new(0);
    let chain: ChainId = ChainId::new(CHAIN).unwrap();
    let key: Vec<u8> = logical_profile_key(&chain).unwrap();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.fence_profile(&mut reads).unwrap(),
        InstalledCommitmentProfile::Historical
    ));
    assert!(reads.is_empty());
    write_row(
        &harness,
        &key,
        StateMutation::Put(encode_logical_profile_record(&harness.profile).unwrap()),
    );
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        harness.fence_profile(&mut reads).unwrap(),
        InstalledCommitmentProfile::Logical(_)
    ));
    assert_eq!(reads.get(&key).copied(), Some(harness.revision(&key)));
}

#[test]
fn derive_distinguishes_an_absent_object_from_a_tombstone() {
    let harness: Harness = Harness::new(0);
    let absent: ObjectId = ObjectId::new([4; 32]);
    let heads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        absent,
        DurableObjectHead::Absent,
    )];
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let derived: LogicalDerivation = harness.derive(&heads, &mut reads).unwrap();
    assert_eq!(derived.generation.get(), 1);
    let gone: ObjectId = ObjectId::new([5; 32]);
    let tombstone: LogicalObservation = LogicalObservation::ObjectDeleted {
        last_object_version: 3,
    };
    install_provenance(&harness, &LogicalSubject::Object(gone), 6, tombstone);
    let heads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        gone,
        Harness::tombstoned_head(3),
    )];
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let derived: LogicalDerivation = harness.derive(&heads, &mut reads).unwrap();
    assert_eq!(derived.generation.get(), 7);
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new(CHAIN).unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
