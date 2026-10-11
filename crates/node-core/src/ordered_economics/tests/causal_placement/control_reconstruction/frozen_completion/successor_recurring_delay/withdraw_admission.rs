//! Fresh withdrawal controls on G's real registration, ordinary Unbond and
//! full seven-epoch successor history. Invoked once by the existing recurrence
//! test at its genuine unlock, before its unchanged accepted Withdraw/replay.
//! No positive bond, registration anchor, committee or custody row is seeded.
use super::*;
use crate::bond_lifecycle::decode_signed_bond_lifecycle_intent;
use crate::ordered_economics::durable_keys::{OrderedKeyFamily, scoped_key};
use crate::ordered_economics::observed_read::ObservedBusinessReadView;
use runtime::portable::{
    DurablePortableRepository, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableSnapshotError, PortableSnapshotToken,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, ImportBatch, ImportBinding, ImportProgress,
    InactiveImportRepository, OutgoingBarrier, SealBarrier, StateObservationSet,
    SuccessorServingObservation, SuccessorServingRepository, SuccessorServingSlot,
    VersionedStateReader,
};
use std::cell::RefCell;

#[derive(Clone, Copy)]
enum RaceAt {
    Commit,
    SecondRead,
}

/// A real forwarding adapter. Its live warrant is issued to this exact
/// adapter, and every mutation port is counted and forwarded to real SQLite.
/// The optional competing write changes only the selected row's revision;
/// its original bytes, business meaning and provenance remain unchanged.
struct AttemptStore<'a> {
    origin: &'a SuccessorWorld,
    hosts: &'a EpochHosts,
    index: usize,
    commits: Cell<usize>,
    object_reads: Cell<usize>,
    reads: RefCell<BTreeMap<Vec<u8>, usize>>,
    committed_reads: RefCell<Vec<StateReadAssertion>>,
    race: Option<(RaceAt, Vec<u8>)>,
    armed: Cell<bool>,
    raced: Cell<bool>,
    after_race: RefCell<Option<SourceBusinessSnapshot>>,
}

impl<'a> AttemptStore<'a> {
    fn new(
        origin: &'a SuccessorWorld,
        hosts: &'a EpochHosts,
        index: usize,
        race: Option<(RaceAt, Vec<u8>)>,
    ) -> Self {
        Self {
            origin,
            hosts,
            index,
            commits: Cell::new(0),
            object_reads: Cell::new(0),
            reads: RefCell::new(BTreeMap::new()),
            committed_reads: RefCell::new(Vec::new()),
            race,
            armed: Cell::new(false),
            raced: Cell::new(false),
            after_race: RefCell::new(None),
        }
    }

    fn inner(&self) -> &SqliteImportTarget {
        &self.hosts.targets[self.index].0
    }

    fn warrant<'s>(&'s self, archive: &CompleteArchive) -> LiveWarrant<'s> {
        let mut artifacts: ArchiveTransport<'_> = ArchiveTransport::new(&archive.links);
        let authority: LiveAuthority<'s> = resolve_live_authority_chain(
            self,
            &self.hosts.operation,
            self.origin.network().domain(),
            reconstruction_plan(self.origin.source(), &self.origin.cut_history),
            &archive.pins,
            CompleteArchive::budget(),
            &mut artifacts,
            self.hosts.public_key(self.origin, self.index),
        )
        .unwrap();
        match authority {
            LiveAuthority::Successor(warrant) => *warrant,
            LiveAuthority::OriginalGenesis => panic!("the actual epoch is an activated successor"),
        }
    }

    fn arm(&self) {
        self.reads.borrow_mut().clear();
        self.object_reads.set(0);
        self.armed.set(true);
    }

    fn count_commit(&self) {
        self.commits.set(self.commits.get().checked_add(1).unwrap());
    }

    fn rewrite(&self, key: &[u8]) {
        assert!(!self.raced.replace(true));
        let context: &DurableOperationContext = &self.hosts.operation;
        let domain: AtomicityDomainId = self.origin.network().domain();
        let observed: VersionedStateValue = self.inner()
            .get_versioned_durable(context, domain, key).unwrap();
        let bytes: Vec<u8> = observed.value().unwrap().to_vec();
        let SuccessorServingSlot::Serving(serving) = self.inner()
            .get_successor_serving(context, domain).unwrap()
        else {
            panic!("the competing write requires the actual protected serving slot")
        };
        let transaction: AtomicStateTransaction = AtomicStateTransaction::from_sets(
            AtomicStateReadSet::new(domain, vec![
                StateReadAssertion::new(key.to_vec(), observed.revision()).unwrap(),
            ]).unwrap(),
            AtomicStateMutationSet::new(domain, vec![
                StateMutationEntry::new(key.to_vec(), StateMutation::Put(bytes)).unwrap(),
            ]).unwrap(),
        ).unwrap();
        assert_eq!(
            self.inner().commit_successor_durable(context, &serving, transaction),
            DurableCommitOutcome::Committed,
            "the competing invocation performs one real protected revision change"
        );
        *self.after_race.borrow_mut() = Some(self.hosts.capture(self.origin, self.index));
    }

    fn before_commit(&self, reads: &[StateReadAssertion]) {
        self.count_commit();
        *self.committed_reads.borrow_mut() = reads.to_vec();
        if self.armed.get()
            && let Some((RaceAt::Commit, key)) = &self.race
        {
            self.rewrite(key);
        }
    }
}

impl DurableDomainStateStore for AttemptStore<'_> {
    fn get_namespace_lifecycle(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, DurableReadError> {
        self.inner().get_namespace_lifecycle(c, d)
    }
    fn get_outgoing_barrier(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError> {
        self.inner().get_outgoing_barrier(c, d)
    }
    fn get_successor_serving(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
    ) -> Result<SuccessorServingSlot, DurableReadError> {
        self.inner().get_successor_serving(c, d)
    }
    fn get_versioned_durable(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        if self.armed.get() {
            let count: usize = {
                let mut reads: std::cell::RefMut<'_, BTreeMap<Vec<u8>, usize>> =
                    self.reads.borrow_mut();
                let count: &mut usize = reads.entry(key.to_vec()).or_default();
                *count = count.checked_add(1).unwrap();
                *count
            };
            if let Some((RaceAt::SecondRead, selected)) = &self.race
                && selected.as_slice() == key && count == 2
            {
                self.rewrite(key);
            }
        }
        self.inner().get_versioned_durable(c, d, key)
    }
    fn commit_durable(
        &self, c: &DurableOperationContext, tx: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.reads());
        self.inner().commit_durable(c, tx)
    }
}

impl StructuredDurableDomainStateStore for AttemptStore<'_> {
    fn get_object_head(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        if self.armed.get() {
            self.object_reads.set(self.object_reads.get().checked_add(1).unwrap());
        }
        self.inner().get_object_head(c, d, id)
    }
    fn get_object_version(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        id: ObjectId, version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        if self.armed.get() {
            self.object_reads.set(self.object_reads.get().checked_add(1).unwrap());
        }
        self.inner().get_object_version(c, d, id, version)
    }
    fn get_request_receipt(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner().get_request_receipt(c, d, id)
    }
    fn commit_invocation(
        &self, c: &DurableOperationContext, tx: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.state().unwrap().reads());
        self.inner().commit_invocation(c, tx)
    }
    fn successor_serving_repository(&self) -> Option<&dyn SuccessorServingRepository> {
        Some(self)
    }
}

impl DurablePortableRepository for AttemptStore<'_> {
    fn scan_portable_keys(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.inner().scan_portable_keys(c, d, scan)
    }
    fn read_portable_descriptor(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.inner().read_portable_descriptor(c, d, key)
    }
    fn read_portable_chunk(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.inner().read_portable_chunk(c, d, request)
    }
}

impl DurablePortableSnapshotRepository for AttemptStore<'_> {
    fn begin_portable_snapshot(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.inner().begin_portable_snapshot(c, d)
    }
    fn scan_portable_keys_at(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        token: &PortableSnapshotToken, scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.inner().scan_portable_keys_at(c, d, token, scan)
    }
    fn read_portable_descriptor_at(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        token: &PortableSnapshotToken, key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        self.inner().read_portable_descriptor_at(c, d, token, key)
    }
    fn read_portable_chunk_at(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        token: &PortableSnapshotToken, request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.inner().read_portable_chunk_at(c, d, token, request)
    }
    fn check_portable_outbox_empty_at(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, token: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.inner().check_portable_outbox_empty_at(c, d, token)
    }
}

impl InactiveImportRepository for AttemptStore<'_> {
    fn begin_import(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        binding: &ImportBinding, accumulator: Digest32,
    ) -> DurableCommitOutcome {
        self.count_commit();
        self.inner().begin_import(c, d, binding, accumulator)
    }
    fn read_import_progress(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
    ) -> Result<Option<ImportProgress>, DurableReadError> {
        self.inner().read_import_progress(c, d)
    }
    fn commit_import_batch(
        &self, c: &DurableOperationContext, d: AtomicityDomainId, batch: &ImportBatch,
    ) -> DurableCommitOutcome {
        self.count_commit();
        self.inner().commit_import_batch(c, d, batch)
    }
    fn finish_import(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        binding: &ImportBinding, progress: &ImportProgress, token: &PortableSnapshotToken,
    ) -> DurableCommitOutcome {
        self.count_commit();
        self.inner().finish_import(c, d, binding, progress, token)
    }
}

impl SuccessorServingRepository for AttemptStore<'_> {
    fn read_namespace_validator(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError> {
        self.inner().read_namespace_validator(c, d)
    }
    fn commit_successor_activation(
        &self, c: &DurableOperationContext, d: AtomicityDomainId,
        binding: &ImportBinding, progress: &ImportProgress, token: &PortableSnapshotToken,
        record: &[u8], tx: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.state().unwrap().reads());
        self.inner().commit_successor_activation(c, d, binding, progress, token, record, tx)
    }
    fn commit_successor_durable(
        &self, c: &DurableOperationContext,
        observation: &SuccessorServingObservation, tx: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.reads());
        self.inner().commit_successor_durable(c, observation, tx)
    }
    fn commit_successor_invocation(
        &self, c: &DurableOperationContext,
        observation: &SuccessorServingObservation, tx: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.state().unwrap().reads());
        self.inner().commit_successor_invocation(c, observation, tx)
    }
    fn commit_successor_seal_retention(
        &self, c: &DurableOperationContext, observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken, tx: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.reads());
        self.inner().commit_successor_seal_retention(c, observation, token, tx)
    }
    fn commit_successor_seal_completion(
        &self, c: &DurableOperationContext, observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken, tx: DurableInvocationTransaction, sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        self.before_commit(tx.state().unwrap().reads());
        self.inner().commit_successor_seal_completion(c, observation, token, tx, sealed)
    }
}

fn resign_envelope(
    origin: &SuccessorWorld,
    owner: &ExitingOwner,
    candidate: &OrderedCandidate,
    intent: BondLifecycleIntent,
) -> OrderedCandidate {
    let digest: Digest32 = crate::bond_lifecycle::bond_lifecycle_intent_digest(
        &origin.network().resolver, &intent,
    ).unwrap();
    let frame: Vec<u8> = crate::bond_lifecycle::bond_lifecycle_signing_frame(
        &candidate.context, digest,
    ).unwrap();
    let mut changed: OrderedCandidate = candidate.clone();
    changed.intent = encode_signed_bond_lifecycle_intent(&SignedBondLifecycleIntent {
        intent,
        signature: owner.signer.key.sign(&frame).into(),
    }).unwrap();
    changed
}

fn with_target(
    origin: &SuccessorWorld,
    hosts: &EpochHosts,
    owner: &ExitingOwner,
    candidate: &OrderedCandidate,
    reference: ObjectRef,
) -> OrderedCandidate {
    let mut envelope: SignedBondLifecycleIntent =
        decode_signed_bond_lifecycle_intent(&candidate.intent).unwrap();
    let BondLifecycleOperation::Withdraw { leg } = &envelope.intent.operation else {
        panic!("the genuine recurrence supplies a Withdraw candidate")
    };
    let mut signed: SignedLocalExecutionIntent =
        execution::local_execution::decode_signed_local_execution(leg).unwrap();
    assert_eq!(signed.intent.call.sender, *owner.signer.id.as_bytes());
    assert_eq!(signed.intent.call.access.entries.len(), 1);
    assert_eq!(signed.intent.call.access.entries[0].mode, AccessMode::Write);
    signed.intent.call.access.entries[0].object_ref = reference;
    let frame: Vec<u8> = local_execution_signing_frame(hosts.policy.context(), &signed.intent)
        .unwrap();
    signed.signature = owner.signer.key.sign(&frame).into();
    envelope.intent.operation = BondLifecycleOperation::Withdraw {
        leg: encode_signed_local_execution(&signed).unwrap(),
    };
    resign_envelope(origin, owner, candidate, envelope.intent)
}

fn with_split_target(
    origin: &SuccessorWorld,
    hosts: &EpochHosts,
    owner: &ExitingOwner,
    candidate: &OrderedCandidate,
    resource: &crate::economics::FastPathEconomicsResourcePolicy,
) -> OrderedCandidate {
    let mut envelope: SignedBondLifecycleIntent =
        decode_signed_bond_lifecycle_intent(&candidate.intent).unwrap();
    let BondLifecycleOperation::Withdraw { leg } = &envelope.intent.operation else {
        panic!("the genuine recurrence supplies a Withdraw candidate")
    };
    let mut signed: SignedLocalExecutionIntent =
        execution::local_execution::decode_signed_local_execution(leg).unwrap();
    let call: &mut CallIntent = &mut signed.intent.call;
    assert_eq!(call.context, *hosts.policy.context());
    assert_eq!(call.sender, *owner.signer.id.as_bytes());
    assert_eq!(call.access.entries.len(), 1);
    assert_eq!(call.access.entries[0].mode, AccessMode::Write);
    assert_eq!(call.access.entries[0].object_ref, owner.unbonded.custody_object);
    assert_eq!(call.code, resource.code);
    assert_eq!(call.instance, resource.instance);
    assert_eq!(call.entrypoint, resource.transfer_entrypoint);
    assert_eq!(resource.split_entrypoint, "split");
    assert_ne!(resource.split_entrypoint, resource.transfer_entrypoint);
    let split_amount: u64 = 1;
    assert!(split_amount > 0 && split_amount < owner.unbonded.amount);
    call.entrypoint = resource.split_entrypoint.clone();
    call.arguments = public_standard_asset::split_arguments(
        split_amount, owner.signer.id.as_bytes(),
    ).unwrap();
    let frame: Vec<u8> = local_execution_signing_frame(hosts.policy.context(), &signed.intent)
        .unwrap();
    signed.signature = owner.signer.key.sign(&frame).into();
    envelope.intent.operation = BondLifecycleOperation::Withdraw {
        leg: encode_signed_local_execution(&signed).unwrap(),
    };
    resign_envelope(origin, owner, candidate, envelope.intent)
}

/// The existing public consensus engine signs a Byzantine leader's exact
/// carrier without retaining any producer or candidate row on the fixture.
fn raw_proposal(
    origin: &SuccessorWorld,
    hosts: &EpochHosts,
    candidate: &OrderedCandidate,
    leader: usize,
) -> OrderedProposal {
    let key: Vec<u8> = scoped_key(
        hosts.policy.key_scope(), hosts.policy.context().chain_id(), OrderedKeyFamily::State,
    ).unwrap();
    let state: consensus::ConsensusState = consensus::decode_consensus_state(
        &hosts.value(origin, leader, &key).1.unwrap(),
    ).unwrap();
    OrderedProposal {
        proposal: hosts.policy.engine().propose(
            &state,
            vec![hosts.policy.candidate_digest(candidate).unwrap()],
            &origin.members[leader],
        ).unwrap(),
        candidate: Some(candidate.clone()),
    }
}

fn attempted_signing(
    store: &AttemptStore<'_>,
    archive: &CompleteArchive,
    candidate: &OrderedCandidate,
    proposal: &OrderedProposal,
    vote: bool,
    signer: &NoSignature<'_>,
) -> Result<(), OrderedEconomicsError> {
    let template: OrderedEconomicsEnvironment<'_> = store.hosts.env(store.origin);
    let env: OrderedEconomicsEnvironment<'_> = store.hosts.env_for_host(&template, store.index);
    let warrant: LiveWarrant<'_> = store.warrant(archive);
    store.arm();
    if vote {
        process_proposal_successor(&warrant, store, &env, proposal, signer).map(|_| ())
    } else {
        propose_successor(&warrant, store, &env, Some(candidate), signer).map(|_| ())
    }
}

pub(super) fn assert_registered_withdraw_admission(
    origin: &SuccessorWorld,
    archive: &CompleteArchive,
    hosts: &EpochHosts,
    owner: &ExitingOwner,
    candidate: &OrderedCandidate,
) {
    assert!(hosts.policy.is_causal());
    assert_eq!(owner.signer.id, successor_chain::never_member_g().id);
    assert_eq!(owner.delay, 7);
    assert_eq!(hosts.policy.context().epoch(), owner.unlock);
    assert!(hosts.policy.registered_validator(owner.signer.id).is_none());
    assert_eq!(hosts.bond(origin, 0, owner.signer.id).0, owner.unbonded);
    assert!(owner.unbonded.custody_object_epoch < hosts.policy.context().epoch());
    let authority: VerifiedSuccessorAuthority = archive.verify(origin);
    assert!(matches!(
        authority.owners().owner(owner.signer.id).unwrap().provenance(),
        OwnerProvenance::Registration { anchor_epoch, .. }
            if *anchor_epoch == owner.unbonded.lifecycle_epoch
    ));
    for epoch in origin.network().root.genesis_context().epoch().get()
        ..=hosts.policy.context().epoch().get()
    {
        assert!(authority.committees().get(Epoch::new(epoch)).unwrap().0
            .get(owner.signer.id).is_none());
    }
    let status: OrderedStatus = hosts.status(origin, archive);
    let leader_id: ValidatorId = hosts.policy.engine().validator_set()
        .leader(status.current_view).unwrap();
    let leader: usize = origin.members.iter()
        .position(|member: &TestSigner| member.id == leader_id).unwrap();
    let voter: usize = (leader + 1) % hosts.targets.len();
    let economics_key: Vec<u8> =
        crate::local_instance_state::fastpath_economics_policy_key(&owner.unbonded.context)
            .unwrap();
    assert_ne!(
        economics_key,
        crate::local_instance_state::fastpath_economics_policy_key(hosts.policy.context())
            .unwrap(),
        "the release policy is loaded from the original resource scope"
    );
    let economics: crate::economics::FastPathEconomicsPolicy =
        crate::economics::decode_fastpath_economics_policy(
            &hosts.value(origin, 0, &economics_key).1.unwrap(),
        ).unwrap();
    assert_eq!(economics.context, owner.unbonded.context);
    let resource_id: BondResourceId = BondResourceId::new(
        owner.unbonded.resource_domain, owner.unbonded.resource,
    ).unwrap();
    let resource_index: usize = economics.resources.binary_search_by_key(
        &resource_id,
        |entry: &crate::economics::FastPathEconomicsResourcePolicy| entry.resource_id,
    ).unwrap();
    let resource: &crate::economics::FastPathEconomicsResourcePolicy =
        &economics.resources[resource_index];
    let original: &ObjectRef = &owner.unbonded.custody_object;
    let mut wrong_id: ObjectRef = original.clone();
    wrong_id.id = ObjectId::new([0x24; 32]);
    let mut wrong_version: ObjectRef = original.clone();
    wrong_version.version = wrong_version.version.checked_add(1).unwrap();
    let mut wrong_digest: ObjectRef = original.clone();
    wrong_digest.digest = Digest32::new(original.digest.algorithm(), [0xa7; 32]);
    let mut wrong_algorithm: ObjectRef = original.clone();
    wrong_algorithm.digest = Digest32::new(
        if original.digest.algorithm() == HashAlgorithmId::Sha3_256 {
            HashAlgorithmId::Sha2_256
        } else {
            HashAlgorithmId::Sha3_256
        },
        *original.digest.bytes(),
    );
    let wrong: Vec<ObjectRef> = vec![wrong_id, wrong_version, wrong_digest, wrong_algorithm];
    for reference in wrong {
        assert_ne!(&reference, original);
        let changed: OrderedCandidate = with_target(origin, hosts, owner, candidate, reference);
        hosts.policy.authenticate_candidate(&changed).unwrap();
        let proposal: OrderedProposal = raw_proposal(origin, hosts, &changed, leader);
        for (vote, index) in [(false, leader), (true, voter)] {
            let store: AttemptStore<'_> = AttemptStore::new(origin, hosts, index, None);
            let signer: NoSignature<'_> = NoSignature {
                member: &origin.members[index], count: Cell::new(0),
            };
            let before: SourceBusinessSnapshot = hosts.capture(origin, index);
            let error: OrderedEconomicsError = attempted_signing(
                &store, archive, &changed, &proposal, vote, &signer,
            ).unwrap_err();
            assert!(matches!(error, OrderedEconomicsError::Prerequisite(
                "fresh bond withdrawal input is not the exact committed custody reference"
            )));
            assert_eq!(signer.count.get(), 0, "the real fresh signer is never invoked");
            assert_eq!(store.commits.get(), 0, "no durable mutation port is invoked");
            assert_eq!(store.object_reads.get(), 0, "custody is neither loaded nor granted");
            assert_eq!(hosts.capture(origin, index), before, "complete durable state is unchanged");
        }
    }

    // The published split has the same one-Write Coin ABI as transfer. Keep
    // the exact custody reference and actual installed code/instance while
    // replacing only the entrypoint and its canonical positive arguments.
    let split: OrderedCandidate = with_split_target(origin, hosts, owner, candidate, resource);
    hosts.policy.authenticate_candidate(&split).unwrap();
    let split_proposal: OrderedProposal = raw_proposal(origin, hosts, &split, leader);
    for (vote, index) in [(false, leader), (true, voter)] {
        let store: AttemptStore<'_> = AttemptStore::new(origin, hosts, index, None);
        let signer: NoSignature<'_> = NoSignature {
            member: &origin.members[index], count: Cell::new(0),
        };
        let before: SourceBusinessSnapshot = hosts.capture(origin, index);
        let error: OrderedEconomicsError = attempted_signing(
            &store, archive, &split, &split_proposal, vote, &signer,
        ).unwrap_err();
        assert!(matches!(error, OrderedEconomicsError::Prerequisite(
            "fresh bond withdrawal leg is not the committed resource release target"
        )));
        assert_eq!(signer.count.get(), 0, "the real fresh signer is never invoked for split");
        assert_eq!(store.commits.get(), 0, "split installs no durable admission rows");
        assert_eq!(store.object_reads.get(), 0, "split never loads or grants custody");
        assert_eq!(hosts.capture(origin, index), before, "split leaves complete state unchanged");
    }

    // Wrong custody does not supersede a healthy stale signed predecessor.
    // Both helpers read the real current G row; no fixture row is rewritten.
    let mut wrong: ObjectRef = original.clone();
    wrong.id = ObjectId::new([0x24; 32]);
    let changed: OrderedCandidate = with_target(origin, hosts, owner, candidate, wrong);
    let env: OrderedEconomicsEnvironment<'_> = hosts.env(origin);
    for generation in [true, false] {
        let mut signed: SignedBondLifecycleIntent =
            decode_signed_bond_lifecycle_intent(&changed.intent).unwrap();
        let expected: OrderedRefusal = if generation {
            signed.intent.expected_generation = signed.intent.expected_generation.checked_add(1)
                .unwrap();
            OrderedRefusal::StaleGeneration
        } else {
            signed.intent.expected_previous_row_digest = Digest32::new(
                signed.intent.expected_previous_row_digest.algorithm(), [0xb8; 32],
            );
            OrderedRefusal::StalePreviousRow
        };
        let stale: OrderedCandidate = resign_envelope(origin, owner, &changed, signed.intent);
        hosts.policy.authenticate_candidate(&stale).unwrap();
        let before: SourceBusinessSnapshot = hosts.capture(origin, 0);
        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        crate::ordered_economics::preflight::require_fresh_bond_withdraw_target(
            &hosts.targets[0].0, &hosts.operation, &env, &stale, &mut reads,
        ).unwrap();
        assert!(matches!(crate::ordered_economics::preflight::preflight(
            &hosts.targets[0].0, &hosts.operation, &env, &stale,
            status.high_qc.height.checked_add(1).unwrap(),
        ), Err(OrderedEconomicsError::Refused(refusal)) if refusal == expected));
        assert_eq!(hosts.capture(origin, 0), before);
    }

    // A real deciding-row revision race can occur after one private signature.
    // The failed CAS exposes no proposal/vote and installs no admission rows.
    let keys: Vec<Vec<u8>> = vec![
        fastpath_epoch_record_key(hosts.policy.context().chain_id()).unwrap(),
        crate::local_instance_state::fastpath_validator_set_key(hosts.policy.context()).unwrap(),
        fastpath_bond_record_key(hosts.policy.context().chain_id(), &owner.signer.id).unwrap(),
        economics_key,
    ];
    let proposal: OrderedProposal = raw_proposal(origin, hosts, candidate, leader);
    for key in keys {
        for (vote, index) in [(false, leader), (true, voter)] {
            let revision: StateRevision = hosts.value(origin, index, &key).0;
            let store: AttemptStore<'_> = AttemptStore::new(
                origin, hosts, index, Some((RaceAt::Commit, key.clone())),
            );
            let signer: NoSignature<'_> = NoSignature {
                member: &origin.members[index], count: Cell::new(0),
            };
            let error: OrderedEconomicsError = attempted_signing(
                &store, archive, candidate, &proposal, vote, &signer,
            ).unwrap_err();
            assert!(matches!(error, OrderedEconomicsError::Node(
                NodeCoreError::DurableCommitRejected(_)
            )));
            assert_eq!(signer.count.get(), 1, "private signing can precede CAS refusal");
            assert_eq!(store.commits.get(), 1, "the attempted real admission commit is rejected");
            assert!(store.raced.get());
            assert!(store.committed_reads.borrow().iter().any(|read: &StateReadAssertion|
                read.key() == key.as_slice() && read.expected_revision() == revision));
            assert_eq!(&hosts.capture(origin, index), store.after_race.borrow().as_ref().unwrap());
        }
    }

    // Writer-free scope control, separate from the public signer-path cases
    // above: a repeated committee observation poisons the same view that the
    // withdrawal gate consumes, even if its helper maps the read to a stop.
    let committee_key: Vec<u8> =
        crate::local_instance_state::fastpath_validator_set_key(hosts.policy.context()).unwrap();
    let store: AttemptStore<'_> = AttemptStore::new(
        origin, hosts, 0, Some((RaceAt::SecondRead, committee_key.clone())),
    );
    store.arm();
    let observed: ObservedBusinessReadView<'_, AttemptStore<'_>> =
        ObservedBusinessReadView::new(&store, origin.network().domain());
    let initial: VersionedStateValue = observed.read_versioned_state(
        &hosts.operation, origin.network().domain(), &committee_key,
    ).unwrap();
    assert!(initial.value().is_some());
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let result: Result<(), OrderedEconomicsError> =
        crate::ordered_economics::preflight::require_fresh_bond_withdraw_target(
            &observed, &hosts.operation, &env, &changed, &mut reads,
        );
    assert!(matches!(&result, Err(OrderedEconomicsError::Prerequisite(
        "fresh bond withdrawal live validator set is unavailable"
    ))));
    let finished: Result<(StateObservationSet, ()), OrderedEconomicsError> =
        observed.finish_with(result);
    assert!(matches!(finished, Err(OrderedEconomicsError::Node(NodeCoreError::StateConflict))));
    assert!(store.raced.get());
    assert_eq!(store.commits.get(), 0);
    assert_eq!(&hosts.capture(origin, 0), store.after_race.borrow().as_ref().unwrap());
}
