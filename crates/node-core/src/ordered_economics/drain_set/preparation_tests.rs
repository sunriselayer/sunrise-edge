//! Control proposal assembly over actual genesis and signed empty-frontier proof.

use super::*;
use crate::genesis::{GenesisManifest, tests as fixture};
use consensus::{
    ConsensusSigner, FrozenFrontierAccumulator, FrozenFrontierCertifier, FrozenFrontierPage,
};
use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{
    DurableDomainStateStore, DurableReadError, MemoryBlobStore, MemoryDurableStateStore,
    VersionedStateReader, WriterFenceGeneration,
};
use validator_set::{ValidatorInfo, ValidatorSet};

struct ControlReader<'a> {
    store: &'a MemoryDurableStateStore,
}

impl VersionedStateReader for ControlReader<'_> {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.store.get_versioned_durable(context, domain, key)
    }
}

struct GenesisSigner;

impl ConsensusSigner for GenesisSigner {
    fn validator_id(&self) -> ValidatorId {
        ValidatorId::new(fixture::sender())
    }

    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }

    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = fixture::key().sign(framed).into();
        Ok(signature.to_vec())
    }
}

#[test]
fn freeze_and_genuine_empty_drain_preparations_have_no_effects() {
    let operation: DurableOperationContext = fixture::context(1);
    let domain: AtomicityDomainId = fixture::domain();
    let resolver: HashSuiteResolver = fixture::resolver();
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let manifest: GenesisManifest = fixture::freeze_bonded_manifest();
    crate::genesis::install_genesis(&store, &operation, domain, &resolver, &manifest, 10).unwrap();
    let validators: ValidatorSet = ValidatorSet::new(
        manifest.validator_set.context.epoch(),
        manifest
            .validator_set
            .validators
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        domain,
        crate::genesis::genesis_manifest_commitment(&resolver, &manifest).unwrap(),
        Some(&manifest),
        validators.clone(),
        resolver.clone(),
    )
    .unwrap();
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture::protocol());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &policy,
        resolver: &resolver,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: &blobs,
    };
    let reader: ControlReader<'_> = ControlReader { store: &store };
    let mut advisory: fast_path::records::FastPathValidatorSetRecord =
        manifest.validator_set.clone();
    advisory.context = PublicationContext::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let freeze_intent: super::super::freeze::FreezeIntent = super::super::freeze::FreezeIntent {
        context: fixture::protocol(),
        request_id: [0x71; 32],
        advisory_next_set: advisory,
    };
    let freeze: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: freeze_intent.request_id,
        kind: OrderedOperationKind::Freeze,
        intent: super::super::freeze::encode_freeze_intent(&freeze_intent).unwrap(),
        created_checkpoint: 11,
    };
    let before_freeze: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain).unwrap();
    let stale: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(2).unwrap(),
        operation.deadline(),
        operation.correlation_id(),
    );
    assert!(matches!(
        super::super::freeze::prepare_freeze_ordered(
            &reader,
            &stale,
            domain,
            &fixture::chain(),
            &freeze,
            1,
        ),
        Err(NodeCoreError::DurableRead(
            DurableReadError::WriterFenced { .. }
        ))
    ));
    super::super::authenticate_candidate(&env, &freeze).unwrap();
    super::super::freeze::require_freeze_warrant(&store, &operation, &env, &freeze, 1).unwrap();
    let prepared_freeze: PreparedStateOperation = super::super::freeze::prepare_freeze_ordered(
        &reader,
        &operation,
        domain,
        &fixture::chain(),
        &freeze,
        1,
    )
    .unwrap();
    let (freeze_transaction, freeze_output): (AtomicStateTransaction, NodeOutput) =
        prepared_freeze.into_parts();
    assert_eq!(freeze_transaction.mutations().len(), 1);
    let freeze_key: Vec<u8> =
        super::super::freeze::admission_closure_key(&fixture::chain(), Epoch::new(0)).unwrap();
    assert_eq!(
        freeze_transaction.reads(),
        &[StateReadAssertion::new(freeze_key.clone(), StateRevision::INITIAL).unwrap(),]
    );
    assert_eq!(
        freeze_transaction.mutations(),
        &[StateMutationEntry::new(
            freeze_key.clone(),
            StateMutation::Put(
                super::super::freeze::encode_admission_closure_record(
                    &super::super::freeze::AdmissionClosureRecord {
                        closed_epoch: Epoch::new(0),
                        request_id: freeze.request_id,
                        closed_at_block_height: 1,
                    },
                )
                .unwrap()
            ),
        )
        .unwrap(),]
    );
    assert!(
        reader
            .read_versioned_state(&operation, domain, &freeze_key)
            .unwrap()
            .value()
            .is_none()
    );
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain).unwrap(),
        before_freeze
    );
    // This owning unit test uses the cfg(test) direct committer, not an
    // invented consensus outcome. Existing ordered tests retain three-chain
    // ordering and atomic original-receipt coverage independently.
    assert_eq!(
        super::super::freeze::handle_freeze_ordered(
            &store,
            &operation,
            domain,
            &fixture::chain(),
            &freeze,
            1,
        )
        .unwrap(),
        freeze_output,
    );
    let after_freeze: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain).unwrap();
    assert_eq!(
        after_freeze.mutation_sequence(),
        before_freeze.mutation_sequence() + 1
    );
    assert!(
        super::super::freeze::prepare_freeze_ordered(
            &reader,
            &operation,
            domain,
            &fixture::chain(),
            &freeze,
            1,
        )
        .is_err()
    );
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain).unwrap(),
        after_freeze
    );

    let frontier: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
        &resolver,
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(0),
        domain,
        freeze.request_id,
        1,
    )
    .unwrap();
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(0),
        validators,
    )
    .unwrap();
    let vote: FrozenFrontierVote = certifier
        .cast_vote(frontier.into_identity(), &GenesisSigner)
        .unwrap();
    drain_union::ingest_drain_signer_page(
        &store,
        &operation,
        domain,
        &resolver,
        &fixture::protocol(),
        vote.validator,
        vote.clone(),
        FrozenFrontierPage {
            after_request_id: None,
            entries: Vec::new(),
            terminal: true,
        },
    )
    .unwrap();
    let selected_votes: Vec<FrozenFrontierVote> = vec![vote];
    let union: DrainUnionIdentity = match drain_union::advance_drain_union(
        &store,
        &operation,
        domain,
        &resolver,
        &[],
        &fixture::protocol(),
        &selected_votes,
    )
    .unwrap()
    {
        drain_union::DrainUnionStep::Ready(identity) => *identity,
        drain_union::DrainUnionStep::Advanced { .. } => panic!("genuine empty union is complete"),
    };
    assert_eq!(union.member_count, 0);
    let drain_intent: DrainSetIntent = DrainSetIntent {
        context: fixture::protocol(),
        request_id: [0x72; 32],
        selected_votes: selected_votes.clone(),
        drain_union_identity: union.clone(),
    };
    let drain: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: drain_intent.request_id,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&drain_intent).unwrap(),
        created_checkpoint: 12,
    };
    let before_drain: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain).unwrap();
    assert!(matches!(
        prepare_drain_set_ordered(&reader, &stale, domain, &fixture::chain(), &drain, 2),
        Err(NodeCoreError::DurableRead(
            DurableReadError::WriterFenced { .. }
        ))
    ));
    super::super::authenticate_candidate(&env, &drain).unwrap();
    preflight_drain_set(&reader, &operation, &env, &drain).unwrap();
    let prepared_drain: PreparedStateOperation =
        prepare_drain_set_ordered(&reader, &operation, domain, &fixture::chain(), &drain, 2)
            .unwrap();
    let (drain_transaction, drain_output): (AtomicStateTransaction, NodeOutput) =
        prepared_drain.into_parts();
    let drain_key: Vec<u8> = drain_set_record_key(&fixture::chain(), Epoch::new(0)).unwrap();
    let record: DrainSetRecord = DrainSetRecord {
        closed_epoch: Epoch::new(0),
        request_id: drain.request_id,
        committed_at_block_height: 2,
        drain_union_identity: union,
        selected_votes,
    };
    assert_eq!(
        drain_transaction.reads(),
        &[StateReadAssertion::new(drain_key.clone(), StateRevision::INITIAL).unwrap(),]
    );
    assert_eq!(
        drain_transaction.mutations(),
        &[StateMutationEntry::new(
            drain_key.clone(),
            StateMutation::Put(encode_drain_set_record(&record).unwrap())
        )
        .unwrap(),]
    );
    assert!(
        reader
            .read_versioned_state(&operation, domain, &drain_key)
            .unwrap()
            .value()
            .is_none()
    );
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain).unwrap(),
        before_drain
    );
    assert_eq!(
        handle_drain_set_ordered(&store, &operation, domain, &fixture::chain(), &drain, 2).unwrap(),
        drain_output,
    );
    assert_eq!(
        read_drain_set_record(
            &reader,
            &operation,
            domain,
            &fixture::chain(),
            Epoch::new(0)
        )
        .unwrap(),
        Some(record)
    );
    let after_drain: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain).unwrap();
    assert_eq!(
        after_drain.mutation_sequence(),
        before_drain.mutation_sequence() + 1
    );
    assert!(
        prepare_drain_set_ordered(&reader, &operation, domain, &fixture::chain(), &drain, 2)
            .is_err()
    );
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain).unwrap(),
        after_drain
    );
}
