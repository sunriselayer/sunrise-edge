//! Genuine genesis/evidence owners drive preparations with no writer port.

use super::*;
use crate::fee_claims::writer_free_preparation_tests::WriterFreeView;
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};

fn prepare_unbond(
    source: &MemoryDurableStateStore,
    signed: &SignedBondLifecycleIntent,
    engine: &CountingEngine,
) -> InvocationPreparation {
    let reader: WriterFreeView<'_, MemoryDurableStateStore> = WriterFreeView::new(source);
    prepare_bond_lifecycle_ordered(
        &reader,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        engine,
        &encode_signed_bond_lifecycle_intent(signed).unwrap(),
        11,
        None,
    )
    .unwrap()
}

fn fresh_unbond(
    source: &MemoryDurableStateStore,
) -> (SignedBondLifecycleIntent, FastPathBondRecord) {
    let bond: FastPathBondRecord = get_bond(source, ValidatorId::new(sender()));
    let recipient: Address = canonical_address(0x50);
    let mut next: FastPathBondRecord = predicted_next(&bond, 11, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let intent: BondLifecycleIntent = base_intent(
        &protocol(),
        [0x61; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    (signed_envelope(intent, &key()), next)
}

#[test]
fn writer_free_lifecycle_prepares_genesis_rooted_transition_and_exact_replay() {
    let manifest: genesis::GenesisManifest = manifest_with_custody(ObjectId::new([0x40; 32]));
    let source: MemoryDurableStateStore = store();
    let direct_store: MemoryDurableStateStore = store();
    install(&source, &manifest);
    install(&direct_store, &manifest);
    let (signed, expected_row) = fresh_unbond(&source);
    let before: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(1), domain())
        .unwrap();
    let engine: CountingEngine = CountingEngine::new();
    let prepared: InvocationPreparation = prepare_unbond(&source, &signed, &engine);
    assert_eq!(engine.call_count(), 0);
    assert_eq!(
        source
            .begin_portable_snapshot(&context(1), domain())
            .unwrap(),
        before
    );
    let proposal: Box<PreparedBusinessInvocation> = match prepared {
        InvocationPreparation::Prepared(proposal) => proposal,
        InvocationPreparation::Retained(_) => panic!("fresh transition cannot be retained"),
    };
    let (transaction, output) = proposal.into_parts();
    let expected_receipt: DurableRequestReceipt = transaction.receipt().clone();
    assert!(
        source
            .get_request_receipt(&context(1), domain(), expected_receipt.request_id())
            .unwrap()
            .is_none()
    );
    let committed: NodeOutput = PreparedBusinessInvocation::new(transaction, output)
        .unwrap()
        .commit(&source, &context(1))
        .unwrap();
    let direct: NodeOutput = call(&direct_store, &signed, &protocol(), &leg_policy(), 11).unwrap();
    assert_eq!(committed, direct);
    assert_eq!(get_bond(&source, expected_row.validator_id), expected_row);
    assert_eq!(
        get_bond(&direct_store, expected_row.validator_id),
        expected_row
    );
    for store in [&source, &direct_store] {
        assert_eq!(
            store
                .get_request_receipt(&context(1), domain(), expected_receipt.request_id())
                .unwrap()
                .unwrap(),
            expected_receipt
        );
        assert!(matches!(
            genesis::install_genesis(store, &context(1), domain(), &resolver(), &manifest, 10)
                .unwrap(),
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }
    let committed_token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(1), domain())
        .unwrap();
    match prepare_unbond(&source, &signed, &engine) {
        InvocationPreparation::Retained(replay) => assert_eq!(replay, committed),
        InvocationPreparation::Prepared(_) => panic!("exact replay cannot create a proposal"),
    }
    assert_eq!(engine.call_count(), 0);
    assert_eq!(
        source
            .begin_portable_snapshot(&context(1), domain())
            .unwrap(),
        committed_token
    );
}

#[test]
fn writer_free_lifecycle_proposal_requires_actual_unchanged_cas_then_valid_progress() {
    let manifest: genesis::GenesisManifest = manifest_with_custody(ObjectId::new([0x40; 32]));
    let source: MemoryDurableStateStore = store();
    install(&source, &manifest);
    let (signed, expected_row) = fresh_unbond(&source);
    let engine: CountingEngine = CountingEngine::new();
    let prepared: InvocationPreparation = prepare_unbond(&source, &signed, &engine);
    // Genuine competing storage action advances the deciding bond revision,
    // without inventing another business result. A proposal is not a commit.
    let previous_row: FastPathBondRecord = get_bond(&source, expected_row.validator_id);
    put_bond(&source, &previous_row);
    let after_competing_write: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(1), domain())
        .unwrap();
    let result: Result<NodeOutput, NodeCoreError> = prepared.commit(&source, &context(1));
    assert!(matches!(result, Err(NodeCoreError::StateConflict)));
    assert_eq!(get_bond(&source, expected_row.validator_id), previous_row);
    assert_eq!(
        source
            .begin_portable_snapshot(&context(1), domain())
            .unwrap(),
        after_competing_write
    );
    assert!(
        source
            .get_request_receipt(
                &context(1),
                domain(),
                DurableRequestId::new(signed.intent.request_id).unwrap()
            )
            .unwrap()
            .is_none()
    );
    let actual: NodeOutput = call(&source, &signed, &protocol(), &leg_policy(), 11).unwrap();
    assert_eq!(get_bond(&source, expected_row.validator_id), expected_row);
    assert_eq!(
        call(&source, &signed, &protocol(), &leg_policy(), 11).unwrap(),
        actual
    );
    assert_eq!(engine.call_count(), 0);
}

#[test]
fn writer_free_slash_prepares_real_evidence_and_wasm_then_commits_exact_bytes() {
    let object_id: ObjectId = ObjectId::new([0xb0; 32]);
    let manifest: genesis::GenesisManifest = manifest_with_custody(object_id);
    let source: MemoryDurableStateStore = store();
    let direct_store: MemoryDurableStateStore = store();
    install(&source, &manifest);
    install(&direct_store, &manifest);
    let (evidence, conflict_digest) = record_class_a_evidence(&source, 15);
    let (direct_evidence, direct_conflict) = record_class_a_evidence(&direct_store, 15);
    assert_eq!(evidence, direct_evidence);
    assert_eq!(conflict_digest, direct_conflict);
    let bond: FastPathBondRecord = get_bond(&source, ValidatorId::new(sender()));
    let fixture: Fixture = build_fixture();
    let custody_object: Object = custody_object_entry(&manifest, object_id, chain()).object;
    let (intent, expected_object, _) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        [0xb1; 32],
    );
    let bytes: Vec<u8> = slash::encode_slash_intent(&intent).unwrap();
    let before: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(1), domain())
        .unwrap();
    let engine: CountingEngine = CountingEngine::new();
    let reader: WriterFreeView<'_, MemoryDurableStateStore> = WriterFreeView::new(&source);
    let prepared: InvocationPreparation = slash::prepare_bond_slash_ordered(
        &reader,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine,
        &bytes,
        20,
        None,
    )
    .unwrap();
    assert_eq!(engine.call_count(), 1);
    assert_eq!(
        source
            .begin_portable_snapshot(&context(1), domain())
            .unwrap(),
        before
    );
    let proposal: Box<PreparedBusinessInvocation> = match prepared {
        InvocationPreparation::Prepared(proposal) => proposal,
        InvocationPreparation::Retained(_) => panic!("fresh slash cannot be retained"),
    };
    let (transaction, output) = proposal.into_parts();
    let expected_receipt: DurableRequestReceipt = transaction.receipt().clone();
    assert!(
        source
            .get_request_receipt(&context(1), domain(), expected_receipt.request_id())
            .unwrap()
            .is_none()
    );
    let committed: NodeOutput = PreparedBusinessInvocation::new(transaction, output)
        .unwrap()
        .commit(&source, &context(1))
        .unwrap();
    let direct: NodeOutput = slash::handle_bond_slash(
        &direct_store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine,
        &bytes,
        20,
    )
    .unwrap();
    assert_eq!(engine.call_count(), 2);
    assert_eq!(committed, direct);
    assert_eq!(
        get_bond(&source, bond.validator_id),
        get_bond(&direct_store, bond.validator_id)
    );
    for store in [&source, &direct_store] {
        assert_eq!(
            store
                .get_request_receipt(&context(1), domain(), expected_receipt.request_id())
                .unwrap()
                .unwrap(),
            expected_receipt
        );
        let expected_reference: ObjectRef = object_ref(&resolver(), &expected_object);
        assert!(matches!(
            store.get_object_head(&context(1), domain(), expected_object.id).unwrap(),
            DurableObjectHead::Current { object_version, digest, .. }
                if object_version.get() == expected_reference.version
                    && digest == expected_reference.digest
        ));
        assert!(matches!(
            genesis::install_genesis(store, &context(1), domain(), &resolver(), &manifest, 10)
                .unwrap(),
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }
    let committed_token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(1), domain())
        .unwrap();
    let replay: InvocationPreparation = slash::prepare_bond_slash_ordered(
        &reader,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine,
        &bytes,
        20,
        None,
    )
    .unwrap();
    match replay {
        InvocationPreparation::Retained(output) => assert_eq!(output, committed),
        InvocationPreparation::Prepared(_) => panic!("exact replay cannot create a proposal"),
    }
    assert_eq!(engine.call_count(), 2);
    assert_eq!(
        source
            .begin_portable_snapshot(&context(1), domain())
            .unwrap(),
        committed_token
    );
}
