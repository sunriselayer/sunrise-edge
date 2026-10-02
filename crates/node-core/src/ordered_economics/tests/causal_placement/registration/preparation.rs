//! Genuine preparation from certified Owned funding and actual ordered
//! admission. No source application rows or positive authorities are seeded.

use super::*;
use crate::business_reconstruction::SourceBusinessSnapshot;
use crate::operation_preparation::InvocationPreparation;
use crate::ordered_economics::observed_read::ObservedBusinessReadView;
use crate::ordered_economics::reservation::{OrderedLegAdmission, load_reservation};
use crate::test_support::capture::assert_same_records_and_blobs;
use crate::test_support::counted_blobs::CountedBlobs;
use crate::test_support::reader_view::WriterFreeView;
use execution::local_execution::{
    LocalContractEngine, LocalExecutionError, LocalExecutionOutcome, LocalExecutionRequest,
};
use runtime::{
    DurableInvocationTransaction, DurableObjectMutation, MemoryDurableStateStore, StateMutation,
    StateObservationSet, StructuredDurableDomainStateStore,
};

struct CountingRegistrationEngine {
    inner: LocalWasmExecutionEngine,
    calls: Cell<usize>,
}

impl CountingRegistrationEngine {
    fn new() -> Self {
        Self {
            inner: LocalWasmExecutionEngine::new(),
            calls: Cell::new(0),
        }
    }
}

impl LocalContractEngine for CountingRegistrationEngine {
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.execute(request)
    }
}

#[test]
fn ordered_writer_free_registration_preparation_preserves_real_execution_bytes() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let _producer: CertifiedPaidMaterial = fund_e(&fixture, 0);
    let (candidate, expected): (OrderedCandidate, FastPathBondRecord) =
        registration(&fixture, REGISTER, 0);
    // Real proposal and four votes retain the precise source/nonce locks. The
    // first operation is not committed until its two empty descendants arrive.
    network.round(1, Some(&candidate));
    assert!(receipt(network, 0, REGISTER).is_none());
    let (reservation, _, _) = load_reservation(
        &network.stores[0],
        &network.context,
        &network.env(),
        &REGISTER,
    )
    .unwrap()
    .unwrap();
    let admission: OrderedLegAdmission<'_> = OrderedLegAdmission {
        request_id: REGISTER,
        objects: &reservation.objects,
        nonce: reservation.nonce,
    };
    let before: SourceBusinessSnapshot = snapshot(network);
    let blobs: CountedBlobs<'_> = CountedBlobs::new(&network.blobs);
    let engine: CountingRegistrationEngine = CountingRegistrationEngine::new();
    let mut environment: OrderedEconomicsEnvironment<'_> = network.env();
    environment.blobs = &blobs;
    environment.engine = &engine;
    let observed: ObservedBusinessReadView<'_, MemoryDurableStateStore> =
        ObservedBusinessReadView::new(&network.stores[0], network.domain());
    let attempt: Result<
        InvocationPreparation,
        crate::bond_lifecycle::registration::BondRegistrationError,
    > = crate::bond_lifecycle::registration::prepare_bond_registration_ordered(
        &observed,
        &network.context,
        &environment,
        &candidate,
        Some(&admission),
    );
    let observations: StateObservationSet = observed.finish().unwrap();
    let prepared: InvocationPreparation = attempt.unwrap();
    assert_eq!(engine.calls.get(), 1);
    assert!(!observations.into_read_set().unwrap().reads().is_empty());
    assert_eq!(
        blobs.put_count(),
        0,
        "preparation cannot publish immutable bodies"
    );
    assert_eq!(
        snapshot(network),
        before,
        "all four collections and source token remain unchanged"
    );
    assert!(receipt(network, 0, REGISTER).is_none());
    let InvocationPreparation::Prepared(prepared) = prepared else {
        panic!("the genuinely admitted original is not a retained replay");
    };
    let (transaction, output): (DurableInvocationTransaction, NodeOutput) = prepared.into_parts();

    network.round(2, None);
    network.round(3, None);
    assert_registered(&fixture, &expected);
    let original: DurableRequestReceipt = receipt(network, 0, REGISTER).unwrap();
    assert_eq!(transaction.receipt(), &original);
    assert_eq!(
        query_ordered_outcome(
            &network.stores[0],
            &network.context,
            &network.env(),
            &REGISTER
        )
        .unwrap()
        .unwrap()
        .output,
        output
    );
    for mutation in transaction.state().unwrap().mutations() {
        match mutation.mutation() {
            StateMutation::Put(bytes) => assert_eq!(
                network.value(0, mutation.key()).as_deref(),
                Some(bytes.as_slice())
            ),
            StateMutation::Delete => assert!(network.value(0, mutation.key()).is_none()),
            StateMutation::Assert => panic!("a prepared mutation cannot be an assertion"),
        }
    }
    for mutation in transaction.object_changes().mutations() {
        let version = match mutation.mutation() {
            DurableObjectMutation::Create { version, .. }
            | DurableObjectMutation::Update { version, .. } => version,
            DurableObjectMutation::Delete => {
                panic!("registration transfers existing custody, never deletes it")
            }
        };
        assert_eq!(
            network.stores[0]
                .get_object_version(
                    &network.context,
                    network.domain(),
                    mutation.object_id(),
                    version.object_version()
                )
                .unwrap()
                .as_ref(),
            Some(version)
        );
    }
    // The independent causal scheduler invokes the same owner preparation,
    // derives the original effects and compares all source business semantics.
    let (identity, history) = complete_history(network);
    let source: SourceBusinessSnapshot = snapshot(network);
    let plan = reconstruction_plan(&fixture, &identity);
    let owned = owned_material_from_source_snapshot(&source, &plan).unwrap();
    let mut overlay = BusinessReconstructionOverlay::new(plan).unwrap();
    overlay.reconstruct(&owned, &history).unwrap();
    overlay.compare_source(&source).unwrap();
    assert_eq!(receipt(network, 0, REGISTER).unwrap(), original);
    let reader: WriterFreeView<'_, MemoryDurableStateStore> =
        WriterFreeView::new(&network.stores[0]);
    let replay: InvocationPreparation =
        crate::bond_lifecycle::registration::prepare_bond_registration_ordered(
            &reader,
            &network.context,
            &environment,
            &candidate,
            None,
        )
        .unwrap();
    match replay {
        InvocationPreparation::Retained(replayed) => assert_eq!(replayed, output),
        InvocationPreparation::Prepared(_) => panic!("exact replay cannot create a proposal"),
    }
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(blobs.put_count(), 0);
    assert_eq!(snapshot(network), source);
}

#[test]
fn writer_free_registration_commit_matches_direct_with_identical_real_admission() {
    let fixture: CausalFixture = fresh_fixture();
    let direct_fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let direct_network: &Network = &direct_fixture.network;
    let producer: CertifiedPaidMaterial = fund_e(&fixture, 0);
    let direct_producer: CertifiedPaidMaterial = fund_e(&direct_fixture, 0);
    assert_eq!(producer.result, direct_producer.result);
    let (candidate, expected): (OrderedCandidate, FastPathBondRecord) =
        registration(&fixture, REGISTER, 0);
    let (direct_candidate, direct_expected): (OrderedCandidate, FastPathBondRecord) =
        registration(&direct_fixture, REGISTER, 0);
    assert_eq!(candidate, direct_candidate);
    assert_eq!(expected, direct_expected);
    // Both networks execute the same real funding and proposal/vote round,
    // including replica zero's identical local signer and retained history.
    network.round(1, Some(&candidate));
    direct_network.round(1, Some(&direct_candidate));
    let before: SourceBusinessSnapshot = snapshot(network);
    let direct_before: SourceBusinessSnapshot = snapshot(direct_network);
    assert_same_records_and_blobs(&before, &direct_before);
    assert!(receipt(network, 0, REGISTER).is_none());
    assert!(receipt(direct_network, 0, REGISTER).is_none());
    let (reservation, _, _) = load_reservation(
        &network.stores[0],
        &network.context,
        &network.env(),
        &REGISTER,
    )
    .unwrap()
    .unwrap();
    let (direct_reservation, _, _) = load_reservation(
        &direct_network.stores[0],
        &direct_network.context,
        &direct_network.env(),
        &REGISTER,
    )
    .unwrap()
    .unwrap();
    let admission: OrderedLegAdmission<'_> = OrderedLegAdmission {
        request_id: REGISTER,
        objects: &reservation.objects,
        nonce: reservation.nonce,
    };
    let direct_admission: OrderedLegAdmission<'_> = OrderedLegAdmission {
        request_id: REGISTER,
        objects: &direct_reservation.objects,
        nonce: direct_reservation.nonce,
    };
    let blobs: CountedBlobs<'_> = CountedBlobs::new(&network.blobs);
    let direct_blobs: CountedBlobs<'_> = CountedBlobs::new(&direct_network.blobs);
    let engine: CountingRegistrationEngine = CountingRegistrationEngine::new();
    let direct_engine: CountingRegistrationEngine = CountingRegistrationEngine::new();
    let mut environment: OrderedEconomicsEnvironment<'_> = network.env();
    environment.blobs = &blobs;
    environment.engine = &engine;
    let mut direct_environment: OrderedEconomicsEnvironment<'_> = direct_network.env();
    direct_environment.blobs = &direct_blobs;
    direct_environment.engine = &direct_engine;
    let reader: WriterFreeView<'_, MemoryDurableStateStore> =
        WriterFreeView::new(&network.stores[0]);
    let prepared: InvocationPreparation =
        crate::bond_lifecycle::registration::prepare_bond_registration_ordered(
            &reader,
            &network.context,
            &environment,
            &candidate,
            Some(&admission),
        )
        .unwrap();
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(blobs.put_count(), 0);
    assert_eq!(snapshot(network), before);
    let InvocationPreparation::Prepared(prepared) = prepared else {
        panic!("the genuinely admitted original is not a retained replay");
    };
    let (transaction, output): (DurableInvocationTransaction, NodeOutput) = prepared.into_parts();
    let original: DurableRequestReceipt = transaction.receipt().clone();
    let committed: NodeOutput =
        crate::operation_preparation::PreparedBusinessInvocation::new(transaction, output)
            .unwrap()
            .commit(&network.stores[0], &network.context)
            .unwrap();
    let direct: NodeOutput = crate::bond_lifecycle::registration::handle_bond_registration_ordered(
        &direct_network.stores[0],
        &direct_network.context,
        &direct_environment,
        &direct_candidate,
        Some(&direct_admission),
    )
    .unwrap();
    assert_eq!(direct_engine.calls.get(), 1);
    assert_eq!(committed, direct);
    for owning_network in [network, direct_network] {
        assert_eq!(receipt(owning_network, 0, REGISTER).unwrap(), original);
        assert_eq!(
            verify_registered_bond_chain(
                &owning_network.stores[0],
                &owning_network.context,
                owning_network.domain(),
                &owning_network.root,
                &owning_network.history,
                e_id(),
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            query_sender_next_nonce(
                &owning_network.stores[0],
                &owning_network.context,
                owning_network.domain(),
                fixture::chain(),
                fixture::protocol().protocol_version(),
                fixture::protocol().epoch(),
                *e_id().as_bytes(),
            )
            .unwrap(),
            1
        );
    }
    let completed: SourceBusinessSnapshot = snapshot(network);
    let direct_completed: SourceBusinessSnapshot = snapshot(direct_network);
    assert_same_records_and_blobs(&completed, &direct_completed);
    let replay: InvocationPreparation =
        crate::bond_lifecycle::registration::prepare_bond_registration_ordered(
            &reader,
            &network.context,
            &environment,
            &candidate,
            None,
        )
        .unwrap();
    match replay {
        InvocationPreparation::Retained(replayed) => assert_eq!(replayed, committed),
        InvocationPreparation::Prepared(_) => panic!("exact replay cannot create a proposal"),
    }
    assert_eq!(
        crate::bond_lifecycle::registration::handle_bond_registration_ordered(
            &direct_network.stores[0],
            &direct_network.context,
            &direct_environment,
            &direct_candidate,
            None,
        )
        .unwrap(),
        direct
    );
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(direct_engine.calls.get(), 1);
    assert_eq!(blobs.put_count(), 0);
    assert_eq!(direct_blobs.put_count(), 0);
    assert_eq!(snapshot(network), completed);
    assert_eq!(snapshot(direct_network), direct_completed);
}
