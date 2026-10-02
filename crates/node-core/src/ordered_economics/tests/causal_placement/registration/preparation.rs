//! Genuine preparation from certified Owned funding and actual ordered
//! admission. No source application rows or positive authorities are seeded.

use super::*;
use crate::operation_preparation::InvocationPreparation;
use crate::ordered_economics::observed_read::ObservedBusinessReadView;
use crate::ordered_economics::reservation::{OrderedLegAdmission, load_reservation};
use runtime::{
    BlobStore, DurableInvocationTransaction, DurableObjectMutation, MemoryDurableStateStore,
    RuntimeError, StateMutation, StateObservationSet, StructuredDurableDomainStateStore,
};

struct CountedBlobs<'a> {
    inner: &'a runtime::MemoryBlobStore,
    puts: Cell<usize>,
}

impl BlobStore for CountedBlobs<'_> {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.puts.set(self.puts.get() + 1);
        self.inner.put_blob(digest, bytes)
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.inner.get_blob(digest)
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
    let before = snapshot(network);
    let blobs: CountedBlobs<'_> = CountedBlobs {
        inner: &network.blobs,
        puts: Cell::new(0),
    };
    let mut environment: OrderedEconomicsEnvironment<'_> = network.env();
    environment.blobs = &blobs;
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
    assert!(!observations.into_read_set().unwrap().reads().is_empty());
    assert_eq!(
        blobs.puts.get(),
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
    let source = snapshot(network);
    let plan = reconstruction_plan(&fixture, &identity);
    let owned = owned_material_from_source_snapshot(&source, &plan).unwrap();
    let mut overlay = BusinessReconstructionOverlay::new(plan).unwrap();
    overlay.reconstruct(&owned, &history).unwrap();
    overlay.compare_source(&source).unwrap();
    assert_eq!(receipt(network, 0, REGISTER).unwrap(), original);
}
