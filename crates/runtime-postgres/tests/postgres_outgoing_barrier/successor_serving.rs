//! Mandatory slot reads are raw metadata, not PostgreSQL serving capability.
//! Reuse this binary's actual live namespace/pool/lock helpers.
use super::*;
use protocol_types::{ExecutionGeneration, ProtocolVersion};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitRejection,
    ImportBinding, ImportContext, ImportProgress, StateMutation, StateMutationEntry,
    StateReadAssertion, StateRevision, SuccessorServingObservation, SuccessorServingRecord,
    SuccessorServingSlot,
};

fn transaction(domain: AtomicityDomainId) -> AtomicStateTransaction {
    AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"never-written".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"never-written".to_vec(), StateMutation::Put(vec![1]))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn set_slot(admin: &mut postgres::Client, namespace: &PostgresNamespace, bytes: &[u8]) {
    admin
        .execute(
            "UPDATE sunrise_edge.successor_serving SET serving = $1
         WHERE chain_id_bytes = $2 AND validator_id = $3 AND atomicity_domain_id = $4",
            &[
                &bytes,
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap();
}

#[test]
fn postgres_successor_slot_is_mandatory_but_never_enables_an_activation_repository() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().unwrap();
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = connect_admin(&url);
    let namespace: PostgresNamespace = fresh_namespace("successor-unsupported", 0xd1, 0xd2);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let operation: DurableOperationContext = context(fence);
    assert_eq!(
        current
            .get_successor_serving(&operation, namespace.domain())
            .unwrap(),
        SuccessorServingSlot::Inactive
    );
    assert!(current.successor_serving_repository().is_none());
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xd3; 32]);
    // A structurally valid forged record is only raw at-rest corruption.
    // Even it cannot opt this ordinary-only adapter into serving writes.
    let binding: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new(std::str::from_utf8(namespace.chain_id_bytes()).unwrap())
                .unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(2),
        },
        domain: namespace.domain(),
        genesis_digest: digest,
        validator_set_digest: digest,
        cut_digest: digest,
        package_digest: digest,
        plan_digest: digest,
        row_count: 0,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(1),
    };
    let progress: ImportProgress = ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: digest,
    };
    let record: SuccessorServingRecord = SuccessorServingRecord {
        subject: digest,
        manifest: digest,
        binding: binding.clone(),
        progress: progress.clone(),
        activation_token: runtime::portable::PortableSnapshotToken::new(
            b"synthetic".to_vec(),
            namespace.domain(),
            fence,
            0,
        )
        .unwrap(),
        anchor: digest,
        validator: namespace.validator_id(),
        public_key: [0xd4; 32],
    };
    let slot: SuccessorServingSlot =
        SuccessorServingSlot::Serving(Box::new(SuccessorServingObservation {
            record: runtime::encode_successor_serving_record(&record).unwrap(),
            binding,
            progress,
        }));
    set_slot(
        &mut admin,
        &namespace,
        &runtime::encode_successor_serving_slot(&slot).unwrap(),
    );
    assert_eq!(
        current
            .get_successor_serving(&operation, namespace.domain())
            .unwrap(),
        slot
    );
    assert!(current.successor_serving_repository().is_none());
    assert_eq!(
        current.commit_durable(&operation, transaction(namespace.domain())),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    assert_eq!(
        current
            .get_versioned_durable(&operation, namespace.domain(), b"never-written")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
}

#[test]
fn postgres_successor_slot_corruption_or_absence_fails_closed_without_repair() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().unwrap();
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = connect_admin(&url);
    let inactive: Vec<u8> =
        runtime::encode_successor_serving_slot(&SuccessorServingSlot::Inactive).unwrap();
    let mut unknown: Vec<u8> = inactive.clone();
    unknown[16] = 3;
    let mut length: Vec<u8> = inactive.clone();
    length[20] = 1;
    for corrupt in [None, Some(vec![0; 16]), Some(unknown), Some(length)] {
        let namespace: PostgresNamespace = fresh_namespace("successor-corrupt", 0xd5, 0xd6);
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
        match corrupt.as_ref() {
            Some(bytes) => set_slot(&mut admin, &namespace, bytes),
            None => {
                admin.execute(
                "DELETE FROM sunrise_edge.successor_serving WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
                &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..]],
            ).unwrap();
            }
        }
        let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
        let operation: DurableOperationContext = context(fence);
        assert_eq!(
            current.get_successor_serving(&operation, namespace.domain()),
            Err(DurableReadError::InvalidPersistedState)
        );
        assert_eq!(
            current.commit_durable(&operation, transaction(namespace.domain())),
            DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
        );
        let persisted: Option<Vec<u8>> = admin.query_opt(
            "SELECT serving FROM sunrise_edge.successor_serving WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
            &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..]],
        ).unwrap().map(|row| row.get(0));
        assert_eq!(persisted, corrupt);
    }
}
