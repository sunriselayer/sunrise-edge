//! Refusal assertions over a genuinely verified successor reconstruction.
//! This test-only helper returns no store or capability and constructs no
//! chain evidence, installed rows, receipts or accepted outcomes.

use super::*;
use crate::test_support::capture::{assert_same_records_and_blobs, captured_source};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    StateMutationEntry, StateReadAssertion,
};

pub(crate) fn assert_replay_authority_is_bounded(overlay: &BusinessReconstructionOverlay<'_>) {
    let operation: &DurableOperationContext = &overlay.plan.operation_context;
    let domain: AtomicityDomainId = overlay.plan.domain;
    let before: SourceBusinessSnapshot =
        captured_source(&overlay.store, &overlay.blobs, operation, domain);
    let foreign: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain, operation.writer_fence());
    let foreign_before: SourceBusinessSnapshot =
        captured_source(&foreign, &overlay.blobs, operation, domain);
    let scope: ReplayScope<'_> = overlay
        .replay_scope()
        .expect("the real preceding verified link constructs replay authority");
    let gate: ServingGate<'_> = ServingGate::Replay(&scope);
    gate.require_live(&overlay.store, operation, domain)
        .unwrap();
    gate.require_reader(&overlay.store, operation, domain)
        .unwrap();

    // The ordinary memory fixture really exposes this getter. Its presence
    // cannot grant replay either the retention or the completion Seal port.
    assert!(ServingGate::Original.seal_port(&overlay.store).is_ok());
    assert!(gate.seal_port(&overlay.store).is_err());
    let signer: ValidatorId = overlay.base.committee().validators()[0].id;
    assert!(gate.require_local_signer(&overlay.store, signer).is_err());

    // Neither a matching domain/fence on another store nor changing the
    // invocation context/domain can carry the scope outside its issuer.
    assert!(gate.require_live(&foreign, operation, domain).is_err());
    assert!(gate.require_reader(&foreign, operation, domain).is_err());
    let other_operation: DurableOperationContext = DurableOperationContext::new(
        operation.writer_fence().checked_next().unwrap(),
        operation.deadline(),
        operation.correlation_id(),
    );
    assert!(
        gate.require_origin(&overlay.store, &other_operation, domain)
            .is_err()
    );
    let mut other_domain_bytes: [u8; 32] = *domain.as_bytes();
    other_domain_bytes[0] ^= 0x01;
    if other_domain_bytes == [0; 32] {
        other_domain_bytes[0] = 0x02;
    }
    let other_domain: AtomicityDomainId = AtomicityDomainId::new(other_domain_bytes).unwrap();
    assert_ne!(domain, other_domain);
    assert!(
        gate.require_live(&overlay.store, operation, other_domain)
            .is_err()
    );

    // Exercise the actual dispatch boundary with a well-formed prospective
    // mutation. Its foreign issuer is refused before the generic memory
    // commit is called, so no test state is seeded or changed.
    let probe_key: Vec<u8> = b"replay-foreign-issuer-refusal-probe".to_vec();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(probe_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(probe_key, StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        gate.commit_durable(&foreign, operation, transaction),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_same_records_and_blobs(
        &captured_source(&overlay.store, &overlay.blobs, operation, domain),
        &before,
    );
    assert_same_records_and_blobs(
        &captured_source(&foreign, &overlay.blobs, operation, domain),
        &foreign_before,
    );
}
