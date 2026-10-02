//! Genuine certified escrow preparation through a view with no writer trait.

use super::*;
use crate::fee_claims::tests::certified_multi_escrow_inventory::{
    Voter, apply_escrow, build_split_claim, build_validator_set, certify, four_sorted_voters,
    install_all, prepare_vote,
};
use crate::paid_execution::tests::{
    FIRST_PAID_NONCE, PaidCall, base_policy, context, domain, entry, memory_store, next_nonce,
    paid_call_with_access, protocol, receipt, refund_account, resolver,
};
use consensus::FastVote;
use execution::LocalWasmExecutionEngine;
use execution::paid_execution::{PaidExecutionStatus, ReservationAccessKind};
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{
    DurableObjectVersion, DurableObjectVersionRecord, DurableReadError, MemoryBlobStore,
    NamespaceLifecycle, VersionedStateReader,
};
use std::cell::Cell;

struct CountingLocalEngine {
    inner: LocalWasmExecutionEngine,
    calls: Cell<u32>,
}

impl CountingLocalEngine {
    fn new() -> Self {
        Self {
            inner: LocalWasmExecutionEngine::new(),
            calls: Cell::new(0),
        }
    }
}

impl LocalContractEngine for CountingLocalEngine {
    fn execute(
        &self,
        request: execution::local_execution::LocalExecutionRequest<'_>,
    ) -> Result<execution::local_execution::LocalExecutionOutcome, LocalExecutionError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.execute(request)
    }
}

/// This adapter deliberately implements only observation ports. Calling an
/// actual durable commit on it would be a compile error, not a test stub.
pub(crate) struct WriterFreeView<'a, S: StructuredStateReader> {
    source: &'a S,
}

impl<'a, S: StructuredStateReader> WriterFreeView<'a, S> {
    pub(crate) const fn new(source: &'a S) -> Self {
        Self { source }
    }
}

impl<S: StructuredStateReader> VersionedStateReader for WriterFreeView<'_, S> {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.source.read_versioned_state(context, domain, key)
    }
}

impl<S: StructuredStateReader> StructuredStateReader for WriterFreeView<'_, S> {
    fn read_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.source.read_namespace_lifecycle(context, domain)
    }

    fn read_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: objects::ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.source.read_object_head(context, domain, object_id)
    }

    fn read_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: objects::ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.source
            .read_object_version(context, domain, object_id, object_version)
    }

    fn read_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.source
            .read_request_receipt(context, domain, request_id)
    }
}

#[test]
fn writer_free_fee_claim_prepares_real_certified_escrow_then_commits_exact_bytes() {
    let voters: Vec<Voter> = four_sorted_voters();
    let entries: Vec<fast_path::FastPathValidatorEntry> =
        voters.iter().map(|voter| voter.entry.clone()).collect();
    let validators: ValidatorSet = build_validator_set(&entries);
    let stores: Vec<runtime::MemoryDurableStateStore> =
        vec![memory_store(), memory_store(), memory_store()];
    let (fixture, policy) = install_all(&stores[0], &entries);
    for store in &stores[1..] {
        install_all(store, &entries);
    }
    let paid: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &policy,
            request: 0xd1,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let votes: Vec<FastVote> = stores
        .iter()
        .zip(&voters)
        .map(|(store, voter)| prepare_vote(store, &policy, voter, &paid))
        .collect();
    let certificate: Vec<u8> = certify(&validators, &votes);
    for store in &stores {
        let applied: NodeOutput = apply_escrow(store, &policy, &paid, &certificate);
        assert_eq!(receipt(&applied).status, PaidExecutionStatus::Success);
        assert_eq!(receipt(&applied).charged.unwrap().actual.get(), 2);
    }
    let claim_request: [u8; 32] = [0xd2; 32];
    let split = build_split_claim(
        &stores[0],
        &fixture,
        &voters[0],
        fast_path::fee_resource_id(&policy).unwrap(),
        [0xd1; 32],
        claim_request,
        next_nonce(&stores[0]),
        0xd3,
    );
    let before: PortableSnapshotToken = stores[0]
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    let nonce_before: u64 = next_nonce(&stores[0]);
    let reader: WriterFreeView<'_, runtime::MemoryDurableStateStore> =
        WriterFreeView::new(&stores[0]);
    let engine: CountingLocalEngine = CountingLocalEngine::new();
    let prepared: InvocationPreparation = prepare_fee_claim_ordered(
        &reader,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &engine,
        &split.signed_bytes,
        12,
        None,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(
        stores[0]
            .begin_portable_snapshot(&context(), domain())
            .unwrap(),
        before
    );
    assert_eq!(next_nonce(&stores[0]), nonce_before);
    assert!(
        reader
            .read_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new(claim_request).unwrap()
            )
            .unwrap()
            .is_none()
    );
    let proposal: Box<PreparedBusinessInvocation> = match prepared {
        InvocationPreparation::Prepared(proposal) => proposal,
        InvocationPreparation::Retained(_) => panic!("fresh claim cannot be retained"),
    };
    let (transaction, expected_output) = proposal.into_parts();
    let exact_receipt: DurableRequestReceipt = transaction.receipt().clone();
    let committed: NodeOutput = PreparedBusinessInvocation::new(transaction, expected_output)
        .unwrap()
        .commit(&stores[0], &context())
        .unwrap();
    let direct: NodeOutput = handle_fee_claim(
        &stores[1],
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &engine,
        &split.signed_bytes,
        12,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 2);
    assert_eq!(committed, direct);
    assert_eq!(
        stores[0]
            .read_request_receipt(&context(), domain(), exact_receipt.request_id())
            .unwrap()
            .unwrap(),
        exact_receipt
    );
    assert_eq!(
        stores[1]
            .read_request_receipt(&context(), domain(), exact_receipt.request_id())
            .unwrap()
            .unwrap(),
        exact_receipt
    );
    let committed_token: PortableSnapshotToken = stores[0]
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    // A preparation retry returns the original output before any fresh
    // admission or execution work, rather than a second proposal.
    let replay: InvocationPreparation = prepare_fee_claim_ordered(
        &reader,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &engine,
        &split.signed_bytes,
        12,
        None,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 2);
    match replay {
        InvocationPreparation::Retained(output) => assert_eq!(output, committed),
        InvocationPreparation::Prepared(_) => panic!("exact replay cannot create a proposal"),
    }
    assert_eq!(
        stores[0]
            .begin_portable_snapshot(&context(), domain())
            .unwrap(),
        committed_token
    );
}
