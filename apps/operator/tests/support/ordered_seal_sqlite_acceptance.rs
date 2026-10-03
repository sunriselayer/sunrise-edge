//! Genuine outgoing Seal through the public CLI and four actual TCP routers.
//! Mutable validator stores are independent SQLite files. Public immutable
//! artifacts share the fixture's blob repository; no completion is seeded.
use super::{fixture::Fixture, hex};
#[path = "ordered_seal_warrant_faults.rs"]
mod warrant_faults;
use consensus::ConsensusSigner;
use consensus::{ConsensusMessage, ConsensusVerifier, ConsensusVote};
use crypto::{Ed25519Verifier, SignatureVerifier};
use ed25519_zebra::SigningKey;
use execution::LocalWasmExecutionEngine;
use native_http::ordered_economics::{
    OrderedEconomicsState, OrderedSealHostComposition, certified_ordered_economics_router,
};
use native_http::{NativeBlockingExecutor, NativeBlockingPolicy};
use node_core::NodeCoreError;
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::ordered_economics::{
    OrderedCandidate, OrderedEconomicsEnvironment, OrderedEconomicsError, OrderedProposal,
    decode_ordered_proposal, decode_seal_outcome, observe_proposal, process_certificate,
    process_proposal, process_tick, propose, query_ordered_outcome, query_status,
};
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::portable::DurableRecordKey;
use runtime::{
    Clock, DurableDomainStateStore, DurableRequestId, IndeterminateCommitReason, OutgoingBarrier,
    StructuredDurableDomainStateStore, SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{ffi::OsString, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;
use warrant_faults::{
    SealCompletionReplyLossMode, SealCompletionReplyLossStore, SealWarrantFault,
    SealWarrantFaultStore,
};

struct Signer {
    id: ValidatorId,
    key: SigningKey,
}
impl ConsensusSigner for Signer {
    fn validator_id(&self) -> ValidatorId {
        self.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(bytes).into();
        Ok(signature.to_vec())
    }
}

struct Verifier;
impl ConsensusVerifier for Verifier {
    fn verify_framed(
        &self,
        _validator: ValidatorId,
        scheme: SignatureSchemeId,
        public_key: &[u8],
        frame: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if scheme != SignatureSchemeId::Ed25519 {
            return Ok(false);
        }
        Ed25519Verifier::from_verifying_key_bytes(public_key)
            .map_err(|error| error.to_string())?
            .verify_framed(frame, signature)
            .map_err(|error| error.to_string())
    }
}

/// Raw fixture control, not a concurrent-safe snapshot/restore mechanism:
/// copies one real SQLite store's main file and WAL/shm companions into an
/// independent destination path. This test is single-threaded and every
/// call site below runs between discrete, already-committed transactions
/// with no other writer ever active, so no in-flight write is torn by the
/// copy; this function does not by itself prove concurrent-snapshot safety.
/// Each call site asserts the clone's own queried status agrees exactly
/// with the real source, rather than merely assuming the copy is coherent.
fn clone_sqlite_store_files(source: &Path, destination: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let from = Path::new(&format!("{}{suffix}", source.display())).to_path_buf();
        if from.exists() {
            std::fs::copy(&from, format!("{}{suffix}", destination.display())).unwrap();
        }
    }
}

fn arguments(fixture: &Fixture, network: &Path, action: &str, extra: &[OsString]) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "economics".into(),
        action.into(),
        "--ordered-network".into(),
        network.as_os_str().into(),
        "--ordered-genesis-manifest".into(),
        fixture.directory.0.join("genesis.bin").into(),
        "--ordered-expected-genesis-digest".into(),
        hex(&fixture.network.manifest_digest).into(),
        "--expected-chain-id".into(),
        fixture.network.chain_id.as_str().into(),
        "--expected-protocol-version".into(),
        fixture.network.protocol_version.get().to_string().into(),
        "--expected-epoch".into(),
        fixture.network.epoch.get().to_string().into(),
        "--domain".into(),
        hex(fixture.network.domain.as_bytes()).into(),
        "--deadline-seconds".into(),
        "90".into(),
        "--per-request-cap-seconds".into(),
        "10".into(),
    ];
    args.extend_from_slice(extra);
    args
}
fn quorum_round<S: StructuredDurableDomainStateStore>(
    fixture: &Fixture,
    env: &OrderedEconomicsEnvironment<'_>,
    stores: &[S],
    candidate: Option<&OrderedCandidate>,
) -> (OrderedProposal, consensus::QuorumCertificate) {
    let status =
        node_core::ordered_economics::query_status(&stores[0], &fixture.operation, env).unwrap();
    let leader_id: ValidatorId = fixture
        .policy
        .engine()
        .validator_set()
        .leader(status.current_view)
        .unwrap();
    let leader_index: usize = fixture
        .network
        .validators
        .iter()
        .position(|validator| validator.validator_id == leader_id)
        .unwrap();
    let leader_signer = Signer {
        id: leader_id,
        key: fixture.network.validators[leader_index].signing_key,
    };
    let proposal: OrderedProposal = propose(
        &stores[leader_index],
        &fixture.operation,
        env,
        candidate,
        &leader_signer,
    )
    .unwrap();
    let mut votes: Vec<ConsensusVote> = Vec::new();
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let signer = Signer {
            id: validator.validator_id,
            key: validator.signing_key,
        };
        let output =
            process_proposal(&stores[index], &fixture.operation, env, &proposal, &signer).unwrap();
        votes.push(
            output
                .messages
                .into_iter()
                .find_map(|message| match message {
                    ConsensusMessage::Vote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap(),
        );
    }
    let certificate = fixture
        .policy
        .engine()
        .certificate_from_votes(&proposal.proposal, &votes, &Verifier)
        .unwrap()
        .unwrap();
    (proposal, certificate)
}

/// Genuine landed-versus-unlanded completion reply-loss at the real
/// `OutgoingSealRepository::commit_seal_completion` port, entirely on
/// isolated clones of the exact pre-Seal state -- never touching the four
/// live validators the rest of this acceptance drives.
///
/// Applying the Seal candidate's own certificate only advances `high_qc`;
/// DR-0187's three-chain rule commits height `h` only once a certificate
/// for `h + 2` is applied. This genuinely drives the Seal round plus its
/// two required EMPTY descendant rounds -- real proposals, real votes,
/// real certificates -- then delivers every one of them to the actual
/// faulted target through the real signerless observer path a lagging
/// replica would use, so its graph/selected prefix/applied `h - 1` are
/// independently valid before the one explicit certificate application
/// that actually commits Seal and is the only place the fault is injected.
fn verify_completion_reply_loss(
    fixture: &Fixture,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) {
    let mut voters: Vec<SqliteDurableStore> = Vec::new();
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let path = fixture
            .directory
            .0
            .join(format!("reply-loss-voter-{index}.sqlite"));
        clone_sqlite_store_files(
            &fixture.directory.0.join(format!("state-{index}.sqlite")),
            &path,
        );
        // A single-threaded, quiescent-between-transactions raw file copy:
        // no writer is active at this instant. Verify coherence directly
        // rather than merely assuming it.
        let cloned = SqliteDurableStore::open_existing(
            &path,
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                validator.validator_id,
                fixture.network.domain,
            ),
        )
        .unwrap();
        assert_eq!(
            query_status(&cloned, &fixture.operation, env).unwrap(),
            query_status(&fixture.stores[index], &fixture.operation, env).unwrap(),
            "the raw clone must agree exactly with the real source status"
        );
        voters.push(cloned);
    }
    // Round A: the real Seal candidate at its own height.
    let (proposal_a, certificate_a) = quorum_round(fixture, env, &voters, Some(candidate));
    for voter in &voters {
        process_certificate(voter, &fixture.operation, env, &certificate_a).unwrap();
    }
    // Round B: the first genuine EMPTY descendant round.
    let (proposal_b, certificate_b) = quorum_round(fixture, env, &voters, None);
    for voter in &voters {
        process_certificate(voter, &fixture.operation, env, &certificate_b).unwrap();
    }
    // Round C: the second genuine EMPTY descendant round. Forming its
    // certificate is the last signature any voter ever produces; no voter
    // itself applies certificate_c, so none signs after Seal.
    let (proposal_c, certificate_c) = quorum_round(fixture, env, &voters, None);
    drop(voters);
    let request = DurableRequestId::new(candidate.request_id).unwrap();
    let zeroth = &fixture.network.validators[0];
    let landed_path = fixture.directory.0.join("reply-loss-landed.sqlite");
    clone_sqlite_store_files(&fixture.directory.0.join("state-0.sqlite"), &landed_path);
    let landed_inner = Arc::new(
        SqliteDurableStore::open_existing(
            &landed_path,
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                zeroth.validator_id,
                fixture.network.domain,
            ),
        )
        .unwrap(),
    );
    assert_eq!(
        query_status(landed_inner.as_ref(), &fixture.operation, env).unwrap(),
        query_status(&fixture.stores[0], &fixture.operation, env).unwrap(),
        "the raw clone must agree exactly with the real source status"
    );
    let landed = SealCompletionReplyLossStore::new(
        Arc::clone(&landed_inner),
        SealCompletionReplyLossMode::LandedIndeterminate,
    );
    // Real signerless observer/recovery: register and apply each round's
    // own justified prefix on the actual faulted target, exactly like a
    // lagging replica, before the one explicit certificate application
    // that commits Seal.
    observe_proposal(&landed, &fixture.operation, env, &proposal_a).unwrap();
    observe_proposal(&landed, &fixture.operation, env, &proposal_b).unwrap();
    observe_proposal(&landed, &fixture.operation, env, &proposal_c).unwrap();
    assert_eq!(
        query_status(&landed, &fixture.operation, env)
            .unwrap()
            .committed_height,
        proposal_a.proposal.height.checked_sub(1).unwrap(),
        "the two descendant rounds commit only up through the empty round, not Seal yet"
    );
    match process_certificate(&landed, &fixture.operation, env, &certificate_c) {
        Err(OrderedEconomicsError::Node(NodeCoreError::DurableCommitIndeterminate(
            IndeterminateCommitReason::ConnectionLost,
        ))) => {}
        other => panic!(
            "a landed ambiguous write must surface this exact documented Indeterminate error, got {other:?}"
        ),
    }
    assert_eq!(landed.hits(), 1, "the landed fault fires exactly once");
    let landed_barrier = landed_inner
        .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
        .unwrap();
    assert!(
        matches!(landed_barrier, OutgoingBarrier::Sealed(_)),
        "the real completion commits despite the lost reply"
    );
    assert_eq!(
        query_status(landed_inner.as_ref(), &fixture.operation, env)
            .unwrap()
            .committed_height,
        proposal_a.proposal.height,
        "the landed completion actually advances the applied prefix through Seal"
    );
    let landed_receipt_before = landed_inner
        .get_request_receipt(&fixture.operation, fixture.network.domain, request)
        .unwrap();
    assert!(landed_receipt_before.is_some());
    let landed_outcome_before = query_ordered_outcome(
        landed_inner.as_ref(),
        &fixture.operation,
        env,
        &candidate.request_id,
    )
    .unwrap();
    assert!(landed_outcome_before.is_some());
    let landed_business_before = capture_source_business_snapshot(
        landed_inner.as_ref(),
        &fixture.blobs,
        &fixture.operation,
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    // Real signerless recovery: engine.rs's own `observe_proposal` converts
    // an already-completed candidate into a read-only retained admission
    // (empty reads/writes/head_reads) rather than an `AlreadyCompleted`
    // error -- that distinction is `process_proposal`'s alone. Its genuine
    // documented output here is therefore the empty signerless event: no
    // message, no newly committed outcome. It never reapplies, changes the
    // receipt, resets the fence or touches business state.
    let landed_recovery = observe_proposal(&landed, &fixture.operation, env, &proposal_a).unwrap();
    assert!(
        landed_recovery.messages.is_empty() && landed_recovery.committed.is_empty(),
        "declared recovery of an already-completed candidate is the genuine empty \
         signerless output, got {landed_recovery:?}"
    );
    assert_eq!(
        landed.hits(),
        1,
        "recovery never touches the completion port again"
    );
    assert_eq!(
        landed_inner
            .get_request_receipt(&fixture.operation, fixture.network.domain, request)
            .unwrap(),
        landed_receipt_before
    );
    assert_eq!(
        query_ordered_outcome(
            landed_inner.as_ref(),
            &fixture.operation,
            env,
            &candidate.request_id
        )
        .unwrap(),
        landed_outcome_before
    );
    assert_eq!(
        capture_source_business_snapshot(
            landed_inner.as_ref(),
            &fixture.blobs,
            &fixture.operation,
            fixture.network.domain,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap(),
        landed_business_before,
        "exact retained reconciliation changes no object, nonce or inventory state"
    );
    assert_eq!(
        landed_inner
            .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
            .unwrap(),
        landed_barrier,
        "recovery never reseals or resets the fence"
    );
    let unlanded_path = fixture.directory.0.join("reply-loss-unlanded.sqlite");
    clone_sqlite_store_files(&fixture.directory.0.join("state-0.sqlite"), &unlanded_path);
    let unlanded_inner = Arc::new(
        SqliteDurableStore::open_existing(
            &unlanded_path,
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                zeroth.validator_id,
                fixture.network.domain,
            ),
        )
        .unwrap(),
    );
    assert_eq!(
        query_status(unlanded_inner.as_ref(), &fixture.operation, env).unwrap(),
        query_status(&fixture.stores[0], &fixture.operation, env).unwrap(),
        "the raw clone must agree exactly with the real source status"
    );
    let unlanded = SealCompletionReplyLossStore::new(
        Arc::clone(&unlanded_inner),
        SealCompletionReplyLossMode::UnlandedIndeterminate,
    );
    observe_proposal(&unlanded, &fixture.operation, env, &proposal_a).unwrap();
    observe_proposal(&unlanded, &fixture.operation, env, &proposal_b).unwrap();
    observe_proposal(&unlanded, &fixture.operation, env, &proposal_c).unwrap();
    assert_eq!(
        query_status(&unlanded, &fixture.operation, env)
            .unwrap()
            .committed_height,
        proposal_a.proposal.height.checked_sub(1).unwrap(),
        "the two descendant rounds commit only up through the empty round, not Seal yet"
    );
    // The exact complete source snapshot immediately before the one call
    // that would commit Seal -- the baseline an unlanded fault must leave
    // completely untouched, with no consensus, applied-prefix or refusal
    // effect whatsoever.
    let unlanded_snapshot_before_fault = capture_source_business_snapshot(
        unlanded_inner.as_ref(),
        &fixture.blobs,
        &fixture.operation,
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    match process_certificate(&unlanded, &fixture.operation, env, &certificate_c) {
        Err(OrderedEconomicsError::Node(NodeCoreError::DurableCommitIndeterminate(
            IndeterminateCommitReason::ConnectionLost,
        ))) => {}
        other => panic!(
            "an unlanded lost reply must surface this exact documented Indeterminate error, got {other:?}"
        ),
    }
    assert_eq!(
        unlanded.hits(),
        1,
        "the unlanded fault fires exactly once before any real commit"
    );
    assert_eq!(
        unlanded_inner
            .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed,
        "unlanded reply loss leaves the real completion uncommitted"
    );
    assert!(
        unlanded_inner
            .get_request_receipt(&fixture.operation, fixture.network.domain, request)
            .unwrap()
            .is_none()
    );
    assert!(
        query_ordered_outcome(
            unlanded_inner.as_ref(),
            &fixture.operation,
            env,
            &candidate.request_id
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        query_status(unlanded_inner.as_ref(), &fixture.operation, env)
            .unwrap()
            .committed_height,
        proposal_a.proposal.height.checked_sub(1).unwrap(),
        "unlanded reply loss leaves the applied prefix exactly where it was, not advanced through Seal"
    );
    assert_eq!(
        capture_source_business_snapshot(
            unlanded_inner.as_ref(),
            &fixture.blobs,
            &fixture.operation,
            fixture.network.domain,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap(),
        unlanded_snapshot_before_fault,
        "unlanded reply loss changes nothing at all: no consensus, applied-prefix or refusal effect"
    );
    // Real retry: once the fault no longer blocks the port, the same real
    // certificate completes for real -- genuine recovery, not a cached
    // response.
    unlanded.reconfigure(SealCompletionReplyLossMode::Healthy);
    let unlanded_retry = process_certificate(&unlanded, &fixture.operation, env, &certificate_c)
        .expect("the real retry completes for real once the fault clears");
    assert_eq!(
        unlanded_retry.committed.len(),
        1,
        "the real retry genuinely advances exactly one newly committed Seal"
    );
    assert_eq!(unlanded_retry.committed[0].request_id, candidate.request_id);
    assert_eq!(
        unlanded_retry.committed[0].block_height,
        proposal_a.proposal.height
    );
    assert!(unlanded_retry.messages.is_empty());
    assert_eq!(
        unlanded.hits(),
        1,
        "the healthy retry is not counted as another fault hit"
    );
    assert!(matches!(
        unlanded_inner
            .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
            .unwrap(),
        OutgoingBarrier::Sealed(_)
    ));
    assert!(
        unlanded_inner
            .get_request_receipt(&fixture.operation, fixture.network.domain, request)
            .unwrap()
            .is_some()
    );
    assert!(
        query_ordered_outcome(
            unlanded_inner.as_ref(),
            &fixture.operation,
            env,
            &candidate.request_id
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(
        query_status(unlanded_inner.as_ref(), &fixture.operation, env)
            .unwrap()
            .committed_height,
        proposal_a.proposal.height,
        "the real retry actually advances the applied prefix through Seal"
    );
    let unlanded_business_after = capture_source_business_snapshot(
        unlanded_inner.as_ref(),
        &fixture.blobs,
        &fixture.operation,
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    // Seal carries no sender identity or nonce to move; this filter proves
    // the real retry adds no object-head/version effect, not nonce
    // coverage, which does not apply to a Seal candidate.
    let business = |snapshot: &SourceBusinessSnapshot| {
        snapshot
            .records
            .iter()
            .filter(|row| {
                matches!(
                    row.descriptor.key(),
                    DurableRecordKey::ObjectHead(_) | DurableRecordKey::ObjectVersion(_, _)
                )
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        business(&unlanded_business_after),
        business(&unlanded_snapshot_before_fault),
        "the real retry's Seal completion produces no new object-state effect"
    );
}
pub(super) async fn run(
    fixture: &mut Fixture,
    candidate_path: &Path,
    candidate: &OrderedCandidate,
    competing_candidate: &OrderedCandidate,
) {
    let fence: WriterFenceGeneration = fixture.operation.writer_fence();
    let mut stores: Vec<Arc<SqliteDurableStore>> = Vec::new();
    let mut ports: Vec<Arc<SealWarrantFaultStore>> = Vec::new();
    let mut servers = Vec::new();
    let mut stops = Vec::new();
    let mut peers: String = String::new();
    let before: Vec<SourceBusinessSnapshot> = fixture
        .stores
        .iter()
        .map(|store| {
            capture_source_business_snapshot(
                store,
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let env = OrderedEconomicsEnvironment {
        policy: &fixture.policy,
        history: &[],
        leg_policy: &fixture.local_policy,
        engine: &fixture.engine,
        blobs: &fixture.blobs,
        seal: Some(node_core::ordered_economics::OrderedSealComposition {
            genesis_root: &fixture.root,
            paid_base_policy: &fixture.local_policy,
            paid_engine: &fixture.engine,
            blobs: &fixture.blobs,
        }),
    };
    let initial_status =
        node_core::ordered_economics::query_status(&fixture.stores[0], &fixture.operation, &env)
            .unwrap();
    let mut seal_height: u64 = initial_status.high_qc.height.checked_add(1).unwrap();
    while seal_height % 3 != 1 {
        seal_height = seal_height.checked_add(1).unwrap();
    }
    let prior_height: u64 = seal_height.checked_sub(1).unwrap();
    let fault_plans: [SealWarrantFault; 4] = [
        SealWarrantFault::Healthy,
        SealWarrantFault::MissingFreeze,
        SealWarrantFault::MissingDrain,
        SealWarrantFault::IneligibleSuccessor,
    ];
    assert_eq!(fixture.network.validators.len(), fault_plans.len());
    // The real pre-Seal height is not generally seal_height - 1: establish
    // genuine authenticated EMPTY alignment first, with real proposal,
    // votes and a real quorum certificate applied to every replica, exactly
    // like any other causal round -- no patched height or lock.
    // DR-0188 bounds client EMPTY alignment at two rounds; genuine progress
    // each round means at most two are ever needed to reach seal_height - 1.
    for _ in 0..2 {
        let aligned_status = query_status(&fixture.stores[0], &fixture.operation, &env).unwrap();
        if aligned_status.high_qc.height.checked_add(1).unwrap() == seal_height {
            break;
        }
        let before_height = aligned_status.high_qc.height;
        let (_, empty_certificate) = quorum_round(fixture, &env, &fixture.stores, None);
        for store in &fixture.stores {
            process_certificate(store, &fixture.operation, &env, &empty_certificate).unwrap();
        }
        let after_height = query_status(&fixture.stores[0], &fixture.operation, &env)
            .unwrap()
            .high_qc
            .height;
        assert_eq!(
            after_height,
            before_height.checked_add(1).unwrap(),
            "each genuine EMPTY alignment round advances high_qc by exactly one height"
        );
    }
    let aligned_status = query_status(&fixture.stores[0], &fixture.operation, &env).unwrap();
    assert_eq!(
        aligned_status.high_qc.height.checked_add(1).unwrap(),
        seal_height,
        "at most two genuine EMPTY alignment rounds reach exactly seal_height - 1"
    );
    // Genuine landed-versus-unlanded completion reply-loss, entirely on
    // isolated clones of this exact pre-Seal state -- never on the four
    // live validators the rest of this acceptance drives below.
    verify_completion_reply_loss(fixture, &env, candidate);
    // DR-0187: build a genuine, real-signed competing Seal proposal before
    // any commitment lands. It targets the exact same height as the
    // accepted candidate but is never admitted by a quorum, so it stays a
    // genuinely uncompleted, pending request -- not a raw-fabricated one.
    let competing_status =
        node_core::ordered_economics::query_status(&fixture.stores[0], &fixture.operation, &env)
            .unwrap();
    assert_eq!(
        competing_status.high_qc.height.checked_add(1).unwrap(),
        seal_height
    );
    let leader_id: ValidatorId = fixture
        .policy
        .engine()
        .validator_set()
        .leader(competing_status.current_view)
        .unwrap();
    let leader_index: usize = fixture
        .network
        .validators
        .iter()
        .position(|validator| validator.validator_id == leader_id)
        .unwrap();
    let leader_signer = Signer {
        id: leader_id,
        key: fixture.network.validators[leader_index].signing_key,
    };
    let competing_proposal: OrderedProposal = propose(
        &fixture.stores[leader_index],
        &fixture.operation,
        &env,
        Some(competing_candidate),
        &leader_signer,
    )
    .unwrap();
    assert_eq!(competing_proposal.proposal.height, seal_height);
    // The genuinely pending original header must exist: a fresh re-propose
    // of the exact same competing candidate, while the real current view
    // and leader are still unchanged (before any own vote is cast),
    // reconciles to the identical retained leader proposal -- proving a
    // real persisted header/leader record, not a one-shot fluke. Replaying
    // this after casting the own vote below would move to a fresh view and
    // a possibly different leader, so it would not prove retained replay.
    let repeated_competing_proposal: OrderedProposal = propose(
        &fixture.stores[leader_index],
        &fixture.operation,
        &env,
        Some(competing_candidate),
        &leader_signer,
    )
    .unwrap();
    assert_eq!(
        repeated_competing_proposal.proposal,
        competing_proposal.proposal
    );
    // At least one real own-vote/leader retention before Seal: the leader
    // casts its own genuine vote on the competing branch, never reaching
    // quorum, so this is a genuinely retained pending vote, not a one-off
    // dangling proposal.
    process_proposal(
        &fixture.stores[leader_index],
        &fixture.operation,
        &env,
        &competing_proposal,
        &leader_signer,
    )
    .unwrap();
    // Query real status after the leader's own cast vote -- never assume
    // casting it advanced the view. Verify it actually did (the engine's
    // own vote-processing sets current_view >= proposal.view + 1
    // unconditionally); if it somehow had not, the competing leader slot
    // would remain occupied and this assertion catches that directly.
    let target_view = query_status(&fixture.stores[leader_index], &fixture.operation, &env)
        .unwrap()
        .current_view;
    assert!(
        target_view > competing_proposal.proposal.view,
        "the leader's own cast vote must have superseded its competing retained slot"
    );
    // Minimal genuine real-clock progression -- not a blind fixed future
    // timestamp loop: the actual wall-clock "now" is already far past any
    // genesis-relative view deadline, so exactly one real Tick per
    // still-behind validator is the minimum justified scenario needed.
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let behind_view = query_status(&fixture.stores[index], &fixture.operation, &env)
            .unwrap()
            .current_view;
        if behind_view < target_view {
            let signer = Signer {
                id: validator.validator_id,
                key: validator.signing_key,
            };
            let now_unix_millis = SystemClock.now_unix_millis().unwrap();
            process_tick(
                &fixture.stores[index],
                &fixture.operation,
                &env,
                now_unix_millis,
                &signer,
            )
            .unwrap();
        }
        assert_eq!(
            query_status(&fixture.stores[index], &fixture.operation, &env)
                .unwrap()
                .current_view,
            target_view,
            "every validator reaches the exact same target view before the real Seal round"
        );
    }
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let store: Arc<SqliteDurableStore> = Arc::new(
            SqliteDurableStore::open_existing(
                fixture.directory.0.join(format!("state-{index}.sqlite")),
                SqliteNamespace::new(
                    fixture.network.chain_id.clone(),
                    validator.validator_id,
                    fixture.network.domain,
                ),
            )
            .unwrap(),
        );
        let blobs: Arc<SqliteBlobStore> =
            Arc::new(SqliteBlobStore::open(fixture.directory.0.join("blobs.sqlite")).unwrap());
        let engine: Arc<LocalWasmExecutionEngine> = Arc::new(LocalWasmExecutionEngine::new());
        let port: Arc<SealWarrantFaultStore> = Arc::new(
            SealWarrantFaultStore::new(
                Arc::clone(&store),
                fixture.policy.clone(),
                fixture.local_policy.clone(),
                Arc::clone(&engine),
                Arc::clone(&blobs),
                prior_height,
                fault_plans[index],
                &before[index],
            )
            .unwrap(),
        );
        assert!(
            Arc::ptr_eq(port.inner(), &store),
            "all authority belongs to the actual validator store"
        );
        let router = certified_ordered_economics_router(OrderedEconomicsState {
            store: Arc::clone(&port),
            clock: Arc::new(SystemClock),
            identities: Arc::new(sunrise_edge_devnet::DevnetOutboxIdentitySource::new(fence)),
            domain: fixture.network.domain,
            writer_fence: fence,
            operation_timeout: Duration::from_secs(60),
            policy: fixture.policy.clone(),
            history: Vec::new(),
            leg_policy: fixture.local_policy.clone(),
            engine: engine.clone(),
            blobs: blobs.clone(),
            seal: Some(OrderedSealHostComposition {
                genesis_root: fixture.root.clone(),
                paid_base_policy: fixture.local_policy.clone(),
                paid_engine: engine,
                blobs,
            }),
            signer: Signer {
                id: validator.validator_id,
                key: validator.signing_key,
            },
            blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
                NonZeroUsize::new(2).unwrap(),
            )),
            cancellation: None,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        peers.push_str(&format!(
            "{} {address} - -\n",
            hex(validator.validator_id.as_bytes())
        ));
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        stops.push(stop);
        servers.push(tokio::spawn(native_http::serve(listener, router, async {
            let _ = shutdown.await;
        })));
        stores.push(store);
        ports.push(port);
    }
    let network = fixture.directory.0.join("seal-network.conf");
    std::fs::write(&network, peers).unwrap();
    let prefix = fixture.directory.0.join("seal-submission");
    let submit_args = arguments(
        fixture,
        &network,
        "network-submit",
        &[
            "--candidate".into(),
            candidate_path.as_os_str().into(),
            "--out".into(),
            prefix.as_os_str().into(),
        ],
    );
    tokio::task::spawn_blocking(move || sunrise_edge_cli::run(submit_args))
        .await
        .unwrap()
        .unwrap();
    let request: DurableRequestId = DurableRequestId::new(candidate.request_id).unwrap();
    for index in 1..ports.len() {
        let port = &ports[index];
        assert!(
            port.fault_hits() > 0,
            "the exact completion warrant fault was consumed"
        );
        assert_eq!(
            port.ordinary_commit_attempts_after_fault(),
            0,
            "a failed Seal warrant stops before any ordinary refusal commit, not merely a later CAS conflict"
        );
        assert_eq!(
            capture_source_business_snapshot(
                stores[index].as_ref(),
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            port.before_fault().unwrap(),
            "a genuine committed Seal certificate cannot advance consensus/applied state or archive on a local warrant failure"
        );
        assert_eq!(
            stores[index]
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed
        );
        assert!(
            stores[index]
                .get_request_receipt(&fixture.operation, fixture.network.domain, request)
                .unwrap()
                .is_none()
        );
        assert!(
            query_ordered_outcome(
                stores[index].as_ref(),
                &fixture.operation,
                &env,
                &candidate.request_id
            )
            .unwrap()
            .is_none()
        );
        port.disable_fault();
    }
    let manifest = std::path::PathBuf::from(format!("{}.manifest", prefix.display()));
    let catchup_prefix = fixture.directory.0.join("seal-warrant-catchup");
    let catchup_args = arguments(
        fixture,
        &network,
        "network-replay",
        &[
            "--manifest".into(),
            manifest.as_os_str().into(),
            "--out".into(),
            catchup_prefix.as_os_str().into(),
        ],
    );
    tokio::task::spawn_blocking(move || sunrise_edge_cli::run(catchup_args))
        .await
        .unwrap()
        .unwrap();
    let mut original_receipts = Vec::new();
    let mut completed = Vec::new();
    let mut agreed = None;
    for (index, store) in stores.iter().enumerate() {
        let barrier = store
            .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
            .unwrap();
        let OutgoingBarrier::Sealed(sealed) = barrier else {
            panic!("every genuine validator must persist Seal");
        };
        assert_eq!(sealed.request, candidate.request_id);
        assert_eq!(sealed.outgoing_epoch, fixture.network.epoch);
        if let Some(previous) = agreed {
            assert_eq!(sealed, previous);
        }
        agreed = Some(sealed);
        let outcome = query_ordered_outcome(
            store.as_ref(),
            &fixture.operation,
            &env,
            &candidate.request_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(outcome.block_height, sealed.height);
        assert_eq!(outcome.block_digest, sealed.block_digest);
        let payload = outcome.output.responses()[0].payload().unwrap();
        let decoded = decode_seal_outcome(payload).unwrap();
        assert_eq!(decoded.target, sealed.target_digest);
        assert_eq!(decoded.request, candidate.request_id);
        let receipt = store
            .get_request_receipt(&fixture.operation, fixture.network.domain, request)
            .unwrap()
            .unwrap();
        original_receipts.push(receipt);
        let signer = Signer {
            id: fixture.network.validators[index].validator_id,
            key: fixture.network.validators[index].signing_key,
        };
        assert!(
            propose(store.as_ref(), &fixture.operation, &env, None, &signer).is_err(),
            "no new outgoing leader signature after Seal"
        );
        let snapshot = capture_source_business_snapshot(
            store.as_ref(),
            &fixture.blobs,
            &fixture.operation,
            fixture.network.domain,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        let business = |snapshot: &SourceBusinessSnapshot| {
            snapshot
                .records
                .iter()
                .filter(|row| {
                    matches!(
                        row.descriptor.key(),
                        DurableRecordKey::ObjectHead(_) | DurableRecordKey::ObjectVersion(_, _)
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            business(&snapshot),
            business(&before[index]),
            "Seal has no object or fee effects"
        );
        for original in before[index]
            .records
            .iter()
            .filter(|row| matches!(row.descriptor.key(), DurableRecordKey::Receipt(_)))
        {
            assert!(
                snapshot.records.contains(original),
                "original business receipt never changes"
            );
        }
        completed.push(snapshot);
    }
    let manifest_text: String = std::fs::read_to_string(&manifest).unwrap();
    let proposal: OrderedProposal = manifest_text
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|path| decode_ordered_proposal(&std::fs::read(path).unwrap()).unwrap())
        .find(|proposal: &OrderedProposal| {
            proposal
                .candidate
                .as_ref()
                .is_some_and(|retained: &OrderedCandidate| {
                    retained.request_id == candidate.request_id && retained.kind == candidate.kind
                })
        })
        .expect("the manifest retains the actual Seal candidate proposal");
    for (index, store) in stores.iter().enumerate() {
        let signer = Signer {
            id: fixture.network.validators[index].validator_id,
            key: fixture.network.validators[index].signing_key,
        };
        // Replaying the exact committed Seal proposal is a legal original
        // reconciliation: it is the identical already-completed request, so
        // this is AlreadyCompleted, never a fresh barrier exposure.
        match process_proposal(store.as_ref(), &fixture.operation, &env, &proposal, &signer) {
            Err(OrderedEconomicsError::AlreadyCompleted(outcome)) => {
                assert_eq!(outcome.block_height, agreed.unwrap().height);
            }
            other => panic!(
                "exact-original Seal proposal replay must reconcile as already completed, got {other:?}"
            ),
        }
        // A genuinely distinct, never-completed competing Seal candidate
        // must instead Stop on the Sealed barrier -- not be laundered
        // through AlreadyCompleted, which would hide an unrelated pending
        // request as if it were this validator's own retained vote.
        assert!(
            query_ordered_outcome(
                store.as_ref(),
                &fixture.operation,
                &env,
                &competing_candidate.request_id
            )
            .unwrap()
            .is_none(),
            "the competing branch was never admitted to completion"
        );
        match process_proposal(
            store.as_ref(),
            &fixture.operation,
            &env,
            &competing_proposal,
            &signer,
        ) {
            Err(OrderedEconomicsError::Node(NodeCoreError::PersistenceInvariant(message))) => {
                assert_eq!(message, "outgoing epoch is sealed; live work is forbidden");
            }
            other => panic!(
                "a distinct pending Seal candidate must stop on the Sealed barrier, got {other:?}"
            ),
        }
    }
    let replay_prefix = fixture.directory.0.join("seal-replay");
    let replay_args = arguments(
        fixture,
        &network,
        "network-replay",
        &[
            "--manifest".into(),
            manifest.as_os_str().into(),
            "--out".into(),
            replay_prefix.as_os_str().into(),
        ],
    );
    tokio::task::spawn_blocking(move || sunrise_edge_cli::run(replay_args))
        .await
        .unwrap()
        .unwrap();
    for (index, store) in stores.iter().enumerate() {
        assert_eq!(
            capture_source_business_snapshot(
                store.as_ref(),
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            completed[index],
            "original signerless replay neither reapplies nor changes metadata"
        );
    }
    for stop in stops {
        stop.send(()).unwrap();
    }
    for server in servers {
        server.await.unwrap().unwrap();
    }
    drop(ports);
    drop(stores);
    fixture.stores.clear(); // True close of every structured-state handle.
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let path = fixture.directory.0.join(format!("state-{index}.sqlite"));
        let namespace = SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            validator.validator_id,
            fixture.network.domain,
        );
        assert!(
            SqliteDurableStore::open_existing(&path, namespace.clone()).is_err(),
            "a committed Seal cannot reopen in serving mode"
        );
        let historical = SqliteDurableStore::open_historical(&path, namespace).unwrap();
        assert_eq!(
            historical
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Sealed(agreed.unwrap())
        );
        assert_eq!(
            historical
                .get_request_receipt(&fixture.operation, fixture.network.domain, request)
                .unwrap(),
            Some(original_receipts[index].clone())
        );
        assert_eq!(
            capture_source_business_snapshot(
                &historical,
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            completed[index]
        );
    }
}
