//! Genuine outgoing Seal through the in-process public Rust CLI entrypoint
//! and four actual TCP routers; its return value is not captured stdout.
//! Mutable validator stores are independent SQLite files. Public immutable
//! artifacts share the fixture's blob repository; no completion is seeded.
use super::{fixture::Fixture, hex};
#[path = "compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[path = "ordered_seal_warrant_faults.rs"]
mod warrant_faults;
use consensus::ConsensusSigner;
use consensus::{
    ConsensusMessage, ConsensusVerifier, ConsensusVote, QuorumCertificate,
    decode_quorum_certificate,
};
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
    OrderedCandidate, OrderedEconomicsEnvironment, OrderedEconomicsError, OrderedEventOutput,
    OrderedOutcome, OrderedProposal, OrderedStatus, decode_ordered_candidate,
    decode_ordered_event_output, decode_ordered_proposal, decode_seal_outcome, observe_proposal,
    process_certificate, process_proposal, process_tick, propose, query_ordered_outcome,
    query_status,
};
use protocol_types::{Digest32, SignatureSchemeId, ValidatorId};
use runtime::portable::DurableRecordKey;
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, DurableRequestId,
    DurableRequestReceipt, IndeterminateCommitReason, OutgoingBarrier, SealBarrier,
    StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
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

fn clone_fixture_stores(
    fixture: &Fixture,
    env: &OrderedEconomicsEnvironment<'_>,
    prefix: &str,
) -> Vec<SqliteDurableStore> {
    let mut stores: Vec<SqliteDurableStore> = Vec::new();
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let path: PathBuf = fixture.directory.0.join(format!("{prefix}-{index}.sqlite"));
        clone_sqlite_store_files(
            &fixture.directory.0.join(format!("state-{index}.sqlite")),
            &path,
        );
        let cloned: SqliteDurableStore = SqliteDurableStore::open_existing(
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
            "each quiescent raw clone independently verifies the original consensus state"
        );
        assert_eq!(
            capture_source_business_snapshot(
                &cloned,
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            capture_source_business_snapshot(
                &fixture.stores[index],
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            "clone rows, referenced blobs, snapshot token and writer fence match their own source"
        );
        assert_eq!(
            cloned
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed
        );
        stores.push(cloned);
    }
    stores
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
) -> (OrderedProposal, QuorumCertificate) {
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

/// Direct rounds belong only to isolated fault/competing test controls.
/// The four source stores must reach their alignment through HTTP/CLI.
fn align_cloned_stores(
    fixture: &Fixture,
    env: &OrderedEconomicsEnvironment<'_>,
    stores: &[SqliteDurableStore],
    seal_height: u64,
) -> Vec<(OrderedProposal, QuorumCertificate)> {
    let mut rounds: Vec<(OrderedProposal, QuorumCertificate)> = Vec::new();
    for _ in 0..2 {
        let status = query_status(&stores[0], &fixture.operation, env).unwrap();
        if status.high_qc.height.checked_add(1).unwrap() == seal_height {
            break;
        }
        let (proposal, certificate) = quorum_round(fixture, env, stores, None);
        assert!(proposal.candidate.is_none() && proposal.proposal.transactions.is_empty());
        assert_eq!(
            proposal.proposal.height,
            status.high_qc.height.checked_add(1).unwrap()
        );
        assert_eq!(
            proposal.proposal.justify.proposal_digest,
            status.high_qc.proposal_digest
        );
        for store in stores {
            process_certificate(store, &fixture.operation, env, &certificate).unwrap();
            assert_eq!(
                query_status(store, &fixture.operation, env)
                    .unwrap()
                    .high_qc,
                certificate
            );
        }
        rounds.push((proposal, certificate));
    }
    assert_eq!(
        query_status(&stores[0], &fixture.operation, env)
            .unwrap()
            .high_qc
            .height
            .checked_add(1)
            .unwrap(),
        seal_height,
        "at most two genuine EMPTY rounds align each isolated scenario"
    );
    rounds
}

fn saved_submission_rounds(
    fixture: &Fixture,
    candidate_path: &Path,
    prefix: &Path,
    candidate: &OrderedCandidate,
    initial_parent: &QuorumCertificate,
) -> Vec<(OrderedProposal, QuorumCertificate)> {
    let saved_candidate: Vec<u8> =
        std::fs::read(format!("{}.round-0.candidate", prefix.display())).unwrap();
    assert_eq!(saved_candidate, std::fs::read(candidate_path).unwrap());
    assert_eq!(
        decode_ordered_candidate(&saved_candidate).unwrap(),
        *candidate
    );
    let manifest_text: String =
        std::fs::read_to_string(format!("{}.manifest", prefix.display())).unwrap();
    let mut rounds: Vec<(OrderedProposal, QuorumCertificate)> = Vec::new();
    let mut parent: QuorumCertificate = initial_parent.clone();
    for (round, line) in manifest_text.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [proposal_path, certificate_path] = fields.as_slice() else {
            panic!("each chronological manifest round retains exactly one proposal/QC pair");
        };
        for (path, kind) in [
            (*proposal_path, "proposal"),
            (*certificate_path, "certificate"),
        ] {
            assert_eq!(
                PathBuf::from(path),
                std::fs::canonicalize(format!("{}.round-{round}.{kind}", prefix.display()))
                    .unwrap(),
                "manifest order is the actual CLI's chronological artifact order"
            );
        }
        let proposal: OrderedProposal =
            decode_ordered_proposal(&std::fs::read(proposal_path).unwrap()).unwrap();
        let certificate: QuorumCertificate =
            decode_quorum_certificate(&std::fs::read(certificate_path).unwrap()).unwrap();
        fixture
            .policy
            .engine()
            .verify_proposal(&proposal.proposal, &Verifier)
            .unwrap();
        fixture
            .policy
            .engine()
            .verify_certificate(&certificate, &Verifier)
            .unwrap();
        let justify: &QuorumCertificate = &proposal.proposal.justify;
        assert_eq!(justify.proposal_digest, parent.proposal_digest);
        assert_eq!(justify.height, parent.height);
        assert_eq!(justify.view, parent.view);
        assert_eq!(
            proposal.proposal.height,
            parent.height.checked_add(1).unwrap()
        );
        assert!(proposal.proposal.view > parent.view);
        assert_eq!(certificate.height, proposal.proposal.height);
        assert_eq!(certificate.view, proposal.proposal.view);
        assert_eq!(
            certificate.proposal_digest,
            fixture
                .policy
                .engine()
                .proposal_digest(&proposal.proposal)
                .unwrap()
        );
        if round == 1 {
            assert_eq!(proposal.candidate.as_ref(), Some(candidate));
            assert_eq!(
                proposal.proposal.transactions,
                vec![fixture.policy.candidate_digest(candidate).unwrap()]
            );
        } else {
            assert!(proposal.candidate.is_none() && proposal.proposal.transactions.is_empty());
        }
        parent = certificate.clone();
        rounds.push((proposal, certificate));
    }
    assert_eq!(
        rounds
            .iter()
            .map(|(proposal, _)| proposal.proposal.height)
            .collect::<Vec<u64>>(),
        (1..=4)
            .map(|offset| initial_parent.height.checked_add(offset).unwrap())
            .collect::<Vec<u64>>(),
        "the actual HTTP/CLI path performs alignment, Seal and both certified descendants"
    );
    rounds
}

fn acknowledged_output(phase: &str) -> OrderedEventOutput {
    let encoded: &str = phase
        .strip_prefix("acknowledged:")
        .expect("an actual acknowledged phase");
    assert_eq!(encoded.len() % 2, 0);
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    decode_ordered_event_output(&bytes).unwrap()
}

fn saved_peer_results(
    fixture: &Fixture,
    prefix: &Path,
    endpoints: &[String],
    rounds: usize,
) -> BTreeMap<(usize, usize), (String, String)> {
    let results_text: String =
        std::fs::read_to_string(format!("{}.results", prefix.display())).unwrap();
    let mut reports: BTreeMap<(usize, usize), (String, String)> = BTreeMap::new();
    let mut pre_certificate_votes: BTreeMap<(usize, usize), String> = BTreeMap::new();
    let validator_count: usize = fixture.network.validators.len();
    assert!(validator_count > 0);
    assert_eq!(endpoints.len(), validator_count);
    let expected_pairs: usize = rounds.checked_mul(validator_count).unwrap();
    let pre_certificate_phase: String = format!("skipped:{}", hex(b"certificate not sent yet"));
    let mut pre_certificate_count: usize = 0;
    let mut record_count: usize = 0;
    let mut previous_round: usize = 0;
    for line in results_text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [round, validator, endpoint, vote, certificate] = fields.as_slice() else {
            panic!("each persisted phase result has exact round/validator/endpoint attribution");
        };
        let round: usize = round.strip_prefix("round=").unwrap().parse().unwrap();
        assert!(round < rounds && round >= previous_round);
        if round > previous_round {
            assert_eq!(reports.len(), round.checked_mul(validator_count).unwrap());
            assert!(
                pre_certificate_votes.is_empty(),
                "every preceding round finished both phases"
            );
        }
        previous_round = round;
        let validator: &str = validator.strip_prefix("validator=").unwrap();
        let index: usize = fixture
            .network
            .validators
            .iter()
            .position(|member| hex(member.validator_id.as_bytes()) == validator)
            .unwrap();
        assert_eq!(
            endpoint.strip_prefix("endpoint_hex=").unwrap(),
            hex(endpoints[index].as_bytes())
        );
        let vote: &str = vote.strip_prefix("vote=").unwrap();
        let certificate: &str = certificate.strip_prefix("certificate=").unwrap();
        let key: (usize, usize) = (round, index);
        // Submit saves all vote phases before certificate fan-out; replay
        // saves each observe phase immediately before that peer's certificate.
        // Both retain exactly one initial and one final record per peer,
        // with configured peer order preserved independently in each phase.
        if certificate == pre_certificate_phase {
            assert!(
                !reports.contains_key(&key),
                "a completed peer phase cannot regress"
            );
            assert_eq!(
                key,
                (
                    pre_certificate_count / validator_count,
                    pre_certificate_count % validator_count
                ),
                "pre-certificate phases occur once in chronological round and configured peer order"
            );
            assert!(pre_certificate_votes.insert(key, vote.to_owned()).is_none());
            pre_certificate_count = pre_certificate_count.checked_add(1).unwrap();
        } else {
            assert!(
                certificate.starts_with("acknowledged:") || certificate.starts_with("rejected:"),
                "the final certificate phase is an actual acknowledgement or rejection, never skipped"
            );
            assert_eq!(
                key,
                (
                    reports.len() / validator_count,
                    reports.len() % validator_count
                ),
                "final phases occur once in chronological round and configured peer order"
            );
            let initial_vote: String = pre_certificate_votes
                .remove(&key)
                .expect("the exact pre-certificate record must precede its final phase");
            assert_eq!(
                vote, initial_vote,
                "the final phase preserves the exact original vote/observe bytes"
            );
            assert!(
                reports
                    .insert(key, (vote.to_owned(), certificate.to_owned()))
                    .is_none()
            );
        }
        record_count = record_count.checked_add(1).unwrap();
    }
    assert!(pre_certificate_votes.is_empty());
    assert_eq!(pre_certificate_count, expected_pairs);
    assert_eq!(reports.len(), expected_pairs);
    assert_eq!(record_count, expected_pairs.checked_mul(2).unwrap());
    reports
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
    seal_height: u64,
) {
    let voters: Vec<SqliteDurableStore> = clone_fixture_stores(fixture, env, "reply-loss-voter");
    let alignment: Vec<(OrderedProposal, QuorumCertificate)> =
        align_cloned_stores(fixture, env, &voters, seal_height);
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
    for (proposal, certificate) in &alignment {
        observe_proposal(&landed, &fixture.operation, env, proposal).unwrap();
        process_certificate(&landed, &fixture.operation, env, certificate).unwrap();
    }
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
    for (proposal, certificate) in &alignment {
        observe_proposal(&unlanded, &fixture.operation, env, proposal).unwrap();
        process_certificate(&unlanded, &fixture.operation, env, certificate).unwrap();
    }
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

/// One real compiled sqlite_source_host process, over its own isolated
/// clone file; dropping it kills and reaps the child.
struct CompiledSourceHost {
    child: std::process::Child,
    address: std::net::SocketAddr,
    generation: u64,
}
impl Drop for CompiledSourceHost {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

fn compiled_host_field(line: &str, key: &str) -> String {
    line.split_whitespace()
        .find_map(|token: &str| token.strip_prefix(key))
        .unwrap_or_else(|| panic!("compiled source host line lacks {key}: {line}"))
        .to_owned()
}

#[allow(clippy::too_many_arguments)]
fn start_compiled_source_host(
    executables: &super::compiled_executable_snapshot::CompiledExecutableSnapshot,
    fixture: &Fixture,
    genesis: &Path,
    blob_db: &Path,
    state_db: &Path,
    key_file: &Path,
    validator_id: ValidatorId,
) -> CompiledSourceHost {
    let mut command = std::process::Command::new(&executables.sqlite_source_host);
    command.args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--validator-id",
        &hex(validator_id.as_bytes()),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        genesis.to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--signing-key-file",
        key_file.to_str().unwrap(),
        "--state-db",
        state_db.to_str().unwrap(),
        "--blob-db",
        blob_db.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--created-checkpoint",
        "1000",
        "--timeout-seconds",
        "30",
        "--max-concurrent",
        "4",
        "--confirm-offline-fence-advance",
    ]);
    let startup_deadline: Duration = Duration::from_secs(30);
    let (mut guard, line) =
        compiled_source_host_process::spawn_bounded_status_line(command, startup_deadline);
    if line.is_empty() {
        panic!(
            "sqlite-source-host exited before serving: {:?}",
            guard.try_wait()
        );
    }
    assert!(line.contains("complete=true mode=serving"), "{line}");
    CompiledSourceHost {
        address: compiled_host_field(&line, "listen=").parse().unwrap(),
        generation: compiled_host_field(&line, "writer_generation=")
            .parse()
            .unwrap(),
        child: guard.into_inner(),
    }
}

/// Builds a context against this clone's own currently persisted writer
/// fence, never `fixture.operation`'s original fence: the compiled host's
/// own exclusive claim has made that original fence genuinely stale for
/// this clone, and reusing it would make a post-claim read wrongly appear
/// fenced rather than proving the real current state.
fn fresh_clone_context(
    store: &SqliteDurableStore,
    correlation: [u8; 16],
) -> DurableOperationContext {
    let current_fence: WriterFenceGeneration = store.writer_fence().unwrap();
    let deadline_millis: u64 = SystemClock
        .now_unix_millis()
        .unwrap()
        .checked_add(60_000)
        .unwrap();
    DurableOperationContext::new(
        current_fence,
        StorageDeadline::new(deadline_millis).unwrap(),
        StorageCorrelationId::new(correlation).unwrap(),
    )
}

/// One complete, independently re-readable snapshot of a compiled source
/// host clone's real Seal evidence: the full business snapshot (every
/// record, referenced blob and the backend snapshot token), the exact
/// receipt, the exact committed outcome and the exact sealed barrier.
struct CompiledSealCapture {
    snapshot: SourceBusinessSnapshot,
    receipt: DurableRequestReceipt,
    outcome: OrderedOutcome,
    barrier: SealBarrier,
}

/// Raw storage-port observation fidelity only. The canonical blob-backed row
/// is committed through the real SQLite runtime, but this does not claim a
/// paid producer, Seal execution or authenticated business reconstruction.
/// In particular, it does not plant new rows in the genuine Seal fixture.
#[test]
fn compiled_clone_snapshot_observes_nonempty_actual_blob_closure() {
    use hashing::{BuiltinHashFunction, HashFunction};
    use node_core::{NodeDedupRecord, RequestId};
    use objects::{Address, Object, ObjectId, Owner};
    use protocol_types::{
        AtomicityDomainId, ChainId, HashAlgorithmId, HashPurpose, ProtocolVersion,
    };
    use runtime::{
        BlobStore, DurableCommitOutcome, DurableInvocationTransaction, DurableObjectChanges,
        DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
        DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
        DurableObjectRoutingProjection, DurableObjectVersion, DurableObjectVersionRecord,
    };
    use rusqlite::{Connection, params};

    let directory: super::fixture::Directory =
        super::fixture::Directory::new("compiled-clone-observer-port");
    let source_blob_path: PathBuf = directory.0.join("original-blobs.sqlite");
    let clone_blob_path: PathBuf = directory.0.join("served-blobs.sqlite");
    let chain: ChainId = ChainId::new("compiled-clone-observer-port").unwrap();
    let protocol: ProtocolVersion = ProtocolVersion::new(1);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xC1; 32]).unwrap();
    let validator: ValidatorId = ValidatorId::new([0xC2; 32]);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let namespace: SqliteNamespace = SqliteNamespace::new(chain.clone(), validator, domain);
    let store: SqliteDurableStore =
        SqliteDurableStore::open(directory.0.join("state.sqlite"), namespace, fence).unwrap();
    let context: DurableOperationContext = fresh_clone_context(&store, [0xC3; 16]);
    let object_id: ObjectId = ObjectId::new([0xC4; 32]);
    let owner: Owner = Owner::Address(Address::new([0xC5; 32]));
    let object: Object = Object {
        id: object_id,
        version: 1,
        owner: owner.clone(),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xC6; 32]),
        schema_version: 1,
        data: vec![0xC7; 70 * 1024],
    };
    let canonical: Vec<u8> = objects::encode_object(&object).unwrap();
    let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(HashPurpose::Object, protocol, &chain, &canonical)
        .unwrap();
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        digest,
        object.schema_version,
        DurableObjectProvenance::new(chain, protocol),
        10,
        digest,
    );
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
            },
        )],
    )
    .unwrap();
    let request: RequestId = RequestId::new([0xC8; 32]).unwrap();
    let canonical_receipt: Vec<u8> = NodeDedupRecord::new(request, digest, Vec::new())
        .unwrap()
        .encode()
        .unwrap();
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(*request.as_bytes()).unwrap(),
        digest,
        canonical_receipt,
    )
    .unwrap();
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    let original_writer: SqliteBlobStore = SqliteBlobStore::open(&source_blob_path).unwrap();
    original_writer.put_blob(digest, canonical.clone()).unwrap();
    assert_eq!(
        store.commit_invocation(&context, invocation),
        DurableCommitOutcome::Committed
    );
    drop(original_writer);
    clone_sqlite_store_files(&source_blob_path, &clone_blob_path);
    let original: SqliteBlobStore = SqliteBlobStore::open_existing(&source_blob_path).unwrap();
    let served: SqliteBlobStore = SqliteBlobStore::open_existing(&clone_blob_path).unwrap();
    let capture =
        |blobs: &SqliteBlobStore| -> Result<SourceBusinessSnapshot, Box<dyn std::error::Error>> {
            capture_source_business_snapshot(
                &store,
                blobs,
                &context,
                domain,
                NonZeroUsize::new(128).unwrap(),
            )
        };
    let baseline: SourceBusinessSnapshot = capture(&served).unwrap();
    baseline.validate().unwrap();
    assert_eq!(
        baseline.referenced_blobs,
        BTreeMap::from([(digest, canonical.clone())])
    );
    assert_eq!(capture(&original).unwrap(), baseline);

    // Change only the exact served copy. Same-length corruption is observable
    // data, not an observer-level digest check or authenticated execution.
    let tamper: Connection = Connection::open(&clone_blob_path).unwrap();
    let mut corrupted: Vec<u8> = canonical.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(
        tamper
            .execute(
                "UPDATE blobs SET content = ?1 WHERE digest_algorithm = ?2 AND digest_bytes = ?3",
                params![
                    corrupted,
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice()
                ],
            )
            .unwrap(),
        1
    );
    let changed: SourceBusinessSnapshot = capture(&served).unwrap();
    assert_eq!(changed.records, baseline.records);
    assert_eq!(changed.token, baseline.token);
    assert_ne!(changed.referenced_blobs, baseline.referenced_blobs);
    assert_eq!(capture(&original).unwrap(), baseline);

    assert_eq!(
        tamper
            .execute(
                "DELETE FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice()
                ],
            )
            .unwrap(),
        1
    );
    let missing: String = capture(&served).unwrap_err().to_string();
    assert!(missing.contains("referenced blob is missing"), "{missing}");
    assert_eq!(capture(&original).unwrap(), baseline);
}

fn capture_compiled_seal_state(
    store: &SqliteDurableStore,
    cloned_blobs: &SqliteBlobStore,
    fixture: &Fixture,
    env: &OrderedEconomicsEnvironment<'_>,
    request: DurableRequestId,
    candidate_request_id: &[u8; 32],
    correlation: [u8; 16],
) -> CompiledSealCapture {
    let context: DurableOperationContext = fresh_clone_context(store, correlation);
    let barrier = store
        .get_outgoing_barrier(&context, fixture.network.domain)
        .unwrap();
    let OutgoingBarrier::Sealed(sealed) = barrier else {
        panic!("every real compiled source host must persist the real Seal");
    };
    let receipt: DurableRequestReceipt = store
        .get_request_receipt(&context, fixture.network.domain, request)
        .unwrap()
        .expect("the real Seal completion leaves an exact receipt");
    let outcome: OrderedOutcome = query_ordered_outcome(store, &context, env, candidate_request_id)
        .unwrap()
        .expect("the real Seal completion leaves an exact committed outcome");
    let snapshot: SourceBusinessSnapshot = capture_source_business_snapshot(
        store,
        cloned_blobs,
        &context,
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    CompiledSealCapture {
        snapshot,
        receipt,
        outcome,
        barrier: sealed,
    }
}

/// Genuine compiled four-source-host positive Seal acceptance (DR-0192).
///
/// The exact readiness-certified Seal candidate conditional_readiness_sqlite
/// already assembled is driven to completion over four real compiled
/// sqlite_source_host child processes and the real sunrise_edge_cli library
/// network-submit/-replay entrypoint, not the separate compiled CLI binary,
/// which this operator test cannot assume another package build exposes as
/// a CARGO_BIN_EXE env var. Every host opens its own isolated quiescent
/// clone of the live post-Drain source plus a shared immutable blob clone,
/// so the live fixture, which the in-process network below still drives
/// for itself through SealWarrantFault, completion reply-loss and the
/// competing branch, is never touched. That is checked here by an exact
/// pre/post business-snapshot and Unsealed-barrier comparison on the live
/// stores, not merely on the clones.
pub(super) fn run_compiled_four_host_seal(
    executables: &super::compiled_executable_snapshot::CompiledExecutableSnapshot,
    fixture: &Fixture,
    candidate_path: &Path,
    candidate: &OrderedCandidate,
) {
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

    let root: PathBuf = fixture.directory.0.join("compiled-four-host-seal");
    std::fs::create_dir(&root).unwrap();
    let genesis: PathBuf = root.join("genesis.bin");
    std::fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    let blob_db: PathBuf = root.join("blobs.sqlite");
    clone_sqlite_store_files(&fixture.directory.0.join("blobs.sqlite"), &blob_db);
    // Observe the exact file all compiled hosts serve, not the untouched
    // original fixture. This handle is existing-only and read-only.
    let cloned_blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();

    let mut key_files: Vec<PathBuf> = Vec::new();
    let mut state_dbs: Vec<PathBuf> = Vec::new();
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let key_path: PathBuf = root.join(format!("source-host-{index}.key"));
        std::fs::write(&key_path, validator.seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        key_files.push(key_path);
        let state_path: PathBuf = root.join(format!("state-{index}.sqlite"));
        clone_sqlite_store_files(
            &fixture.directory.0.join(format!("state-{index}.sqlite")),
            &state_path,
        );
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            validator.validator_id,
            fixture.network.domain,
        );
        let cloned: SqliteDurableStore =
            SqliteDurableStore::open_existing(&state_path, namespace).unwrap();
        assert_eq!(
            capture_source_business_snapshot(
                &cloned,
                &cloned_blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            before[index],
            "the isolated clone starts out exactly identical to its live source"
        );
        assert_eq!(
            cloned
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed
        );
        drop(cloned);
        state_dbs.push(state_path);
    }

    let hosts: Vec<CompiledSourceHost> = (0..4)
        .map(|index: usize| {
            start_compiled_source_host(
                executables,
                fixture,
                &genesis,
                &blob_db,
                &state_dbs[index],
                &key_files[index],
                fixture.network.validators[index].validator_id,
            )
        })
        .collect();
    for host in &hosts {
        assert_eq!(
            host.generation, 2,
            "the first real claim of each fresh isolated clone is exactly generation 2"
        );
    }

    let mut peers: String = String::new();
    for (validator, host) in fixture.network.validators.iter().zip(&hosts) {
        peers.push_str(&format!(
            "{} {} - -\n",
            hex(validator.validator_id.as_bytes()),
            host.address
        ));
    }
    let network: PathBuf = root.join("seal-network.conf");
    std::fs::write(&network, peers).unwrap();

    let prefix: PathBuf = root.join("compiled-seal-submission");
    let submit_args: Vec<OsString> = arguments(
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
    sunrise_edge_cli::run(submit_args).unwrap();

    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
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
    let initial_status: OrderedStatus =
        query_status(&fixture.stores[0], &fixture.operation, &env).unwrap();
    let endpoints: Vec<String> = hosts.iter().map(|host| host.address.to_string()).collect();
    let rounds: Vec<(OrderedProposal, QuorumCertificate)> = saved_submission_rounds(
        fixture,
        candidate_path,
        &prefix,
        candidate,
        &initial_status.high_qc,
    );
    let submission_results: BTreeMap<(usize, usize), (String, String)> =
        saved_peer_results(fixture, &prefix, &endpoints, rounds.len());
    for (round, (_, certificate)) in rounds.iter().enumerate() {
        for (index, validator) in fixture.network.validators.iter().enumerate() {
            let (vote_phase, certificate_phase) = &submission_results[&(round, index)];
            let voted: OrderedEventOutput = acknowledged_output(vote_phase);
            assert!(voted.committed.is_empty());
            assert!(
                voted.messages.iter().any(|message| {
                    if let ConsensusMessage::Vote(vote) = message {
                        fixture
                            .policy
                            .engine()
                            .verify_vote(vote, &Verifier)
                            .unwrap();
                        vote.validator == validator.validator_id
                            && vote.height == certificate.height
                            && vote.view == certificate.view
                            && vote.proposal_digest == certificate.proposal_digest
                    } else {
                        false
                    }
                }),
                "the saved acknowledgement attributes the actual signed vote to its configured peer and round"
            );
            let certified: OrderedEventOutput = acknowledged_output(certificate_phase);
            assert!(certified.messages.is_empty());
            if round == rounds.len() - 1 {
                assert_eq!(certified.committed.len(), 1);
                assert_eq!(certified.committed[0].request_id, candidate.request_id);
            } else {
                assert!(certified.committed.is_empty());
            }
        }
    }

    let request: DurableRequestId = DurableRequestId::new(candidate.request_id).unwrap();
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

    // Captured immediately after network-submit, while the four real
    // compiled host processes are still running: open_historical bypasses
    // the live Sealed-open refusal, but every read still goes through a
    // context built from this clone's own actual current writer fence.
    let after_submit: Vec<CompiledSealCapture> = state_dbs
        .iter()
        .enumerate()
        .map(|(index, state_path): (usize, &PathBuf)| {
            let namespace: SqliteNamespace = SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                fixture.network.validators[index].validator_id,
                fixture.network.domain,
            );
            let historical: SqliteDurableStore =
                SqliteDurableStore::open_historical(state_path, namespace).unwrap();
            capture_compiled_seal_state(
                &historical,
                &cloned_blobs,
                fixture,
                &env,
                request,
                &candidate.request_id,
                [0x53; 16],
            )
        })
        .collect();
    let candidate_digest: Digest32 = fixture.policy.candidate_digest(candidate).unwrap();
    for (index, capture) in after_submit.iter().enumerate() {
        assert_eq!(capture.barrier.request, candidate.request_id);
        if index > 0 {
            assert_eq!(
                capture.barrier, after_submit[0].barrier,
                "every real compiled source host agrees on the exact same Seal barrier"
            );
            assert_eq!(
                capture.receipt, after_submit[0].receipt,
                "all four actual Seal receipts are byte-for-byte identical"
            );
        }
        assert_eq!(capture.outcome.request_id, candidate.request_id);
        assert_eq!(capture.outcome.candidate_digest, candidate_digest);
        assert_eq!(capture.outcome.block_height, capture.barrier.height);
        assert_eq!(capture.outcome.block_digest, capture.barrier.block_digest);
        let payload = capture.outcome.output.responses()[0].payload().unwrap();
        let decoded = decode_seal_outcome(payload).unwrap();
        assert_eq!(decoded.target, capture.barrier.target_digest);
        assert_eq!(decoded.request, candidate.request_id);
        assert_eq!(
            business(&capture.snapshot),
            business(&before[index]),
            "Seal has no object or fee effects on the real compiled clone either"
        );
        for original in before[index]
            .records
            .iter()
            .filter(|row| matches!(row.descriptor.key(), DurableRecordKey::Receipt(_)))
        {
            assert!(
                capture.snapshot.records.contains(original),
                "original business receipt never changes"
            );
        }
    }

    let manifest: PathBuf = PathBuf::from(format!("{}.manifest", prefix.display()));
    let replay_prefix: PathBuf = root.join("compiled-seal-replay");
    let replay_args: Vec<OsString> = arguments(
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
    sunrise_edge_cli::run(replay_args).unwrap();
    let replay_results: BTreeMap<(usize, usize), (String, String)> =
        saved_peer_results(fixture, &replay_prefix, &endpoints, rounds.len());
    for (observe_phase, certificate_phase) in replay_results.values() {
        let observed: OrderedEventOutput = acknowledged_output(observe_phase);
        let certified: OrderedEventOutput = acknowledged_output(certificate_phase);
        assert!(observed.messages.is_empty() && observed.committed.is_empty());
        assert!(certified.messages.is_empty() && certified.committed.is_empty());
    }

    // Captured again, still while every host process remains running, with
    // a distinct correlation id so this is a genuinely independent fresh
    // read, not a cached one; an exact network-replay must change none of
    // it.
    let after_replay: Vec<CompiledSealCapture> = state_dbs
        .iter()
        .enumerate()
        .map(|(index, state_path): (usize, &PathBuf)| {
            let namespace: SqliteNamespace = SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                fixture.network.validators[index].validator_id,
                fixture.network.domain,
            );
            let historical: SqliteDurableStore =
                SqliteDurableStore::open_historical(state_path, namespace).unwrap();
            capture_compiled_seal_state(
                &historical,
                &cloned_blobs,
                fixture,
                &env,
                request,
                &candidate.request_id,
                [0x52; 16],
            )
        })
        .collect();
    for index in 0..after_replay.len() {
        assert_eq!(
            after_replay[index].snapshot.token.mutation_sequence(),
            after_submit[index].snapshot.token.mutation_sequence(),
            "exact network-replay does not advance the physical mutation sequence"
        );
        assert_eq!(
            after_replay[index].snapshot, after_submit[index].snapshot,
            "exact network-replay changes no record, blob or snapshot token"
        );
        assert_eq!(
            after_replay[index].receipt, after_submit[index].receipt,
            "exact network-replay changes no receipt byte"
        );
        assert_eq!(
            after_replay[index].barrier, after_submit[index].barrier,
            "exact network-replay changes no barrier byte"
        );
        assert_eq!(
            after_replay[index].outcome, after_submit[index].outcome,
            "exact network-replay changes no outcome byte"
        );
    }

    for host in hosts {
        drop(host);
    }

    // DR-0192: a fresh new-source startup against the now-Sealed clone
    // refuses before serving: no listener, no status line. Bounded: any
    // timeout, malformed exit or IO error still kills and reaps the real
    // process instead of hanging, since the child is owned by the shared
    // guard before its stdout/stderr are even taken.
    let refusal_key: PathBuf = root.join("fresh-refusal.key");
    std::fs::write(&refusal_key, fixture.network.validators[0].seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&refusal_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut refusal_command = std::process::Command::new(&executables.sqlite_source_host);
    refusal_command.args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--validator-id",
        &hex(fixture.network.validators[0].validator_id.as_bytes()),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        genesis.to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--signing-key-file",
        refusal_key.to_str().unwrap(),
        "--state-db",
        state_dbs[0].to_str().unwrap(),
        "--blob-db",
        blob_db.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--created-checkpoint",
        "1000",
        "--timeout-seconds",
        "30",
        "--max-concurrent",
        "4",
        "--confirm-offline-fence-advance",
    ]);
    let refusal: std::process::Output = compiled_source_host_process::spawn_bounded_output(
        refusal_command,
        Duration::from_secs(30),
    );
    assert!(
        !refusal.status.success(),
        "a fresh open against an already-Sealed namespace must refuse, not serve"
    );
    assert!(
        refusal.stdout.is_empty(),
        "a refused startup never reaches its listener status line"
    );
    assert!(
        String::from_utf8_lossy(&refusal.stderr).contains("already Sealed"),
        "{}",
        String::from_utf8_lossy(&refusal.stderr)
    );

    for (index, store) in fixture.stores.iter().enumerate() {
        assert_eq!(
            capture_source_business_snapshot(
                store,
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            before[index],
            "the live post-Drain source is completely untouched by the isolated compiled-host Seal"
        );
        assert_eq!(
            store
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed,
            "the live source stays Unsealed: only its isolated clone was ever driven to Seal"
        );
    }
}

pub(super) async fn run(
    fixture: &mut Fixture,
    candidate_path: &Path,
    candidate: &OrderedCandidate,
    competing_candidate: &OrderedCandidate,
    successor: &super::successor_host_acceptance::SuccessorProcessInputs,
) {
    let fence: WriterFenceGeneration = fixture.operation.writer_fence();
    let mut stores: Vec<Arc<SqliteDurableStore>> = Vec::new();
    let mut ports: Vec<Arc<SealWarrantFaultStore>> = Vec::new();
    let mut servers = Vec::new();
    let mut stops = Vec::new();
    let mut peers: String = String::new();
    let mut endpoints: Vec<String> = Vec::new();
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
    assert_eq!(
        initial_status.high_qc.height,
        initial_status.committed_height.checked_add(2).unwrap(),
        "the genuine post-Drain source has both certified descendants"
    );
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
    // Genuine landed-versus-unlanded completion reply-loss, entirely on
    // isolated clones of this exact pre-Seal state -- never on the four
    // live validators the rest of this acceptance drives below.
    verify_completion_reply_loss(fixture, &env, candidate, seal_height);
    // DR-0187: build a genuine, real-signed competing Seal proposal before
    // any commitment lands. It targets the exact same height as the
    // accepted candidate but is never admitted by a quorum, so it stays a
    // genuinely uncompleted, pending request. This hypothetical competing
    // branch belongs to independently checked quiescent clones, so it cannot
    // consume the live source's leader slot, own vote or HTTP alignment.
    let competing_stores: Vec<SqliteDurableStore> =
        clone_fixture_stores(fixture, &env, "competing-voter");
    let competing_alignment: Vec<(OrderedProposal, QuorumCertificate)> =
        align_cloned_stores(fixture, &env, &competing_stores, seal_height);
    let competing_status =
        node_core::ordered_economics::query_status(&competing_stores[0], &fixture.operation, &env)
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
        &competing_stores[leader_index],
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
        &competing_stores[leader_index],
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
    let competing_vote_output: OrderedEventOutput = process_proposal(
        &competing_stores[leader_index],
        &fixture.operation,
        &env,
        &competing_proposal,
        &leader_signer,
    )
    .unwrap();
    let competing_own_vote: ConsensusVote = competing_vote_output
        .messages
        .iter()
        .find_map(|message| match message {
            ConsensusMessage::Vote(vote) => Some(vote.clone()),
            _ => None,
        })
        .unwrap();
    fixture
        .policy
        .engine()
        .verify_vote(&competing_own_vote, &Verifier)
        .unwrap();
    assert_eq!(competing_own_vote.validator, leader_id);
    assert_eq!(
        competing_own_vote.proposal_digest,
        fixture
            .policy
            .engine()
            .proposal_digest(&competing_proposal.proposal)
            .unwrap()
    );
    let repeated_competing_vote: OrderedEventOutput = process_proposal(
        &competing_stores[leader_index],
        &fixture.operation,
        &env,
        &competing_proposal,
        &leader_signer,
    )
    .unwrap();
    assert!(
        repeated_competing_vote
            .messages
            .contains(&ConsensusMessage::Vote(competing_own_vote))
    );
    // Query real status after the leader's own cast vote -- never assume
    // casting it advanced the view. Verify it actually did (the engine's
    // own vote-processing sets current_view >= proposal.view + 1
    // unconditionally); if it somehow had not, the competing leader slot
    // would remain occupied and this assertion catches that directly.
    let target_view = query_status(&competing_stores[leader_index], &fixture.operation, &env)
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
        let behind_view = query_status(&competing_stores[index], &fixture.operation, &env)
            .unwrap()
            .current_view;
        if behind_view < target_view {
            let signer = Signer {
                id: validator.validator_id,
                key: validator.signing_key,
            };
            let now_unix_millis = SystemClock.now_unix_millis().unwrap();
            process_tick(
                &competing_stores[index],
                &fixture.operation,
                &env,
                now_unix_millis,
                &signer,
            )
            .unwrap();
        }
        assert_eq!(
            query_status(&competing_stores[index], &fixture.operation, &env)
                .unwrap()
                .current_view,
            target_view,
            "every isolated competing validator reaches the same real-clock target view"
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
        endpoints.push(address.to_string());
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
    for (index, store) in stores.iter().enumerate() {
        assert_eq!(
            query_status(store.as_ref(), &fixture.operation, &env).unwrap(),
            initial_status,
            "no direct alignment, competing vote or Tick changes a live post-Drain validator before network-submit"
        );
        assert_eq!(
            capture_source_business_snapshot(
                store.as_ref(),
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            before[index],
            "every live source row, receipt, referenced blob, token and fence remains at its original post-Drain state"
        );
        assert_eq!(
            store
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed
        );
    }
    tokio::task::spawn_blocking(move || sunrise_edge_cli::run(submit_args))
        .await
        .unwrap()
        .unwrap();
    let rounds: Vec<(OrderedProposal, QuorumCertificate)> = saved_submission_rounds(
        fixture,
        candidate_path,
        &prefix,
        candidate,
        &initial_status.high_qc,
    );
    assert_eq!(competing_alignment.len(), 1);
    for parent in [&competing_alignment[0].1, &competing_status.high_qc] {
        assert_eq!(parent.proposal_digest, rounds[0].1.proposal_digest);
        assert_eq!(parent.height, rounds[0].1.height);
        assert_eq!(parent.view, rounds[0].1.view);
    }
    let submission_results: BTreeMap<(usize, usize), (String, String)> =
        saved_peer_results(fixture, &prefix, &endpoints, rounds.len());
    for (round, (_, certificate)) in rounds.iter().enumerate() {
        for (index, validator) in fixture.network.validators.iter().enumerate() {
            let (vote_phase, certificate_phase) = &submission_results[&(round, index)];
            let voted: OrderedEventOutput = acknowledged_output(vote_phase);
            assert!(voted.committed.is_empty());
            assert!(
                voted.messages.iter().any(|message| {
                    if let ConsensusMessage::Vote(vote) = message {
                        fixture
                            .policy
                            .engine()
                            .verify_vote(vote, &Verifier)
                            .unwrap();
                        vote.validator == validator.validator_id
                            && vote.height == certificate.height
                            && vote.view == certificate.view
                            && vote.proposal_digest == certificate.proposal_digest
                    } else {
                        false
                    }
                }),
                "the saved acknowledgement attributes the actual signed vote to its configured peer and round"
            );
            if round == rounds.len() - 1 && index != 0 {
                assert!(certificate_phase.starts_with("rejected:"));
                continue;
            }
            let certified: OrderedEventOutput = acknowledged_output(certificate_phase);
            assert!(certified.messages.is_empty());
            if round == rounds.len() - 1 {
                assert_eq!(certified.committed.len(), 1);
                assert_eq!(certified.committed[0].request_id, candidate.request_id);
                assert_eq!(
                    certified.committed[0].block_height,
                    rounds[1].0.proposal.height
                );
                assert_eq!(
                    certified.committed[0].block_digest,
                    rounds[1].1.proposal_digest
                );
                assert_eq!(
                    certified.committed[0].candidate_digest,
                    fixture.policy.candidate_digest(candidate).unwrap()
                );
                assert_eq!(
                    query_ordered_outcome(
                        stores[index].as_ref(),
                        &fixture.operation,
                        &env,
                        &candidate.request_id
                    )
                    .unwrap(),
                    Some(certified.committed[0].clone()),
                    "the CLI's saved healthy acknowledgement matches the actual persisted Seal outcome"
                );
            } else {
                assert!(
                    certified.committed.is_empty(),
                    "alignment and earlier QCs cannot acknowledge Seal completion"
                );
            }
        }
    }
    assert_eq!(ports[0].fault_hits(), 0);
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
    let catchup_results: BTreeMap<(usize, usize), (String, String)> =
        saved_peer_results(fixture, &catchup_prefix, &endpoints, rounds.len());
    for ((round, index), (observe_phase, certificate_phase)) in &catchup_results {
        let observed: OrderedEventOutput = acknowledged_output(observe_phase);
        let certified: OrderedEventOutput = acknowledged_output(certificate_phase);
        assert!(
            observed.messages.is_empty() && certified.messages.is_empty(),
            "actual HTTP recovery is signerless"
        );
        assert!(observed.committed.is_empty());
        if *round == rounds.len() - 1 && *index != 0 {
            assert_eq!(certified.committed.len(), 1);
            assert_eq!(certified.committed[0].request_id, candidate.request_id);
            assert_eq!(
                certified.committed[0].block_height,
                rounds[1].0.proposal.height
            );
            assert_eq!(
                certified.committed[0].block_digest,
                rounds[1].1.proposal_digest
            );
        } else {
            assert!(certified.committed.is_empty());
        }
    }
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
    let proposal: &OrderedProposal = &rounds[1].0;
    for (index, store) in stores.iter().enumerate() {
        let signer = Signer {
            id: fixture.network.validators[index].validator_id,
            key: fixture.network.validators[index].signing_key,
        };
        // Replaying the exact committed Seal proposal is a legal original
        // reconciliation: it is the identical already-completed request, so
        // this is AlreadyCompleted, never a fresh barrier exposure.
        match process_proposal(store.as_ref(), &fixture.operation, &env, proposal, &signer) {
            Err(OrderedEconomicsError::AlreadyCompleted(outcome)) => {
                assert_eq!(outcome.block_height, agreed.unwrap().height);
            }
            other => panic!(
                "exact-original Seal proposal replay must reconcile as already completed, got {other:?}"
            ),
        }
    }
    for (index, store) in competing_stores.iter().enumerate() {
        assert_eq!(
            store
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed
        );
        assert!(
            query_ordered_outcome(
                store,
                &fixture.operation,
                &env,
                &competing_candidate.request_id
            )
            .unwrap()
            .is_none()
        );
        // Apply the exact saved HTTP/CLI branch to the hypothetical pending
        // stores through the real observer. No clone votes for that branch;
        // its genuine Seal completion comes only from the CLI's real QCs.
        for (round, (selected, certificate)) in rounds.iter().enumerate() {
            let observed: OrderedEventOutput =
                observe_proposal(store, &fixture.operation, &env, selected).unwrap();
            let certified: OrderedEventOutput =
                process_certificate(store, &fixture.operation, &env, certificate).unwrap();
            assert!(observed.messages.is_empty() && certified.messages.is_empty());
            assert!(observed.committed.is_empty());
            if round == rounds.len() - 1 {
                assert_eq!(certified.committed.len(), 1);
                assert_eq!(certified.committed[0].request_id, candidate.request_id);
                assert_eq!(
                    certified.committed[0].block_height,
                    rounds[1].0.proposal.height
                );
                assert_eq!(
                    certified.committed[0].block_digest,
                    rounds[1].1.proposal_digest
                );
            } else {
                assert!(certified.committed.is_empty());
            }
        }
        assert_eq!(
            store
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Sealed(agreed.unwrap())
        );
        assert_eq!(
            query_ordered_outcome(store, &fixture.operation, &env, &candidate.request_id).unwrap(),
            query_ordered_outcome(
                stores[index].as_ref(),
                &fixture.operation,
                &env,
                &candidate.request_id
            )
            .unwrap(),
            "a competing clone completes the same selected Seal, not its pending request"
        );
        // A distinct request with a genuinely retained leader/own vote
        // remains uncompleted. The retained-signature path must Stop at the
        // barrier rather than return a cached vote or AlreadyCompleted.
        assert!(
            query_ordered_outcome(
                store,
                &fixture.operation,
                &env,
                &competing_candidate.request_id
            )
            .unwrap()
            .is_none(),
            "the competing branch was never admitted to completion"
        );
        assert!(
            store
                .get_request_receipt(
                    &fixture.operation,
                    fixture.network.domain,
                    DurableRequestId::new(competing_candidate.request_id).unwrap(),
                )
                .unwrap()
                .is_none()
        );
        let before_stop: SourceBusinessSnapshot = capture_source_business_snapshot(
            store,
            &fixture.blobs,
            &fixture.operation,
            fixture.network.domain,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        let signer = Signer {
            id: fixture.network.validators[index].validator_id,
            key: fixture.network.validators[index].signing_key,
        };
        match process_proposal(
            store,
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
        assert_eq!(
            capture_source_business_snapshot(
                store,
                &fixture.blobs,
                &fixture.operation,
                fixture.network.domain,
                NonZeroUsize::new(128).unwrap(),
            )
            .unwrap(),
            before_stop,
            "blocked cached competing work changes no token, fence, record or receipt"
        );
        assert_eq!(
            store
                .get_outgoing_barrier(&fixture.operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Sealed(agreed.unwrap())
        );
    }
    drop(competing_stores);
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
    let replay_results: BTreeMap<(usize, usize), (String, String)> =
        saved_peer_results(fixture, &replay_prefix, &endpoints, rounds.len());
    for (observe_phase, certificate_phase) in replay_results.values() {
        let observed: OrderedEventOutput = acknowledged_output(observe_phase);
        let certified: OrderedEventOutput = acknowledged_output(certificate_phase);
        assert!(observed.messages.is_empty() && observed.committed.is_empty());
        assert!(certified.messages.is_empty() && certified.committed.is_empty());
    }
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
    fixture.stores.clear(); // True close of every live state-{index} handle.
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
    // Every outgoing assertion above stays intact; the sealed files are now
    // only historical. The positive first-successor process acceptance runs
    // inside this lifetime over the same genuine sealed source.
    let (original_proposal, original_certificate): &(OrderedProposal, QuorumCertificate) = rounds
        .last()
        .expect("the actual original TCP submission retained its certified suffix");
    assert_eq!(original_proposal.proposal.epoch, fixture.network.epoch);
    assert_eq!(original_certificate.epoch, fixture.network.epoch);
    assert_eq!(
        original_proposal.proposal.chain_id,
        fixture.network.chain_id
    );
    assert_eq!(original_certificate.chain_id, fixture.network.chain_id);
    let original_round: (Vec<u8>, Vec<u8>) = (
        node_core::ordered_economics::encode_ordered_proposal(original_proposal).unwrap(),
        consensus::encode_quorum_certificate(original_certificate).unwrap(),
    );
    super::successor_host_acceptance::run(&*fixture, successor, candidate, fence, &original_round)
        .await;
}
