//! Genuine outgoing Seal through the in-process public Rust CLI entrypoint
//! and four actual TCP routers; its return value is not captured stdout.
//! Mutable validator stores are independent SQLite files. Public immutable
//! artifacts share the fixture's blob repository; no completion is seeded.
use super::{fixture::Fixture, hex};
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
    OrderedProposal, decode_ordered_candidate, decode_ordered_event_output,
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
        vec![9, 10, 11, 12],
        "the actual HTTP/CLI path performs EMPTY9, Seal10 and EMPTY11/12 from original QC8"
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
        initial_status.high_qc.height, 8,
        "the genuine post-Drain source has QC8"
    );
    assert_eq!(initial_status.committed_height, 6);
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
    assert_eq!(seal_height, 10);
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
    super::successor_host_acceptance::run(&*fixture, successor, candidate, fence).await;
}
