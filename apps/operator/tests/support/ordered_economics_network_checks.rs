//! Real network interruption/quorum/owned-path controls, with an independent
//! real FastVote positive control so unrelated admission failures cannot mask
//! the lock conflict under test.
use super::*;
use std::{
    io::Write,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use sunrise_edge_client::ordered_economics_client::{
    ArtifactSink, OrderedEconomicsEndpoint, OrderedEconomicsNetworkError,
};
use sunrise_edge_client::transport::{Method, Transport, WireRequest};
use sunrise_edge_client::{Client, LoopbackHttpTransport};

struct Signer {
    id: ValidatorId,
    key: SigningKey,
}
impl consensus::ConsensusSigner for Signer {
    fn validator_id(&self) -> ValidatorId {
        self.id
    }
    fn signature_scheme(&self) -> protocol_types::SignatureSchemeId {
        protocol_types::SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(frame).into();
        Ok(signature.to_vec())
    }
}

pub(super) fn transport(addr: std::net::SocketAddr) -> LoopbackHttpTransport {
    LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        NonZeroUsize::new(64 * 1024).unwrap(),
        NonZeroUsize::new(node_wire::ordered_economics::MAX_ORDERED_EVENT_OUTPUT_BYTES).unwrap(),
    )
    .unwrap()
}

fn endpoints(
    network: &Path,
    fixture: &FastVoteGenesisFixture,
) -> Vec<OrderedEconomicsEndpoint<LoopbackHttpTransport>> {
    fs::read_to_string(network)
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let validator_id: ValidatorId = fixture
                .validators
                .iter()
                .find(|validator| validator.validator_id.to_string() == fields[0])
                .expect("network endpoint must match the independently pinned fixture")
                .validator_id;
            OrderedEconomicsEndpoint {
                validator_id,
                endpoint_label: fields[1].to_owned(),
                client: Client::new(transport(fields[1].parse().unwrap())),
            }
        })
        .collect()
}

struct SavedSink<'a> {
    dir: &'a Path,
    label: &'a str,
    interrupt: bool,
}
impl ArtifactSink for SavedSink<'_> {
    fn persist(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        let path = self.dir.join(format!("{}.{}", self.label, name));
        let mut file = fs::File::create_new(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::File::open(self.dir)?.sync_all()?;
        if self.interrupt && name == "round-0.proposal" {
            return Err(std::io::Error::other(
                "test interruption after exact proposal persistence",
            ));
        }
        Ok(())
    }
}

pub(super) fn capture_proposal(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    dir: &Path,
    candidate: &OrderedCandidate,
) -> Vec<u8> {
    let policy = sunrise_edge_client::ordered_economics_client::load_trusted_ordered_policy(
        genesis,
        &fixture.resolver,
        fixture.manifest_digest,
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    let peers = endpoints(network, fixture);
    let bytes = encode_ordered_candidate(candidate).unwrap();
    let mut sink = SavedSink {
        dir,
        label: "fencing",
        interrupt: true,
    };
    let result = sunrise_edge_client::ordered_economics_client::submit_candidate(
        &peers,
        &policy,
        &bytes,
        None,
        Instant::now() + Duration::from_secs(90),
        Duration::from_secs(5),
        &mut sink,
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsNetworkError::Artifact(_))
    ));
    let bytes = fs::read(dir.join("fencing.round-0.proposal")).unwrap();
    let proposal = node_core::ordered_economics::decode_ordered_proposal(&bytes).unwrap();
    policy
        .engine()
        .verify_proposal(
            &proposal.proposal,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap();
    assert_eq!(proposal.candidate.as_ref(), Some(candidate));
    bytes
}

pub(super) fn observe_status(addr: std::net::SocketAddr, proposal: &[u8]) -> u16 {
    transport(addr)
        .send(&WireRequest {
            method: Method::Post,
            path: node_wire::ordered_economics::ORDERED_ECONOMICS_OBSERVE_PATH.into(),
            content_type: Some(node_wire::ordered_economics::ORDERED_PROPOSAL_MEDIA_TYPE),
            body: proposal.to_vec(),
            deadline: Some(Instant::now() + Duration::from_secs(5)),
        })
        .unwrap()
        .status
}

pub(super) fn reject_bad_prefixes_without_posts(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    genesis: &Path,
    manifest: &Path,
    live_addr: std::net::SocketAddr,
) {
    let policy = sunrise_edge_client::ordered_economics_client::load_trusted_ordered_policy(
        genesis,
        &fixture.resolver,
        fixture.manifest_digest,
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    let rounds: Vec<(Vec<u8>, Vec<u8>)> = fs::read_to_string(manifest)
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 2);
            (fs::read(fields[0]).unwrap(), fs::read(fields[1]).unwrap())
        })
        .collect();
    assert!(rounds.len() > 3);
    let relay = crate::support::http_relay::HttpRelay::new(live_addr);
    let peer = OrderedEconomicsEndpoint {
        validator_id: namespace.validator_id(),
        endpoint_label: relay.addr.to_string(),
        client: Client::new(transport(relay.addr)),
    };
    let baseline = snapshot(pool, namespace);
    let mut reordered = rounds.clone();
    reordered.swap(0, 1);
    let mut forged = rounds;
    let last = forged.last_mut().unwrap();
    let mut proposal = node_core::ordered_economics::decode_ordered_proposal(&last.0).unwrap();
    proposal.proposal.signature[0] ^= 1;
    last.0 = node_core::ordered_economics::encode_ordered_proposal(&proposal).unwrap();
    for bad in [reordered, forged] {
        assert!(matches!(
            sunrise_edge_client::ordered_economics_client::replay_declared_prefix(
                std::slice::from_ref(&peer),
                &policy,
                &bad,
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(5),
            ),
            Err(OrderedEconomicsNetworkError::Rejected(_))
        ));
        assert_eq!(relay.posts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(snapshot(pool, namespace), baseline);
    }
}

pub(super) fn reserve_and_check(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    network: &Path,
    genesis: &Path,
    dir: &Path,
    candidate: &OrderedCandidate,
) -> PathBuf {
    let policy = sunrise_edge_client::ordered_economics_client::load_trusted_ordered_policy(
        genesis,
        &fixture.resolver,
        fixture.manifest_digest,
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    let peers = endpoints(network, fixture);
    let bytes = encode_ordered_candidate(candidate).unwrap();
    let mut sink = SavedSink {
        dir,
        label: "interrupted",
        interrupt: true,
    };
    let interrupted = sunrise_edge_client::ordered_economics_client::submit_candidate(
        &peers,
        &policy,
        &bytes,
        None,
        Instant::now() + Duration::from_secs(90),
        Duration::from_secs(5),
        &mut sink,
    );
    assert!(matches!(
        interrupted,
        Err(OrderedEconomicsNetworkError::Artifact(_))
    ));
    let proposal_path = dir.join("interrupted.round-0.proposal");
    let proposal_bytes = fs::read(&proposal_path).unwrap();
    let proposal = node_core::ordered_economics::decode_ordered_proposal(&proposal_bytes).unwrap();
    policy
        .engine()
        .verify_proposal(
            &proposal.proposal,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap();
    let leader_index = fixture
        .validators
        .iter()
        .position(|v| v.validator_id == proposal.proposal.leader)
        .unwrap();
    assert!(leader_index < 3);

    // Build an ordinary address-owned paid transfer on the very same source
    // and nonce as Replace's deposit leg, not a custody transfer or bad sender.
    let signed =
        node_core::bond_lifecycle::decode_signed_bond_lifecycle_intent(&candidate.intent).unwrap();
    let node_core::bond_lifecycle::BondLifecycleOperation::Replace { deposit_leg, .. } =
        signed.intent.operation
    else {
        panic!("Replace expected")
    };
    let mut call = execution::local_execution::decode_signed_local_execution(&deposit_leg)
        .unwrap()
        .intent
        .call;
    let key = SigningKey::from([0x77; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    call.request_id = [0xEF; 32];
    call.gas_limit = 100_000;
    call.arguments = public_standard_asset::transfer_arguments(&sender).unwrap();
    let source = call.access.entries[0].object_ref.clone();
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let intent = execution::paid_execution::PaidIntent {
        context: fixture.context.clone(),
        request_id: call.request_id,
        sender,
        nonce: call.nonce,
        fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(
            &fixture.resolver,
            &manifest.fee_policy,
        )
        .unwrap(),
        consent: execution::paid_execution::FeeSourceConsent {
            source,
            access: execution::paid_execution::ReservationAccessKind::Write,
            max_fee: fees::Amount::new(100),
            refund_recipient: sender,
        },
        application: execution::paid_execution::PaidApplication::Call(call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame =
        execution::paid_execution::paid_intent_signing_frame(&fixture.context, &intent).unwrap();
    let paid_bytes = execution::paid_execution::encode_signed_paid_intent(
        &execution::paid_execution::SignedPaidIntent {
            intent,
            signature: key.sign(&frame).into(),
        },
    )
    .unwrap();
    let context = cli::read_context(pool, &namespaces[leader_index]);
    let control = runtime::MemoryDurableStateStore::new(context.writer_fence());
    node_core::install_genesis_with_history(
        &control,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &manifest,
        1,
    )
    .unwrap();
    let entry = &fixture.validators[leader_index];
    let signer = Signer {
        id: entry.validator_id,
        key: SigningKey::from(entry.seed),
    };
    let blobs = runtime::MemoryBlobStore::default();
    let engine = execution::LocalWasmExecutionEngine::new();
    let leg_policy = LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    node_core::fast_path::prepare(
        &control,
        &blobs,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        &leg_policy,
        &manifest.fee_policy,
        &engine,
        &signer,
        &paid_bytes,
        1,
    )
    .unwrap();
    let before: Vec<Snapshot> = namespaces.iter().map(|n| snapshot(pool, n)).collect();
    assert!(
        peers[leader_index]
            .client
            .prepare_fastvote(&paid_bytes, None)
            .is_err()
    );
    let error = node_core::fast_path::prepare(
        &store(pool, &namespaces[leader_index]),
        &PostgresBlobStore::new(pool.clone(), namespaces[leader_index].clone()).unwrap(),
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        &leg_policy,
        &manifest.fee_policy,
        &engine,
        &signer,
        &paid_bytes,
        1,
    )
    .unwrap_err();
    assert!(
        format!("{error}").contains("lock"),
        "must be the actual shared reservation conflict: {error}"
    );
    assert_eq!(
        before,
        namespaces
            .iter()
            .map(|n| snapshot(pool, n))
            .collect::<Vec<_>>()
    );

    // Two real votes cannot manufacture a three-of-four QC or business commit.
    let mut sink = SavedSink {
        dir,
        label: "no-quorum",
        interrupt: false,
    };
    let no_quorum = sunrise_edge_client::ordered_economics_client::submit_candidate(
        &peers[..2],
        &policy,
        &bytes,
        Some(proposal_bytes),
        Instant::now() + Duration::from_secs(30),
        Duration::from_secs(5),
        &mut sink,
    );
    assert!(matches!(
        no_quorum,
        Err(OrderedEconomicsNetworkError::QuorumNotFormed)
    ));
    for namespace in &namespaces[..3] {
        let id = runtime::DurableRequestId::new(candidate.request_id).unwrap();
        assert!(
            store(pool, namespace)
                .get_request_receipt(&cli::read_context(pool, namespace), fixture.domain, id)
                .unwrap()
                .is_none()
        );
        let next = node_core::query_sender_next_nonce(
            &store(pool, namespace),
            &cli::read_context(pool, namespace),
            fixture.domain,
            fixture.chain_id.clone(),
            fixture.protocol_version,
            fixture.epoch,
            sender,
        )
        .unwrap();
        assert_eq!(next, 0);
    }
    proposal_path
}
