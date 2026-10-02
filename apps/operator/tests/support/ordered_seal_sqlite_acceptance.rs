//! Genuine outgoing Seal through the public CLI and four actual TCP routers.
//! Mutable validator stores are independent SQLite files. Public immutable
//! artifacts share the fixture's blob repository; no completion is seeded.
use super::{fixture::Fixture, hex};
use consensus::ConsensusSigner;
use ed25519_zebra::SigningKey;
use execution::LocalWasmExecutionEngine;
use native_http::ordered_economics::{
    OrderedEconomicsState, OrderedSealHostComposition, certified_ordered_economics_router,
};
use native_http::{NativeBlockingExecutor, NativeBlockingPolicy};
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::ordered_economics::{
    OrderedCandidate, OrderedEconomicsEnvironment, OrderedProposal, decode_ordered_proposal,
    decode_seal_outcome, process_proposal, propose, query_ordered_outcome,
};
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::portable::DurableRecordKey;
use runtime::{
    DurableDomainStateStore, DurableRequestId, OutgoingBarrier, StructuredDurableDomainStateStore,
    SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{ffi::OsString, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

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

pub(super) async fn run(
    fixture: &mut Fixture,
    candidate_path: &Path,
    candidate: &OrderedCandidate,
) {
    let fence: WriterFenceGeneration = fixture.operation.writer_fence();
    let mut stores: Vec<Arc<SqliteDurableStore>> = Vec::new();
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
        let router = certified_ordered_economics_router(OrderedEconomicsState {
            store: Arc::clone(&store),
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
                key: validator.signing_key.clone(),
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
            key: fixture.network.validators[index].signing_key.clone(),
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
    let manifest = std::path::PathBuf::from(format!("{}.manifest", prefix.display()));
    let proposal_path = std::fs::read_to_string(&manifest)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let proposal: OrderedProposal =
        decode_ordered_proposal(&std::fs::read(proposal_path).unwrap()).unwrap();
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
    for (index, store) in stores.iter().enumerate() {
        let signer = Signer {
            id: fixture.network.validators[index].validator_id,
            key: fixture.network.validators[index].signing_key.clone(),
        };
        assert!(
            process_proposal(store.as_ref(), &fixture.operation, &env, &proposal, &signer).is_err(),
            "cached vote is not exposed after Seal"
        );
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
