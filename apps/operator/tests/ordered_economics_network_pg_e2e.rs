//! Actual compiled network CLI, independent PostgreSQL stores, shared claims,
//! declared observer recovery and process-restart replay. Claim construction
//! uses production read-only APIs under test-controlled quiescence, never the
//! fence-advancing offline operator while a host is running.
#[path = "support/ordered_economics_bond.rs"]
mod bond;
#[path = "support/ordered_economics_evidence.rs"]
mod evidence;
#[path = "support/ordered_economics_network_checks.rs"]
mod network_checks;
mod support;

use abi::call_values::{CallValue, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
    encode_signed_local_execution, local_execution_signing_frame,
};
use node_core::fee_claims::{self, FeeClaimKind, FeeClaimPreparationRequest};
use node_core::ordered_economics::{
    OrderedCandidate, OrderedOperationKind, encode_ordered_candidate,
};
use objects::{AccessMode, Address};
use postgres::{Config, NoTls};
use protocol_types::ValidatorId;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{DurableDomainStateStore, StructuredDurableDomainStateStore};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::{
    ffi::OsString,
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::Output,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use support::cli::{self, CliContext};
use support::genesis_fixture::{self, FastVoteGenesisFixture};
use support::host::{self, HostProcess, TempDir};

type AdminPool = Pool<PostgresConnectionManager<NoTls>>;
type Store = PostgresDurableStore<PostgresConnectionManager<NoTls>>;

/// Equality compares every exact SQL row; Debug is deliberately compact so a
/// failed invariant never dumps megabytes of canonical objects and receipts.
#[derive(PartialEq, Eq)]
struct Snapshot(Vec<Vec<String>>);
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::hash::{Hash, Hasher};
        f.debug_list()
            .entries(self.0.iter().map(|rows| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                rows.hash(&mut hasher);
                (rows.len(), hasher.finish())
            }))
            .finish()
    }
}

fn store(pool: &AdminPool, namespace: &PostgresNamespace) -> Store {
    PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    )
}

/// Includes every scoped table, local revision and commit sequence. No replay
/// comparison excludes vote records, fences, tombstones, receipts or logs.
fn snapshot(pool: &AdminPool, namespace: &PostgresNamespace) -> Snapshot {
    let mut connection = pool.get().unwrap();
    Snapshot(["storage_metadata", "blobs", "state_records", "object_heads", "object_versions",
        "request_receipts", "outbox_batches", "outbox_messages", "outbox_delivery",
        "outbox_delivery_attempts", "checkpoints", "migration_jobs"]
        .iter().map(|table: &&str| {
            let sql: String = format!("SELECT row_to_json(t)::text FROM sunrise_edge.{table} t WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 ORDER BY row_to_json(t)::text");
            connection.query(&sql, &[&namespace.chain_id_bytes(), &namespace.validator_id().as_bytes().as_slice(), &namespace.domain().as_bytes().as_slice()]).unwrap()
                .iter().map(|row| row.get::<_, String>(0)).collect()
        }).collect())
}

fn inspect(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
) -> fee_claims::FeeEscrowInspection {
    let durable: Store = store(pool, namespace);
    let blobs: PostgresBlobStore<PostgresConnectionManager<NoTls>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
    fee_claims::inspect_fee_escrow(
        &durable,
        &blobs,
        &cli::read_context(pool, namespace),
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        fixture.request_id,
    )
    .unwrap()
}

/// No HTTP request or other test writer runs during this multi-read preview.
/// This is NOT a claim that the offline inspection API is an online snapshot.
fn prepare_claim(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    claimant: ValidatorId,
    request: [u8; 32],
    recipient: Address,
) -> OrderedCandidate {
    let durable: Store = store(pool, namespace);
    let blobs: PostgresBlobStore<PostgresConnectionManager<NoTls>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
    let context: runtime::DurableOperationContext = cli::read_context(pool, namespace);
    let key: SigningKey = SigningKey::from(
        fixture
            .validators
            .iter()
            .find(|entry| entry.validator_id == claimant)
            .unwrap()
            .seed,
    );
    let public: [u8; 32] = VerificationKey::from(&key).into();
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let view: fee_claims::FeeClaimInspection = fee_claims::inspect_fee_claim(
        &durable,
        &blobs,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        fixture.request_id,
        claimant,
        public,
        &policy,
    )
    .unwrap();
    let kind: FeeClaimKind = view.entitlement.kind.unwrap();
    let signed_leg: Option<Vec<u8>> = match kind {
        FeeClaimKind::ZeroShare => None,
        FeeClaimKind::Split | FeeClaimKind::FinalTransfer => {
            let execution: &fee_claims::FeeClaimExecutionView = view.execution.as_ref().unwrap();
            let split: bool = kind == FeeClaimKind::Split;
            let entrypoint: String = if split {
                execution.resource.split_entrypoint.clone()
            } else {
                execution.resource.transfer_entrypoint.clone()
            };
            let argument: CallValue = CallValue::Tuple(if split {
                vec![
                    CallValue::U64(view.entitlement.amount),
                    CallValue::Bytes(recipient.as_bytes().to_vec()),
                ]
            } else {
                vec![CallValue::Bytes(recipient.as_bytes().to_vec())]
            });
            let arguments: Vec<u8> = encode_call_value(
                execution.interface.argument_layout(&entrypoint).unwrap(),
                &argument,
            )
            .unwrap();
            let intent: LocalExecutionIntent = LocalExecutionIntent {
                mode: LocalExecutionMode::Call,
                policy_digest: execution.policy.digest(&fixture.resolver).unwrap(),
                call: CallIntent {
                    context: fixture.context.clone(),
                    request_id: request,
                    sender: public,
                    nonce: execution.next_nonce,
                    code: execution.resource.code.clone(),
                    instance: execution.resource.instance.clone(),
                    entrypoint,
                    type_arguments: execution.resource.ty.args().to_vec(),
                    access: AccessManifest {
                        entries: vec![AccessEntry {
                            object_ref: view.escrow.settlement.fee_output.clone().unwrap(),
                            mode: AccessMode::Write,
                        }],
                    },
                    arguments,
                    gas_limit: 500_000,
                },
                authorizations: Vec::new(),
            };
            let frame: Vec<u8> = local_execution_signing_frame(&fixture.context, &intent).unwrap();
            Some(
                encode_signed_local_execution(&SignedLocalExecutionIntent {
                    intent,
                    signature: key.sign(&frame).into(),
                })
                .unwrap(),
            )
        }
    };
    let checkpoint: u64 = 2;
    let prepared: fee_claims::PreparedFeeClaim = fee_claims::prepare_fee_claim(
        &durable,
        &blobs,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        &policy,
        &execution::LocalWasmExecutionEngine::new(),
        FeeClaimPreparationRequest {
            escrow_request_id: fixture.request_id,
            request_id: request,
            validator_id: claimant,
            claimant_public_key: public,
            recipient,
            signed_leg: signed_leg.as_deref(),
        },
        checkpoint,
    )
    .unwrap();
    let digest: protocol_types::Digest32 =
        fee_claims::fee_claim_intent_digest(&fixture.resolver, &prepared.intent).unwrap();
    let frame: Vec<u8> = fee_claims::fee_claim_signing_frame(&fixture.context, digest).unwrap();
    let signed: fee_claims::codec::SignedFeeClaimIntent = fee_claims::codec::SignedFeeClaimIntent {
        intent: prepared.intent,
        signature: key.sign(&frame).into(),
    };
    OrderedCandidate {
        context: fixture.context.clone(),
        request_id: request,
        kind: OrderedOperationKind::FeeClaim,
        intent: fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap(),
        created_checkpoint: checkpoint,
    }
}

fn command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    action: &str,
    extra: &[&str],
) -> Output {
    let candidate_name: &str = extra
        .windows(2)
        .find(|pair| pair[0] == "--candidate")
        .and_then(|pair| Path::new(pair[1]).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("declared-prefix");
    eprintln!("ordered network CLI: {action} {candidate_name}");
    let chain: String = fixture.chain_id.to_string();
    let protocol: String = fixture.protocol_version.get().to_string();
    let epoch: String = fixture.epoch.get().to_string();
    let domain: String = fixture.domain.to_string();
    let digest: String = cli::to_hex(&fixture.manifest_digest);
    let mut args: Vec<OsString> = [
        "economics",
        action,
        "--ordered-network",
        network.to_str().unwrap(),
        "--ordered-genesis-manifest",
        genesis.to_str().unwrap(),
        "--ordered-expected-genesis-digest",
        &digest,
        "--expected-chain-id",
        &chain,
        "--expected-protocol-version",
        &protocol,
        "--expected-epoch",
        &epoch,
        "--domain",
        &domain,
        "--deadline-seconds",
        "90",
        "--per-request-cap-seconds",
        "10",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.extend(extra.iter().map(OsString::from));
    cli::edge_cli_command(args).output().unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "actual network CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn nonce(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    claimant: ValidatorId,
) -> u64 {
    let public: [u8; 32] = VerificationKey::from(&SigningKey::from(
        fixture
            .validators
            .iter()
            .find(|entry| entry.validator_id == claimant)
            .unwrap()
            .seed,
    ))
    .into();
    node_core::query_sender_next_nonce(
        &store(pool, namespace),
        &cli::read_context(pool, namespace),
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        public,
    )
    .unwrap()
}

fn prepare_unbond(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    validator: ValidatorId,
    request: [u8; 32],
    recipient: Address,
) -> (
    OrderedCandidate,
    node_core::fast_path::records::FastPathBondRecord,
) {
    use node_core::bond_lifecycle::{
        self, BondLifecycleIntent, BondLifecycleOperation, SignedBondLifecycleIntent,
    };
    use node_core::fast_path::records::{
        FastPathBondRecord, FastPathBondState, decode_fastpath_bond_record,
        encode_fastpath_bond_record,
    };
    let durable: Store = store(pool, namespace);
    let key: Vec<u8> =
        node_core::local_instance_state::fastpath_bond_record_key(&fixture.chain_id, &validator)
            .unwrap();
    let observed: runtime::VersionedStateValue = durable
        .get_versioned_durable(&cli::read_context(pool, namespace), fixture.domain, &key)
        .unwrap();
    let row: FastPathBondRecord = decode_fastpath_bond_record(observed.value().unwrap()).unwrap();
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let resource = manifest
        .economics_policy
        .resources
        .iter()
        .find(|r| {
            r.resource_id.domain() == row.resource_domain && r.resource_id.value() == &row.resource
        })
        .unwrap();
    let mut next: FastPathBondRecord = row.clone();
    next.generation = row.generation.checked_add(1).unwrap();
    next.committed_at_checkpoint = 2;
    next.lifecycle_epoch = fixture.epoch;
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: protocol_types::Epoch::new(
            fixture
                .epoch
                .get()
                .checked_add(resource.bond.as_ref().unwrap().unbonding_epochs)
                .unwrap(),
        ),
        recipient: *recipient.as_bytes(),
    };
    let intent: BondLifecycleIntent = BondLifecycleIntent {
        context: fixture.context.clone(),
        request_id: request,
        validator_id: validator,
        resource_id: resource.resource_id,
        expected_generation: row.generation,
        expected_previous_row_digest: bond_lifecycle::bond_row_digest(
            &fixture.resolver,
            row.lifecycle_epoch,
            &encode_fastpath_bond_record(&row).unwrap(),
        )
        .unwrap(),
        expected_next_row_digest: bond_lifecycle::bond_row_digest(
            &fixture.resolver,
            next.lifecycle_epoch,
            &encode_fastpath_bond_record(&next).unwrap(),
        )
        .unwrap(),
        operation: BondLifecycleOperation::Unbond { recipient },
    };
    let signing_key: SigningKey = SigningKey::from(
        fixture
            .validators
            .iter()
            .find(|v| v.validator_id == validator)
            .unwrap()
            .seed,
    );
    let digest = bond_lifecycle::bond_lifecycle_intent_digest(&fixture.resolver, &intent).unwrap();
    let frame: Vec<u8> =
        bond_lifecycle::bond_lifecycle_signing_frame(&fixture.context, digest).unwrap();
    let signed = SignedBondLifecycleIntent {
        intent,
        signature: signing_key.sign(&frame).into(),
    };
    (
        OrderedCandidate {
            context: fixture.context.clone(),
            request_id: request,
            kind: OrderedOperationKind::BondLifecycle,
            intent: bond_lifecycle::encode_signed_bond_lifecycle_intent(&signed).unwrap(),
            created_checkpoint: 2,
        },
        next,
    )
}

fn receipt(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    request: [u8; 32],
) -> runtime::DurableRequestReceipt {
    store(pool, namespace)
        .get_request_receipt(
            &cli::read_context(pool, namespace),
            fixture.domain,
            runtime::DurableRequestId::new(request).unwrap(),
        )
        .unwrap()
        .expect("ordered apply must retain original receipt")
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn ordered_economics_network_four_namespace_competing_claims_e2e() {
    let Some(url) = support::live_postgres_url() else {
        return;
    };
    let _lock = support::LiveTestLock::acquire();
    let config: Config = Config::from_str(&url).unwrap();
    let backend = cli::single_tcp_backend_addr(&config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _connector, ca_der) = support::tls_relay::TlsPassthroughProxy::spawn(backend);
    let dsn: String = cli::proxied_dsn(&config, proxy.local_addr().port());
    let unique: String = format!(
        "ordered-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut fixture: FastVoteGenesisFixture = genesis_fixture::build_economics_fixture(&unique);
    let bond_source: node_core::GenesisObjectEntry = bond::fund_source(&mut fixture);
    fixture
        .validators
        .sort_by_key(|validator| validator.validator_id);
    let dir: PathBuf = std::env::temp_dir().join(format!("sunrise-edge-{unique}"));
    fs::create_dir(&dir).unwrap();
    let _owned = TempDir(dir.clone());
    let ca: PathBuf = dir.join("ca.der");
    let genesis: PathBuf = dir.join("genesis");
    let intent: PathBuf = dir.join("paid-intent");
    host::write_new(&ca, &ca_der);
    host::write_new(&genesis, &fixture.manifest_bytes);
    host::write_new(&intent, &fixture.paid_intent_bytes);
    let chain: String = fixture.chain_id.to_string();
    let domain: String = fixture.domain.to_string();
    let digest: String = cli::to_hex(&fixture.manifest_digest);
    let cli_ctx = CliContext {
        ca_path: &ca,
        dsn: &dsn,
        chain_id: chain.clone(),
        protocol_version: fixture.protocol_version,
        manifest_path: &genesis,
        digest_hex: digest.clone(),
    };
    let pool: AdminPool = cli::admin_pool(&config);
    let namespaces: Vec<PostgresNamespace> = fixture
        .validators
        .iter()
        .map(|v| PostgresNamespace::new(&fixture.chain_id, v.validator_id, fixture.domain).unwrap())
        .collect();
    let keys: Vec<PathBuf> = fixture
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let path: PathBuf = dir.join(format!("validator-{i}.seed"));
            host::write_new_secure_mode(&path, &v.seed);
            path
        })
        .collect();

    // Only this pre-host fixture bootstrap uses the explicitly offline operator.
    // No offline fence advance occurs once any HTTP host is running.
    let mut votes: Vec<PathBuf> = Vec::new();
    for (i, v) in fixture.validators.iter().enumerate() {
        let id: String = v.validator_id.to_string();
        cli::assert_stdout_contains(
            &cli::namespace_init(&cli_ctx, &id, &domain),
            "complete=true",
        );
        cli::assert_stdout_contains(
            &cli::install_genesis(&cli_ctx, &id, &domain, true),
            "outcome=fresh_install",
        );
        let vote: PathBuf = dir.join(format!("paid-{i}.vote"));
        cli::assert_stdout_contains(
            &cli::prepare_vote(&cli_ctx, &id, &domain, &keys[i], &intent, &vote, true),
            "complete=true",
        );
        votes.push(vote);
    }
    let cert: PathBuf = dir.join("paid.certificate");
    success(&cli::assemble_certificate(&cli_ctx, &votes[..3], &cert));
    for (i, v) in fixture.validators.iter().enumerate() {
        let out: PathBuf = dir.join(format!("paid-{i}.applied"));
        cli::assert_stdout_contains(
            &cli::apply_certificate(
                &cli_ctx,
                &v.validator_id.to_string(),
                &domain,
                &intent,
                &cert,
                &out,
                true,
            ),
            "complete=true",
        );
    }
    let initial: fee_claims::FeeEscrowInspection = inspect(&pool, &namespaces[0], &fixture);
    let positive: Vec<ValidatorId> = initial
        .claimants
        .iter()
        .filter(|s| s.amount > 0)
        .map(|s| s.validator_id)
        .collect();
    let zero: Vec<ValidatorId> = initial
        .claimants
        .iter()
        .filter(|s| s.amount == 0)
        .map(|s| s.validator_id)
        .collect();
    assert_eq!((positive.len(), zero.len()), (2, 2));
    assert_eq!(initial.settlement.total_amount, Some(2));

    let mut hosts: Vec<Option<HostProcess>> = fixture
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            Some(host::spawn_ordered_host(
                &ca,
                &dsn,
                &chain,
                &v.validator_id.to_string(),
                &domain,
                &genesis,
                &digest,
                &keys[i],
                "127.0.0.1:0",
            ))
        })
        .collect();
    let network: PathBuf = dir.join("network.conf");
    let network_text: String = fixture
        .validators
        .iter()
        .zip(&hosts)
        .map(|(v, h)| format!("{} {} - -\n", v.validator_id, h.as_ref().unwrap().addr))
        .collect();
    host::write_new(&network, network_text.as_bytes());
    let recipient: Address =
        Address::new(VerificationKey::from(&SigningKey::from([0x77; 32])).into());
    let before: Vec<Snapshot> = namespaces.iter().map(|n| snapshot(&pool, n)).collect();
    let a: OrderedCandidate = prepare_claim(
        &pool,
        &namespaces[0],
        &fixture,
        positive[0],
        [0xE1; 32],
        recipient,
    );
    let stale_b: OrderedCandidate = prepare_claim(
        &pool,
        &namespaces[0],
        &fixture,
        positive[1],
        [0xE2; 32],
        recipient,
    );
    assert_eq!(
        before,
        namespaces
            .iter()
            .map(|n| snapshot(&pool, n))
            .collect::<Vec<_>>(),
        "read-only preview must not advance a fence or reserve a nonce"
    );
    let a_path: PathBuf = dir.join("a.candidate");
    let stale_path: PathBuf = dir.join("stale-b.candidate");
    host::write_new(&a_path, &encode_ordered_candidate(&a).unwrap());
    host::write_new(&stale_path, &encode_ordered_candidate(&stale_b).unwrap());

    // The fourth validator is truly offline for shared ordering. Its selected
    // leadership slot requires trusted-clock pacemaker progress, not reselection.
    drop(hosts[3].take());
    let offline_before: Snapshot = snapshot(&pool, &namespaces[3]);
    let a_out: PathBuf = dir.join("a");
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            a_path.to_str().unwrap(),
            "--out",
            a_out.to_str().unwrap(),
        ],
    ));
    for n in &namespaces[..3] {
        assert!(
            inspect(&pool, n, &fixture)
                .claimants
                .iter()
                .find(|s| s.validator_id == positive[0])
                .unwrap()
                .claimed
        );
    }
    let b_nonce: u64 = nonce(&pool, &namespaces[0], &fixture, positive[1]);
    let a_receipts: Vec<runtime::DurableRequestReceipt> = namespaces[..3]
        .iter()
        .map(|n| receipt(&pool, n, &fixture, a.request_id))
        .collect();
    assert!(a_receipts.iter().all(|r| r == &a_receipts[0]));
    // The fourth (selected next leader) is offline. An exact completed request
    // must reconcile read-only, before Tick could advance any replica's view.
    let completed_before: Vec<Snapshot> = namespaces.iter().map(|n| snapshot(&pool, n)).collect();
    let exact_out: PathBuf = dir.join("already-completed");
    let exact_retry = command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            a_path.to_str().unwrap(),
            "--out",
            exact_out.to_str().unwrap(),
        ],
    );
    assert!(!exact_retry.status.success());
    assert!(
        String::from_utf8_lossy(&exact_retry.stderr)
            .contains("original saved proposal/certificate manifest")
    );
    assert_eq!(
        completed_before,
        namespaces
            .iter()
            .map(|n| snapshot(&pool, n))
            .collect::<Vec<_>>()
    );
    let stale_out: PathBuf = dir.join("stale-b");
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            stale_path.to_str().unwrap(),
            "--out",
            stale_out.to_str().unwrap(),
        ],
    ));
    for (i, n) in namespaces[..3].iter().enumerate() {
        assert_eq!(nonce(&pool, n, &fixture, positive[1]), b_nonce);
        assert!(
            !inspect(&pool, n, &fixture)
                .claimants
                .iter()
                .find(|s| s.validator_id == positive[1])
                .unwrap()
                .claimed
        );
        assert_eq!(receipt(&pool, n, &fixture, a.request_id), a_receipts[i]);
        let rejected = receipt(&pool, n, &fixture, stale_b.request_id);
        let record = node_core::NodeDedupRecord::decode(rejected.canonical_bytes()).unwrap();
        assert_eq!(record.responses().len(), 1);
        assert_eq!(
            record.responses()[0].status(),
            node_core::NodeResponseStatus::Rejected
        );
        assert_eq!(
            node_core::ordered_economics::decode_ordered_refusal_payload(
                record.responses()[0].payload().unwrap()
            )
            .unwrap(),
            node_core::ordered_economics::OrderedRefusal::StaleGeneration
        );
    }
    assert_eq!(snapshot(&pool, &namespaces[3]), offline_before);

    let mut prefixes: Vec<PathBuf> = vec![a_out, stale_out];
    for (index, claimant) in [positive[1], zero[0], zero[1]].into_iter().enumerate() {
        let candidate: OrderedCandidate = prepare_claim(
            &pool,
            &namespaces[0],
            &fixture,
            claimant,
            [0xE3 + u8::try_from(index).unwrap(); 32],
            recipient,
        );
        let path: PathBuf = dir.join(format!("fresh-{index}.candidate"));
        let out: PathBuf = dir.join(format!("fresh-{index}"));
        host::write_new(&path, &encode_ordered_candidate(&candidate).unwrap());
        success(&command(
            &fixture,
            &network,
            &genesis,
            "network-submit",
            &[
                "--candidate",
                path.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
        ));
        prefixes.push(out);
    }
    for n in &namespaces[..3] {
        let view: fee_claims::FeeEscrowInspection = inspect(&pool, n, &fixture);
        assert!(view.claimants.iter().all(|s| s.claimed));
        assert_eq!(
            (
                view.verification.verified_claims,
                view.verification.verified_payouts
            ),
            // The verifier counts created split-payout records, not the
            // final whole-object transfer (which it verifies separately).
            (4, 1)
        );
    }

    let (replace, replaced_bond, released_collateral) = bond::prepare_replace(
        &pool,
        &namespaces[0],
        &fixture,
        &bond_source,
        fixture.validators[0].validator_id,
    );
    let replace_path: PathBuf = dir.join("replace.candidate");
    let replace_out: PathBuf = dir.join("replace");
    host::write_new(&replace_path, &encode_ordered_candidate(&replace).unwrap());
    let resume = network_checks::reserve_and_check(
        &fixture,
        &pool,
        &namespaces,
        &network,
        &genesis,
        &dir,
        &replace,
    );
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            replace_path.to_str().unwrap(),
            "--out",
            replace_out.to_str().unwrap(),
            "--resume-proposal",
            resume.to_str().unwrap(),
        ],
    ));
    prefixes.push(replace_out);
    for n in &namespaces[..3] {
        assert_eq!(
            bond::current_bond(&pool, n, &fixture, fixture.validators[0].validator_id),
            replaced_bond
        );
    }

    // Genuine signed unbond against committed collateral, not an imported
    // Exited/Jailed row invented to bypass membership prerequisites.
    let (unbond, expected_bond) = prepare_unbond(
        &pool,
        &namespaces[0],
        &fixture,
        fixture.validators[0].validator_id,
        [0xE6; 32],
        recipient,
    );
    let unbond_path: PathBuf = dir.join("unbond.candidate");
    let unbond_out: PathBuf = dir.join("unbond");
    host::write_new(&unbond_path, &encode_ordered_candidate(&unbond).unwrap());
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            unbond_path.to_str().unwrap(),
            "--out",
            unbond_out.to_str().unwrap(),
        ],
    ));
    prefixes.push(unbond_out);
    let bond_key: Vec<u8> = node_core::local_instance_state::fastpath_bond_record_key(
        &fixture.chain_id,
        &fixture.validators[0].validator_id,
    )
    .unwrap();
    for n in &namespaces[..3] {
        let raw: runtime::VersionedStateValue = store(&pool, n)
            .get_versioned_durable(&cli::read_context(&pool, n), fixture.domain, &bond_key)
            .unwrap();
        assert_eq!(
            node_core::fast_path::records::decode_fastpath_bond_record(raw.value().unwrap())
                .unwrap(),
            expected_bond
        );
    }

    // All three signed evidence families use the same shared network order;
    // no direct/offline evidence mutation is used after host startup.
    let evidence_validator: ValidatorId = fixture.validators[0].validator_id;
    let proofs: Vec<evidence::Proof> = evidence::proofs(&fixture, evidence_validator);
    for (index, proof) in proofs.iter().enumerate() {
        let path: PathBuf = dir.join(format!("evidence-{index}.candidate"));
        let out: PathBuf = dir.join(format!("evidence-{index}"));
        host::write_new(&path, &encode_ordered_candidate(&proof.candidate).unwrap());
        success(&command(
            &fixture,
            &network,
            &genesis,
            "network-submit",
            &[
                "--candidate",
                path.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
        ));
        prefixes.push(out);
        for n in &namespaces[..3] {
            let found = node_core::query_fastpath_equivocation_evidence(
                &store(&pool, n),
                &cli::read_context(&pool, n),
                fixture.domain,
                &fixture.resolver,
                &fixture.chain_id,
                fixture.epoch,
                *evidence_validator.as_bytes(),
                proof.identity,
            )
            .unwrap()
            .unwrap();
            assert_eq!(found.evidence_bytes, proof.evidence_bytes);
        }
    }
    // A second request carrying identical valid evidence must not wedge the
    // ordered prefix or overwrite its permanent normalized evidence row.
    let duplicate: OrderedCandidate = OrderedCandidate {
        request_id: [0xD5; 32],
        ..proofs[0].candidate.clone()
    };
    let duplicate_path: PathBuf = dir.join("evidence-duplicate.candidate");
    let duplicate_out: PathBuf = dir.join("evidence-duplicate");
    host::write_new(
        &duplicate_path,
        &encode_ordered_candidate(&duplicate).unwrap(),
    );
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            duplicate_path.to_str().unwrap(),
            "--out",
            duplicate_out.to_str().unwrap(),
        ],
    ));
    prefixes.push(duplicate_out);
    let slash: OrderedCandidate = evidence::prepare_slash(
        &pool,
        &namespaces[0],
        &fixture,
        evidence_validator,
        proofs[0].identity,
    );
    let slash_path: PathBuf = dir.join("slash.candidate");
    let slash_out: PathBuf = dir.join("slash");
    host::write_new(&slash_path, &encode_ordered_candidate(&slash).unwrap());
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            slash_path.to_str().unwrap(),
            "--out",
            slash_out.to_str().unwrap(),
        ],
    ));
    prefixes.push(slash_out);
    let reference_bond: Vec<u8> = store(&pool, &namespaces[0])
        .get_versioned_durable(
            &cli::read_context(&pool, &namespaces[0]),
            fixture.domain,
            &bond_key,
        )
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    let jailed =
        node_core::fast_path::records::decode_fastpath_bond_record(&reference_bond).unwrap();
    assert_eq!(jailed.generation, expected_bond.generation + 1);
    assert_eq!(
        jailed.slashable_from_epoch,
        expected_bond.slashable_from_epoch
    );
    assert_eq!(jailed.amount, expected_bond.amount);
    assert_eq!(
        jailed.state,
        node_core::fast_path::records::FastPathBondState::Jailed {
            evidence_digest: proofs[0].identity
        }
    );
    for n in &namespaces[..3] {
        assert_eq!(
            store(&pool, n)
                .get_versioned_durable(&cli::read_context(&pool, n), fixture.domain, &bond_key)
                .unwrap()
                .value()
                .unwrap(),
            reference_bond
        );
    }

    // Reactivation posts genuinely fresh released collateral; it cannot
    // reuse the forfeited object or erase the retained slash evidence.
    let (reactivate, expected_reactivated) = bond::prepare_reactivate(
        &pool,
        &namespaces[0],
        &fixture,
        &released_collateral,
        evidence_validator,
    );
    let reactivate_path: PathBuf = dir.join("reactivate.candidate");
    let reactivate_out: PathBuf = dir.join("reactivate");
    host::write_new(
        &reactivate_path,
        &encode_ordered_candidate(&reactivate).unwrap(),
    );
    success(&command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            reactivate_path.to_str().unwrap(),
            "--out",
            reactivate_out.to_str().unwrap(),
        ],
    ));
    prefixes.push(reactivate_out);
    for n in &namespaces[..3] {
        assert_eq!(
            bond::current_bond(&pool, n, &fixture, evidence_validator),
            expected_reactivated
        );
    }
    let reference_bond: Vec<u8> =
        node_core::fast_path::records::encode_fastpath_bond_record(&expected_reactivated).unwrap();

    // Full dependency-ordered declared prefix, not only the last three blocks.
    let all_manifest: PathBuf = dir.join("complete.manifest");
    let declared: String = prefixes
        .iter()
        .map(|p| fs::read_to_string(PathBuf::from(format!("{}.manifest", p.display()))).unwrap())
        .collect();
    host::write_new(&all_manifest, declared.as_bytes());
    hosts[3] = Some(host::spawn_ordered_host(
        &ca,
        &dsn,
        &chain,
        &fixture.validators[3].validator_id.to_string(),
        &domain,
        &genesis,
        &digest,
        &keys[3],
        "127.0.0.1:0",
    ));
    let fourth_network: PathBuf = dir.join("fourth.conf");
    host::write_new(
        &fourth_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id,
            hosts[3].as_ref().unwrap().addr
        )
        .as_bytes(),
    );
    let recovered: PathBuf = dir.join("recovered");
    success(&command(
        &fixture,
        &fourth_network,
        &genesis,
        "network-replay",
        &[
            "--manifest",
            all_manifest.to_str().unwrap(),
            "--out",
            recovered.to_str().unwrap(),
        ],
    ));
    let reference: fee_claims::FeeEscrowInspection = inspect(&pool, &namespaces[0], &fixture);
    let fourth: fee_claims::FeeEscrowInspection = inspect(&pool, &namespaces[3], &fixture);
    assert_eq!(fourth.canonical_settlement, reference.canonical_settlement);
    assert_eq!(
        (
            fourth.verification.verified_claims,
            fourth.verification.verified_payouts
        ),
        (4, 1)
    );
    for request in [
        [0xE1; 32], [0xE2; 32], [0xE3; 32], [0xE4; 32], [0xE5; 32], [0xE6; 32], [0xD1; 32],
        [0xD2; 32], [0xD3; 32], [0xD4; 32], [0xD5; 32], [0xD6; 32], [0xE0; 32],
    ] {
        assert_eq!(
            receipt(&pool, &namespaces[3], &fixture, request),
            receipt(&pool, &namespaces[0], &fixture, request)
        );
    }
    assert_eq!(
        store(&pool, &namespaces[3])
            .get_versioned_durable(
                &cli::read_context(&pool, &namespaces[3]),
                fixture.domain,
                &bond_key
            )
            .unwrap()
            .value()
            .unwrap(),
        reference_bond
    );
    for proof in &proofs {
        let fourth = node_core::query_fastpath_equivocation_evidence(
            &store(&pool, &namespaces[3]),
            &cli::read_context(&pool, &namespaces[3]),
            fixture.domain,
            &fixture.resolver,
            &fixture.chain_id,
            fixture.epoch,
            *evidence_validator.as_bytes(),
            proof.identity,
        )
        .unwrap()
        .unwrap();
        assert_eq!(fourth.evidence_bytes, proof.evidence_bytes);
    }
    let recovered_before: Snapshot = snapshot(&pool, &namespaces[3]);
    let replayed: PathBuf = dir.join("same-boot");
    success(&command(
        &fixture,
        &fourth_network,
        &genesis,
        "network-replay",
        &[
            "--manifest",
            all_manifest.to_str().unwrap(),
            "--out",
            replayed.to_str().unwrap(),
        ],
    ));
    assert_eq!(snapshot(&pool, &namespaces[3]), recovered_before);
    drop(hosts[3].take());
    hosts[3] = Some(host::spawn_ordered_host(
        &ca,
        &dsn,
        &chain,
        &fixture.validators[3].validator_id.to_string(),
        &domain,
        &genesis,
        &digest,
        &keys[3],
        "127.0.0.1:0",
    ));
    let restart_network: PathBuf = dir.join("restart.conf");
    host::write_new(
        &restart_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id,
            hosts[3].as_ref().unwrap().addr
        )
        .as_bytes(),
    );
    let reopened_before: Snapshot = snapshot(&pool, &namespaces[3]);
    let reopened: PathBuf = dir.join("reopened");
    success(&command(
        &fixture,
        &restart_network,
        &genesis,
        "network-replay",
        &[
            "--manifest",
            all_manifest.to_str().unwrap(),
            "--out",
            reopened.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        snapshot(&pool, &namespaces[3]),
        reopened_before,
        "historical replay must not rewrite consensus metadata or reacquire reservations"
    );
    network_checks::reject_bad_prefixes_without_posts(
        &fixture,
        &pool,
        &namespaces[3],
        &genesis,
        &all_manifest,
        hosts[3].as_ref().unwrap().addr,
    );

    // Identical old request ID but changed committed checkpoint conflicts before
    // any fresh proposal/vote bookkeeping, even after all later row generations.
    let conflict: OrderedCandidate = OrderedCandidate {
        created_checkpoint: 3,
        ..a
    };
    let conflict_path: PathBuf = dir.join("checkpoint-conflict.candidate");
    host::write_new(
        &conflict_path,
        &encode_ordered_candidate(&conflict).unwrap(),
    );
    let conflict_before: Vec<Snapshot> =
        namespaces[..3].iter().map(|n| snapshot(&pool, n)).collect();
    let conflict_out: PathBuf = dir.join("checkpoint-conflict");
    let conflicting_retry = command(
        &fixture,
        &network,
        &genesis,
        "network-submit",
        &[
            "--candidate",
            conflict_path.to_str().unwrap(),
            "--out",
            conflict_out.to_str().unwrap(),
        ],
    );
    assert!(!conflicting_retry.status.success());
    assert!(String::from_utf8_lossy(&conflicting_retry.stderr).contains("request header conflict"));
    assert_eq!(
        namespaces[..3]
            .iter()
            .map(|n| snapshot(&pool, n))
            .collect::<Vec<_>>(),
        conflict_before
    );

    // Authentic fresh Unbond after Reactivate, not a stale row/nonce or a dead
    // endpoint. Another real writer claims only validator four's namespace.
    let (fence_candidate, _) = prepare_unbond(
        &pool,
        &namespaces[0],
        &fixture,
        evidence_validator,
        [0xE7; 32],
        recipient,
    );
    let proposal =
        network_checks::capture_proposal(&fixture, &network, &genesis, &dir, &fence_candidate);
    let stale_addr = hosts[3].as_ref().unwrap().addr;
    let rival = host::spawn_ordered_host(
        &ca,
        &dsn,
        &chain,
        &fixture.validators[3].validator_id.to_string(),
        &domain,
        &genesis,
        &digest,
        &keys[3],
        "127.0.0.1:0",
    );
    assert_ne!(rival.addr, stale_addr);
    let after_fence = snapshot(&pool, &namespaces[3]);
    assert_eq!(network_checks::observe_status(stale_addr, &proposal), 503);
    assert_eq!(snapshot(&pool, &namespaces[3]), after_fence);
    assert_eq!(network_checks::observe_status(rival.addr, &proposal), 200);
    assert!(
        store(&pool, &namespaces[3])
            .get_request_receipt(
                &cli::read_context(&pool, &namespaces[3]),
                fixture.domain,
                runtime::DurableRequestId::new(fence_candidate.request_id).unwrap(),
            )
            .unwrap()
            .is_none(),
        "observation must not fabricate a business commit"
    );
    drop(hosts[3].take());
    drop(rival);
}
