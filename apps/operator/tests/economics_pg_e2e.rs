//! Real compiled offline PostgreSQL fee-claim workflow (DR-0149).
//! The ephemeral TLS relay authenticates only the operator-to-relay leg.
mod support;

use node_core::fee_claims::{codec, inspect_fee_escrow};
use node_core::{NodeResponse, decode_genesis_manifest};
use objects::ObjectRef;
use postgres::{Config, NoTls};
use protocol_types::ValidatorId;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::DurableDomainStateStore;
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::{
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
};
use support::cli::{self, CliContext};
use support::genesis_fixture::{self, FastVoteGenesisFixture};

#[derive(Default)]
struct Artifacts(Vec<PathBuf>);
impl Artifacts {
    fn fresh(&mut self, label: &str) -> PathBuf {
        let path: PathBuf = cli::temp_path(label);
        self.0.push(path.clone());
        path
    }
}
impl Drop for Artifacts {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn command(
    cli: &CliContext<'_>,
    fixture: &FastVoteGenesisFixture,
    name: &str,
    output: &Path,
) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_economics_pg"));
    command.env(cli::DSN_ENV, cli.dsn).args([
        name,
        "--tls-root-der",
        cli.ca_path.to_str().unwrap(),
        "--chain-id",
        cli.chain_id.as_str(),
        "--validator-id",
        &fixture.validators[0].validator_id.to_string(),
        "--domain",
        &fixture.domain.to_string(),
        "--protocol-version",
        &fixture.protocol_version.get().to_string(),
        "--epoch",
        "0",
        "--suite",
        genesis_fixture::SUITE_FLAG,
        "--genesis-manifest",
        cli.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &cli.digest_hex,
        "--timeout-seconds",
        "60",
        "--out",
        output.to_str().unwrap(),
        "--confirm-offline-fence-advance",
    ]);
    command
}

fn prepare(
    cli: &CliContext<'_>,
    fixture: &FastVoteGenesisFixture,
    claimant: ValidatorId,
    key: &Path,
    request: [u8; 32],
    output: &Path,
) -> Output {
    command(cli, fixture, "claim-prepare", output)
        .args([
            "--escrow-request-id",
            &cli::to_hex(&fixture.request_id),
            "--claimant-validator-id",
            &claimant.to_string(),
            "--request-id",
            &cli::to_hex(&request),
            "--recipient",
            &cli::to_hex(&<[u8; 32]>::from(ed25519_zebra::VerificationKey::from(
                &ed25519_zebra::SigningKey::from([0x77; 32]),
            ))),
            "--signing-key-file",
            key.to_str().unwrap(),
            "--gas-limit",
            "500000",
            "--checkpoint",
            "2",
        ])
        .output()
        .unwrap()
}

fn apply(
    cli: &CliContext<'_>,
    fixture: &FastVoteGenesisFixture,
    claim: &Path,
    output: &Path,
) -> Output {
    command(cli, fixture, "claim-apply", output)
        .args(["--claim", claim.to_str().unwrap(), "--checkpoint", "2"])
        .output()
        .unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "operator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    cli::assert_stdout_contains(output, "complete=true");
    cli::assert_stdout_contains(output, "scope=single_namespace");
}

/// Includes every row/object/receipt/blob, excluding only the intentionally
/// advanced namespace writer fence. This catches audit/nonce mutations too.
fn snapshot(
    pool: &Pool<PostgresConnectionManager<NoTls>>,
    namespace: &PostgresNamespace,
) -> Vec<Vec<String>> {
    let mut connection = pool.get().unwrap();
    ["state_records", "object_heads", "object_versions", "request_receipts", "blobs"]
        .iter().map(|table: &&str| {
            let sql: String = format!("SELECT row_to_json(t)::text FROM sunrise_edge.{table} t WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 ORDER BY row_to_json(t)::text");
            connection.query(&sql, &[&namespace.chain_id_bytes(), &namespace.validator_id().as_bytes().as_slice(), &namespace.domain().as_bytes().as_slice()]).unwrap().iter().map(|row| row.get::<_,String>(0)).collect()
        }).collect()
}

fn inspect(
    pool: &Pool<PostgresConnectionManager<NoTls>>,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
) -> node_core::fee_claims::FeeEscrowInspection {
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap();
    let store = PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
    let blobs = PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
    inspect_fee_escrow(
        &store,
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

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn economics_pg_offline_signed_claim_workflow_e2e() {
    let Some(url) = support::live_postgres_url() else {
        eprintln!("skipping economics_pg live PostgreSQL E2E: test database is unset");
        return;
    };
    let _lock = support::LiveTestLock::acquire();
    let config: Config = Config::from_str(&url).unwrap();
    let backend = cli::single_tcp_backend_addr(&config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _, ca) = support::tls_relay::TlsPassthroughProxy::spawn(backend);
    let (ca_path, _ca_guard) = cli::bounded_temp_file("economics-ca", &ca);
    let dsn: String = cli::proxied_dsn(&config, proxy.local_addr().port());
    let unique: String = format!(
        "economics-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: FastVoteGenesisFixture = genesis_fixture::build_economics_fixture(&unique);
    let (manifest_path, _manifest_guard) =
        cli::bounded_temp_file("economics-genesis", &fixture.manifest_bytes);
    let (intent_path, _intent_guard) =
        cli::bounded_temp_file("economics-intent", &fixture.paid_intent_bytes);
    let cli: CliContext<'_> = CliContext {
        ca_path: &ca_path,
        dsn: &dsn,
        chain_id: fixture.chain_id.to_string(),
        protocol_version: fixture.protocol_version,
        manifest_path: &manifest_path,
        digest_hex: cli::to_hex(&fixture.manifest_digest),
    };
    let keys: Vec<_> = fixture
        .validators
        .iter()
        .map(|validator| cli::write_signing_key_file(&validator.seed))
        .collect();
    let mut artifacts: Artifacts = Artifacts::default();
    let mut votes: Vec<PathBuf> = Vec::new();
    for (index, validator) in fixture.validators.iter().enumerate() {
        let id: String = validator.validator_id.to_string();
        assert!(
            cli::namespace_init(&cli, &id, &fixture.domain.to_string())
                .status
                .success()
        );
        assert!(
            cli::install_genesis(&cli, &id, &fixture.domain.to_string(), true)
                .status
                .success()
        );
        let vote: PathBuf = artifacts.fresh("economics-vote");
        assert!(
            cli::prepare_vote(
                &cli,
                &id,
                &fixture.domain.to_string(),
                &keys[index].0,
                &intent_path,
                &vote,
                true
            )
            .status
            .success()
        );
        votes.push(vote);
    }
    let certificate: PathBuf = artifacts.fresh("economics-certificate");
    assert!(
        cli::assemble_certificate(&cli, &votes[..3], &certificate)
            .status
            .success()
    );
    let original_apply: PathBuf = artifacts.fresh("economics-original-apply");
    assert!(
        cli::apply_certificate(
            &cli,
            &fixture.validators[0].validator_id.to_string(),
            &fixture.domain.to_string(),
            &intent_path,
            &certificate,
            &original_apply,
            true
        )
        .status
        .success()
    );
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &fixture.chain_id,
        fixture.validators[0].validator_id,
        fixture.domain,
    )
    .unwrap();
    let pool = cli::admin_pool(&config);
    let initial = inspect(&pool, &namespace, &fixture);
    assert_eq!(initial.settlement.total_amount, Some(2));
    let positive: Vec<_> = initial
        .claimants
        .iter()
        .filter(|share| share.amount > 0)
        .map(|share| share.validator_id)
        .collect();
    let zero: Vec<_> = initial
        .claimants
        .iter()
        .filter(|share| share.amount == 0)
        .map(|share| share.validator_id)
        .collect();
    assert_eq!((positive.len(), zero.len()), (2, 2));
    let key_index = |id: ValidatorId| {
        fixture
            .validators
            .iter()
            .position(|validator| validator.validator_id == id)
            .unwrap()
    };

    let before = snapshot(&pool, &namespace);
    let listing: PathBuf = artifacts.fresh("economics-list");
    success(
        &command(&cli, &fixture, "escrow-list", &listing)
            .args(["--page-size", "1"])
            .output()
            .unwrap(),
    );
    assert!(
        fs::read_to_string(&listing)
            .unwrap()
            .contains(&cli::to_hex(&fixture.request_id))
    );
    let inspection: PathBuf = artifacts.fresh("economics-inspect");
    success(
        &command(&cli, &fixture, "escrow-inspect", &inspection)
            .args(["--escrow-request-id", &cli::to_hex(&fixture.request_id)])
            .output()
            .unwrap(),
    );
    assert_eq!(snapshot(&pool, &namespace), before);
    let fence = cli::current_fence(&pool, &namespace);
    let existing: Output = command(&cli, &fixture, "escrow-list", &listing)
        .args(["--page-size", "1"])
        .output()
        .unwrap();
    assert!(!existing.status.success());
    assert_eq!(cli::current_fence(&pool, &namespace), fence);

    // Prepare zero and split proposals from the same generation. Prepare
    // must leave all application, nonce, audit and receipt rows untouched.
    let zero_first: PathBuf = artifacts.fresh("economics-zero-first");
    success(&prepare(
        &cli,
        &fixture,
        zero[0],
        &keys[key_index(zero[0])].0,
        [0xD1; 32],
        &zero_first,
    ));
    let stale_split: PathBuf = artifacts.fresh("economics-stale-split");
    success(&prepare(
        &cli,
        &fixture,
        positive[0],
        &keys[key_index(positive[0])].0,
        [0xD2; 32],
        &stale_split,
    ));
    assert_eq!(snapshot(&pool, &namespace), before);
    let stale_operation = cli::read_context(&pool, &namespace);
    let zero_receipt: PathBuf = artifacts.fresh("economics-zero-receipt");
    success(&apply(&cli, &fixture, &zero_first, &zero_receipt));
    let after_zero = snapshot(&pool, &namespace);
    let rejected: PathBuf = artifacts.fresh("economics-stale-rejected");
    assert!(
        !apply(&cli, &fixture, &stale_split, &rejected)
            .status
            .success()
    );
    assert_eq!(snapshot(&pool, &namespace), after_zero);
    let store = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );
    assert!(
        store
            .get_versioned_durable(
                &stale_operation,
                fixture.domain,
                &node_core::local_instance_state::fastpath_settlement_key(
                    &fixture.chain_id,
                    &fixture.request_id
                )
                .unwrap()
            )
            .is_err()
    );

    // Historical claimant and namespace identities differ; the one-key
    // operator profile is only claimant+leg signer, not namespace identity.
    let wrong_key: PathBuf = artifacts.fresh("economics-wrong-key");
    let fence = cli::current_fence(&pool, &namespace);
    assert!(
        !prepare(
            &cli,
            &fixture,
            positive[0],
            &keys[key_index(zero[0])].0,
            [0xD3; 32],
            &wrong_key
        )
        .status
        .success()
    );
    assert_eq!(cli::current_fence(&pool, &namespace), fence);
    let split: PathBuf = artifacts.fresh("economics-split");
    success(&prepare(
        &cli,
        &fixture,
        positive[0],
        &keys[key_index(positive[0])].0,
        [0xD4; 32],
        &split,
    ));
    assert_eq!(snapshot(&pool, &namespace), after_zero);
    let split_intent = codec::decode_signed_fee_claim_intent(&fs::read(&split).unwrap()).unwrap();
    let codec::FeeClaimOperation::Split {
        expected_payout: Some(payout),
        ..
    } = &split_intent.intent.operation
    else {
        panic!("fresh split must sign exact v2 payout");
    };
    let payout: ObjectRef = payout.clone();
    let split_receipt: PathBuf = artifacts.fresh("economics-split-receipt");
    success(&apply(&cli, &fixture, &split, &split_receipt));
    let current = inspect(&pool, &namespace, &fixture);
    assert_eq!(current.verification.verified_payouts, 1);

    let final_claim: PathBuf = artifacts.fresh("economics-final");
    success(&prepare(
        &cli,
        &fixture,
        positive[1],
        &keys[key_index(positive[1])].0,
        [0xD5; 32],
        &final_claim,
    ));
    let final_receipt: PathBuf = artifacts.fresh("economics-final-receipt");
    success(&apply(&cli, &fixture, &final_claim, &final_receipt));
    let zero_last: PathBuf = artifacts.fresh("economics-zero-last");
    success(&prepare(
        &cli,
        &fixture,
        zero[1],
        &keys[key_index(zero[1])].0,
        [0xD6; 32],
        &zero_last,
    ));
    let zero_last_receipt: PathBuf = artifacts.fresh("economics-zero-last-receipt");
    success(&apply(&cli, &fixture, &zero_last, &zero_last_receipt));
    let finished = snapshot(&pool, &namespace);
    let final_inspection = inspect(&pool, &namespace, &fixture);
    assert!(final_inspection.claimants.iter().all(|share| share.claimed));
    assert_eq!(final_inspection.verification.verified_claims, 4);
    assert_eq!(final_inspection.verification.verified_payouts, 1);
    let split_row = node_core::fast_path::records::decode_fastpath_settlement_record(
        NodeResponse::decode(&fs::read(&split_receipt).unwrap())
            .unwrap()
            .payload()
            .unwrap(),
    )
    .unwrap();
    assert!(split_row.generation < final_inspection.settlement.generation);
    let payout_before = node_core::query_object(
        &store,
        &cli::read_context(&pool, &namespace),
        fixture.domain,
        &fixture.chain_id,
        payout.id,
    )
    .unwrap();
    drop(store);
    drop(pool);

    // A new process + reopened pool replays an old generation receipt;
    // current row, payout bytes, nonce and claim envelopes remain identical.
    let replay: PathBuf = artifacts.fresh("economics-replay");
    success(&apply(&cli, &fixture, &split, &replay));
    assert_eq!(
        fs::read(&replay).unwrap(),
        fs::read(&split_receipt).unwrap()
    );
    let reopened = cli::admin_pool(&config);
    assert_eq!(snapshot(&reopened, &namespace), finished);
    let reopened_store = PostgresDurableStore::new(
        reopened.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );
    assert_eq!(
        node_core::query_object(
            &reopened_store,
            &cli::read_context(&reopened, &namespace),
            fixture.domain,
            &fixture.chain_id,
            payout.id
        )
        .unwrap(),
        payout_before
    );

    // Same request id with other valid signed bytes is a conflict, while
    // damaged artifacts and existing output paths fail before any fence.
    let mut conflicting =
        codec::decode_signed_fee_claim_intent(&fs::read(&zero_first).unwrap()).unwrap();
    conflicting.intent.recipient = objects::Address::new(
        ed25519_zebra::VerificationKey::from(&ed25519_zebra::SigningKey::from([0x88; 32])).into(),
    );
    let digest =
        node_core::fee_claims::fee_claim_intent_digest(&fixture.resolver, &conflicting.intent)
            .unwrap();
    conflicting.signature = fixture.validators[key_index(zero[0])]
        .signing_key
        .sign(&node_core::fee_claims::fee_claim_signing_frame(&fixture.context, digest).unwrap())
        .into();
    let conflict: PathBuf = artifacts.fresh("economics-conflict");
    fs::write(
        &conflict,
        codec::encode_signed_fee_claim_intent(&conflicting).unwrap(),
    )
    .unwrap();
    let conflict_receipt: PathBuf = artifacts.fresh("economics-conflict-receipt");
    assert!(
        !apply(&cli, &fixture, &conflict, &conflict_receipt)
            .status
            .success()
    );
    assert_eq!(snapshot(&reopened, &namespace), finished);
    let fence = cli::current_fence(&reopened, &namespace);
    let exact_artifact: Vec<u8> = fs::read(&split).unwrap();
    assert!(!apply(&cli, &fixture, &split, &split).status.success());
    assert_eq!(fs::read(&split).unwrap(), exact_artifact);
    assert_eq!(cli::current_fence(&reopened, &namespace), fence);
    let mut wrong_signature = codec::decode_signed_fee_claim_intent(&exact_artifact).unwrap();
    wrong_signature.signature[0] ^= 1;
    let bad_signature: PathBuf = artifacts.fresh("economics-bad-signature");
    fs::write(
        &bad_signature,
        codec::encode_signed_fee_claim_intent(&wrong_signature).unwrap(),
    )
    .unwrap();
    let bad_signature_out: PathBuf = artifacts.fresh("economics-bad-signature-out");
    assert!(
        !apply(&cli, &fixture, &bad_signature, &bad_signature_out)
            .status
            .success()
    );
    assert!(!bad_signature_out.exists());
    assert_eq!(cli::current_fence(&reopened, &namespace), fence);
    let mut wrong_context = codec::decode_signed_fee_claim_intent(&exact_artifact).unwrap();
    wrong_context.intent.context = execution::publication::PublicationContext::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        protocol_types::Epoch::new(1),
    )
    .unwrap();
    let bad_context: PathBuf = artifacts.fresh("economics-bad-context");
    fs::write(
        &bad_context,
        codec::encode_signed_fee_claim_intent(&wrong_context).unwrap(),
    )
    .unwrap();
    let bad_context_out: PathBuf = artifacts.fresh("economics-bad-context-out");
    assert!(
        !apply(&cli, &fixture, &bad_context, &bad_context_out)
            .status
            .success()
    );
    assert!(!bad_context_out.exists());
    assert_eq!(cli::current_fence(&reopened, &namespace), fence);
    let corrupt: PathBuf = artifacts.fresh("economics-corrupt");
    fs::write(&corrupt, b"truncated").unwrap();
    let corrupt_out: PathBuf = artifacts.fresh("economics-corrupt-out");
    let fence = cli::current_fence(&reopened, &namespace);
    assert!(
        !apply(&cli, &fixture, &corrupt, &corrupt_out)
            .status
            .success()
    );
    assert_eq!(cli::current_fence(&reopened, &namespace), fence);
    assert_eq!(snapshot(&reopened, &namespace), finished);
    assert_eq!(
        decode_genesis_manifest(&fixture.manifest_bytes)
            .unwrap()
            .fee_policy
            .conversion_divisor,
        40_000
    );
}
