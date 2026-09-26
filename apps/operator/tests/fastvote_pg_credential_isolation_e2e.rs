//! Live, multi-process, multi-validator, **per-validator-database**
//! credential-isolation E2E for the `fastvote_pg` operator CLI
//! (DR-0126/DR-0129/DR-0130).
//!
//! `fastvote_pg_e2e.rs` proves the closed FastVote workflow across four
//! validators sharing one PostgreSQL database, each in its own
//! `(chain_id, validator_id, domain)` namespace tuple inside the shared
//! `sunrise_edge` schema. That is not credential isolation: any role with
//! ordinary table privileges in that one shared schema can read or write
//! every other validator's namespace tuple directly, regardless of which
//! login role issued the query. This test instead gives every validator its
//! own dedicated PostgreSQL **database** and login **role**
//! (`support::isolated_databases`), with `PUBLIC` privileges revoked on each
//! database, and drives every real CLI subprocess with its own per-validator
//! DSN. It proves both:
//!
//! 1. **Positive**: the full closed FastVote workflow (namespace-init,
//!    install-genesis, prepare-vote x4, a 3-of-4 certificate, apply-
//!    certificate x4, an idempotent replay) still succeeds end to end
//!    across four separate databases, with the same quorum/consistency
//!    assertions as the shared-database E2E.
//! 2. **Negative**: validator B's credentials cannot even open a PostgreSQL
//!    connection to validator A's database (a real, live database-level
//!    authorization failure, not a permission check inside a shared schema), and a real
//!    `fastvote_pg` subprocess attempting to claim A's validator identity
//!    while authenticated as B never touches A's actual durable state --
//!    A's real writer fence and durable snapshot are byte-for-byte
//!    unaffected by every such attempt.
//!
//! Skips (with a diagnostic on stderr) unless `SUNRISE_EDGE_TEST_POSTGRES_URL`
//! is configured, exactly like every other live PostgreSQL test in this
//! repository. The configured URL's role must have at least `CREATEROLE`
//! and `CREATEDB` (ordinarily a superuser, for a disposable test PostgreSQL
//! server only): this test creates and, best-effort, tears down its own
//! uniquely named roles and databases, and never touches any other
//! persistent or shared data.

mod support;

use ed25519_zebra::{SigningKey, VerificationKey};
use postgres::{Config, NoTls, config::SslMode};
use protocol_types::ValidatorId;
use runtime::{
    DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
};
use runtime_postgres::PostgresNamespace;
use std::{
    net::SocketAddr,
    num::NonZeroU32,
    path::PathBuf,
    process::Output,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use support::cli::{
    CliContext, DurableSnapshot, TempFileGuard, admin_pool, apply_certificate,
    assemble_certificate, assert_stdout_contains, bounded_temp_file, current_fence,
    install_genesis, namespace_init, namespace_init_allow_failure, prepare_vote, proxied_dsn_for,
    single_tcp_backend_addr, snapshot, temp_path, to_hex, write_signing_key_file,
};
use support::genesis_fixture::{self, FastVoteGenesisFixture};
use support::isolated_databases::IsolatedDatabaseCluster;

const VALIDATOR_COUNT: usize = 4;

#[test]
#[ignore = "requires a disposable, superuser-accessible live PostgreSQL server"]
fn fastvote_pg_operator_credential_isolated_multivalidator_e2e() {
    let Some(database_url) = support::live_postgres_url() else {
        eprintln!(
            "skipping live PostgreSQL fastvote_pg credential-isolation E2E: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };

    // Acquired before any live-database work, shared with every other live
    // PostgreSQL test family in this repository.
    let _live_test_lock = support::LiveTestLock::acquire();

    let admin_config: Config = Config::from_str(&database_url).unwrap();
    let backend_addr: SocketAddr =
        single_tcp_backend_addr(&admin_config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    let (ca_path, _ca_guard) = bounded_temp_file("ca", &ca_der);
    let proxy_port: u16 = proxy.local_addr().port();

    // Four dedicated databases + login roles, `PUBLIC` revoked on each,
    // dropped (best-effort) on scope exit regardless of test outcome.
    let cluster: IsolatedDatabaseCluster =
        IsolatedDatabaseCluster::provision(&admin_config, VALIDATOR_COUNT);

    let unique: String = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: FastVoteGenesisFixture = genesis_fixture::build_fixture(&format!("ci-{unique}"));
    let (manifest_path, _manifest_guard) =
        bounded_temp_file("genesis-manifest", &fixture.manifest_bytes);
    let (paid_intent_path, _paid_intent_guard) =
        bounded_temp_file("paid-intent", &fixture.paid_intent_bytes);
    let digest_hex: String = to_hex(&fixture.manifest_digest);
    let domain_hex: String = format!("{}", fixture.domain);
    let chain_id: String = format!("{}", fixture.chain_id);

    let validator_hex: Vec<String> = fixture
        .validators
        .iter()
        .map(|validator| format!("{}", validator.validator_id))
        .collect();
    let key_files: Vec<(PathBuf, TempFileGuard)> = fixture
        .validators
        .iter()
        .map(|validator| write_signing_key_file(&validator.seed))
        .collect();

    // One `CliContext` per validator, each pointing through the *same*
    // shared TLS relay/backend, but with that validator's own dedicated
    // database and login role baked into its DSN.
    let dsns: Vec<String> = cluster
        .databases
        .iter()
        .map(|entry| {
            proxied_dsn_for(
                &entry.role,
                Some(&entry.password),
                &entry.database,
                proxy_port,
            )
        })
        .collect();
    let clis: Vec<CliContext<'_>> = dsns
        .iter()
        .map(|dsn| CliContext {
            ca_path: &ca_path,
            dsn,
            chain_id: chain_id.clone(),
            manifest_path: &manifest_path,
            digest_hex: digest_hex.clone(),
        })
        .collect();

    // ==================== positive: full workflow, four separate DBs ====================

    for (index, cli) in clis.iter().enumerate() {
        let first: Output = namespace_init(cli, &validator_hex[index], &domain_hex);
        for field in [
            "complete=true",
            &format!("chain_id={chain_id}"),
            &format!("validator_id={}", validator_hex[index]),
            &format!("domain={domain_hex}"),
            "writer_fence=1",
        ] {
            assert_stdout_contains(&first, field);
        }

        let installed: Output = install_genesis(cli, &validator_hex[index], &domain_hex, true);
        for field in [
            "complete=true",
            "outcome=fresh_install",
            "writer_generation=2",
            &format!("manifest_digest={digest_hex}"),
        ] {
            assert_stdout_contains(&installed, field);
        }
    }

    let mut vote_paths: Vec<PathBuf> = Vec::with_capacity(VALIDATOR_COUNT);
    let mut vote_guards: Vec<TempFileGuard> = Vec::with_capacity(VALIDATOR_COUNT);
    let mut vote_fields: Vec<(String, String, String)> = Vec::with_capacity(VALIDATOR_COUNT);
    for index in 0..VALIDATOR_COUNT {
        let vote_output: PathBuf = temp_path(&format!("ci-vote-{index}"));
        let prepared: Output = prepare_vote(
            &clis[index],
            &validator_hex[index],
            &domain_hex,
            &key_files[index].0,
            &paid_intent_path,
            &vote_output,
            true,
        );
        assert_stdout_contains(&prepared, "complete=true");
        assert_stdout_contains(&prepared, "writer_generation=3");
        let stdout: String = String::from_utf8_lossy(&prepared.stdout).into_owned();
        let field = |name: &str| -> String {
            stdout
                .split_whitespace()
                .find_map(|token| token.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing {name} in prepare-vote stdout: {stdout}"))
                .to_owned()
        };
        vote_fields.push((
            field("tx_hash"),
            field("execution_effects_hash"),
            field("locked_objects_digest"),
        ));
        vote_paths.push(vote_output.clone());
        vote_guards.push(TempFileGuard(vote_output));
    }
    // Deterministic execution across four fully independent databases: all
    // four validators, each executing the identical real paid intent
    // against their own independently installed copy of the identical
    // genesis in their own database, derive byte-identical vote headers.
    for fields in &vote_fields[1..] {
        assert_eq!(fields, &vote_fields[0]);
    }

    let certificate_path: PathBuf = temp_path("ci-certificate");
    let assembled: Output = assemble_certificate(&clis[0], &vote_paths[..3], &certificate_path);
    assert!(
        assembled.status.success(),
        "assemble-certificate (3-of-4) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&assembled.stdout),
        String::from_utf8_lossy(&assembled.stderr)
    );
    for field in [
        "complete=true",
        "votes_supplied=3",
        "votes_in_certificate=3",
    ] {
        assert_stdout_contains(&assembled, field);
    }
    let _certificate_guard = TempFileGuard(certificate_path.clone());

    let mut first_responses: Vec<Vec<u8>> = Vec::with_capacity(VALIDATOR_COUNT);
    let mut response_guards: Vec<TempFileGuard> = Vec::with_capacity(VALIDATOR_COUNT);
    for index in 0..VALIDATOR_COUNT {
        let response_path: PathBuf = temp_path(&format!("ci-response-{index}"));
        let applied: Output = apply_certificate(
            &clis[index],
            &validator_hex[index],
            &domain_hex,
            &paid_intent_path,
            &certificate_path,
            &response_path,
            true,
        );
        for field in ["complete=true", "writer_generation=4"] {
            assert_stdout_contains(&applied, field);
        }
        first_responses.push(std::fs::read(&response_path).unwrap());
        response_guards.push(TempFileGuard(response_path));
    }
    for response in &first_responses[1..] {
        assert_eq!(response, &first_responses[0]);
    }

    // Independent, per-database re-verification (direct superuser
    // connections, each into that validator's own physical database).
    let namespaces: Vec<PostgresNamespace> = fixture
        .validators
        .iter()
        .map(|validator| {
            PostgresNamespace::new(&fixture.chain_id, validator.validator_id, fixture.domain)
                .unwrap()
        })
        .collect();
    let admin_pools: Vec<_> = (0..VALIDATOR_COUNT)
        .map(|index| admin_pool(&cluster.admin_config(index)))
        .collect();
    let first_snapshots: Vec<DurableSnapshot> = (0..VALIDATOR_COUNT)
        .map(|index| snapshot(&admin_pools[index], &namespaces[index], &fixture))
        .collect();
    for snapshot in &first_snapshots {
        assert!(
            snapshot.certificate_record.is_some(),
            "applied certificate must leave a permanent audit record in the validator's own database"
        );
    }

    // Idempotent replay after independent per-database re-verification: must
    // stay byte-identical.
    for index in 0..VALIDATOR_COUNT {
        let replay_response_path: PathBuf = temp_path(&format!("ci-replay-response-{index}"));
        let applied_again: Output = apply_certificate(
            &clis[index],
            &validator_hex[index],
            &domain_hex,
            &paid_intent_path,
            &certificate_path,
            &replay_response_path,
            true,
        );
        assert_stdout_contains(&applied_again, "complete=true");
        assert_stdout_contains(&applied_again, "writer_generation=5");
        assert_eq!(
            std::fs::read(&replay_response_path).unwrap(),
            first_responses[index]
        );
        let _replay_response_guard: TempFileGuard = TempFileGuard(replay_response_path);
    }
    let second_snapshots: Vec<DurableSnapshot> = (0..VALIDATOR_COUNT)
        .map(|index| snapshot(&admin_pools[index], &namespaces[index], &fixture))
        .collect();
    assert_eq!(
        first_snapshots, second_snapshots,
        "an idempotent replay must leave byte-identical durable receipt/object/nonce state in \
         each validator's own database"
    );

    // ==================== negative: credential isolation ====================

    // ---- (1) B's role/password cannot CONNECT to A's database ----
    // A plain, direct (no TLS relay) connection attempt using validator[1]'s
    // real role and password but validator[0]'s dbname: `PUBLIC` was revoked
    // on every database at provisioning time and validator[1]'s role was
    // never individually granted `CONNECT` on validator[0]'s database, so
    // PostgreSQL itself must refuse the connection before any query ever
    // runs.
    let mut cross_db_config: Config = admin_config.clone();
    cross_db_config.ssl_mode(SslMode::Disable);
    cross_db_config.user(&cluster.databases[1].role);
    cross_db_config.password(&cluster.databases[1].password);
    cross_db_config.dbname(&cluster.databases[0].database);
    let cross_db_error: postgres::Error = match cross_db_config.connect(NoTls) {
        Ok(_) => panic!("validator[1]'s credentials must never CONNECT to validator[0]'s database"),
        Err(error) => error,
    };
    assert_eq!(
        cross_db_error.code().map(|code| code.code()),
        Some("42501"),
        "cross-database refusal must be PostgreSQL's insufficient-privilege error"
    );

    // Sanity: the same role/password legitimately connects to its own
    // database, proving the failure above is specifically about database
    // access, not a bad password.
    let mut own_db_config: Config = admin_config.clone();
    own_db_config.ssl_mode(SslMode::Disable);
    own_db_config.user(&cluster.databases[1].role);
    own_db_config.password(&cluster.databases[1].password);
    own_db_config.dbname(&cluster.databases[1].database);
    assert!(
        own_db_config.connect(NoTls).is_ok(),
        "validator[1]'s own credentials must still connect to validator[1]'s own database"
    );

    // ---- (2) a real fastvote_pg subprocess authenticated as B, targeting A's
    //      identity strings, can never reach A's actual durable state ----
    let fence_before_cross_attempt = current_fence(&admin_pools[0], &namespaces[0]);
    let cross_dsn: String = proxied_dsn_for(
        &cluster.databases[1].role,
        Some(&cluster.databases[1].password),
        &cluster.databases[0].database,
        proxy_port,
    );
    let cross_cli: CliContext<'_> = CliContext {
        ca_path: &ca_path,
        dsn: &cross_dsn,
        chain_id: chain_id.clone(),
        manifest_path: &manifest_path,
        digest_hex: digest_hex.clone(),
    };
    let cross_attempt: Output =
        namespace_init_allow_failure(&cross_cli, &validator_hex[0], &domain_hex);
    assert!(
        !cross_attempt.status.success(),
        "a fastvote_pg subprocess authenticated as validator[1] must fail to operate against \
         validator[0]'s database, even when claiming validator[0]'s own validator-id/domain"
    );
    assert!(cross_attempt.stdout.is_empty());
    let cross_stderr: String = String::from_utf8_lossy(&cross_attempt.stderr).into_owned();
    assert!(
        cross_stderr.contains("PostgreSQL TLS connection or pool initialization failed")
            || cross_stderr.contains("PostgreSQL TLS connection unavailable"),
        "cross-database CLI failure must be a PostgreSQL connection refusal: {cross_stderr}"
    );
    assert_eq!(
        current_fence(&admin_pools[0], &namespaces[0]),
        fence_before_cross_attempt,
        "a failed cross-database attempt must never advance validator[0]'s real writer fence"
    );
    assert_eq!(
        snapshot(&admin_pools[0], &namespaces[0], &fixture),
        second_snapshots[0],
        "a failed cross-database attempt must leave validator[0]'s real durable state untouched"
    );

    // ---- (3) even a *legitimate* connection as B, claiming A's validator-id
    //      inside B's own database, can never reach A's real database ----
    // This is the crux of the isolation requirement: the shared
    // `sunrise_edge` schema keys everything by a `(chain_id, validator_id,
    // domain)` tuple, so validator[1] can freely create a namespace row
    // labeled with validator[0]'s id -- but only inside validator[1]'s own,
    // physically separate database. It can never be the same row as
    // validator[0]'s real namespace.
    let claimed_in_b: Output = namespace_init(&clis[1], &validator_hex[0], &domain_hex);
    assert_stdout_contains(&claimed_in_b, "complete=true");
    assert_stdout_contains(&claimed_in_b, "writer_fence=1");
    assert_eq!(
        current_fence(&admin_pools[0], &namespaces[0]),
        fence_before_cross_attempt,
        "validator[1] claiming validator[0]'s identity inside its own database must not affect \
         validator[0]'s real writer fence"
    );
    assert_eq!(
        snapshot(&admin_pools[0], &namespaces[0], &fixture),
        second_snapshots[0],
        "validator[1] claiming validator[0]'s identity inside its own database must not affect \
         validator[0]'s real durable state"
    );
    // The row it did create lives only inside validator[1]'s own database,
    // reachable only through validator[1]'s own admin connection/pool, at
    // exactly fence 1 (a fresh, otherwise-untouched namespace), never
    // colliding with validator[1]'s own real namespace (already at fence 5).
    let namespace_claimed_in_b: PostgresNamespace = PostgresNamespace::new(
        &fixture.chain_id,
        fixture.validators[0].validator_id,
        fixture.domain,
    )
    .unwrap();
    assert_eq!(
        current_fence(&admin_pools[1], &namespace_claimed_in_b).get(),
        1
    );
    assert_eq!(current_fence(&admin_pools[1], &namespaces[1]).get(), 5);

    // ---- (4) a scratch identity's database is unaffected by any of the above ----
    let scratch_seed: [u8; 32] = [0xC0; 32];
    let scratch_key: SigningKey = SigningKey::from(scratch_seed);
    let scratch_public: [u8; 32] = VerificationKey::from(&scratch_key).into();
    let scratch_id: ValidatorId = ValidatorId::new(scratch_public);
    let scratch_hex: String = format!("{scratch_id}");
    // validator[2]'s own, legitimate database: proves a scratch identity
    // installed there is independent of every other validator's database.
    let scratch_namespace: PostgresNamespace =
        PostgresNamespace::new(&fixture.chain_id, scratch_id, fixture.domain).unwrap();
    namespace_init(&clis[2], &scratch_hex, &domain_hex);
    assert_eq!(current_fence(&admin_pools[2], &scratch_namespace).get(), 1);
    assert_eq!(
        current_fence(&admin_pools[0], &namespaces[0]),
        fence_before_cross_attempt
    );
    assert_eq!(current_fence(&admin_pools[3], &namespaces[3]).get(), 5);

    // ---- (5) out-of-band read: validator[0]'s durable object/nonce state
    //      independently re-verified once more via node_core's own public
    //      query helpers, directly against validator[0]'s own database,
    //      completely unaffected by every isolation negative above ----
    let read_context: DurableOperationContext = DurableOperationContext::new(
        current_fence(&admin_pools[0], &namespaces[0]),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x44; 16]).unwrap(),
    );
    let store = runtime_postgres::PostgresDurableStore::new(
        admin_pools[0].clone(),
        namespaces[0].clone(),
        runtime_postgres::PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    );
    let certificate_key: Vec<u8> = node_core::local_instance_state::fastpath_certificate_key(
        &fixture.chain_id,
        &fixture.request_id,
    )
    .unwrap();
    assert!(
        store
            .get_versioned_durable(&read_context, fixture.domain, &certificate_key)
            .unwrap()
            .value()
            .is_some(),
        "validator[0]'s real applied-certificate record must still be present and readable in \
         its own database after every credential-isolation negative"
    );

    let created_roles: Vec<String> = cluster
        .databases
        .iter()
        .map(|entry| entry.role.clone())
        .collect();
    drop(store);
    drop(admin_pools);
    drop(proxy);
    drop(cluster);
    let mut cleanup_admin_config: Config = admin_config.clone();
    cleanup_admin_config.ssl_mode(SslMode::Disable);
    let mut cleanup_admin: postgres::Client = cleanup_admin_config.connect(NoTls).unwrap();
    for role in created_roles {
        let exists: bool = cleanup_admin
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
                &[&role],
            )
            .unwrap()
            .get(0);
        assert!(
            !exists,
            "test-created validator role must be removed: {role}"
        );
    }
}
