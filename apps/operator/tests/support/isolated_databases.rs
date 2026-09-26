//! Per-validator PostgreSQL database + login role provisioning for the
//! credential-isolation E2E.
//!
//! The `fastvote_pg` durable schema (`runtime_postgres`) is one globally
//! shared `sunrise_edge` schema keyed by a `(chain_id, validator_id, domain)`
//! namespace tuple, so two validators sharing one database and merely holding
//! separate PostgreSQL roles cannot be isolated from each other by GRANT
//! alone: a role with any table privilege in that shared schema can query or
//! write another validator's namespace tuple directly, and PostgreSQL has no
//! row-level default-deny for it. This module provisions one dedicated
//! database and one dedicated login role per validator instead, which *is*
//! a real isolation boundary: PostgreSQL enforces `CONNECT` privilege at the
//! database level before any table in it is ever reachable.
#![allow(dead_code)]

use postgres::{Config, NoTls, config::SslMode};
use std::time::{SystemTime, UNIX_EPOCH};

/// One test-provisioned validator database: a freshly created PostgreSQL
/// login role and a same-named database it exclusively owns, with `PUBLIC`
/// `CONNECT`/`TEMPORARY`/`CREATE` revoked so no role other than this one (or
/// a superuser, which bypasses the ACL system entirely) can even open a
/// connection to it.
pub struct IsolatedValidatorDatabase {
    pub role: String,
    pub database: String,
    pub password: String,
}

/// `count` isolated validator databases sharing one PostgreSQL server,
/// provisioned through a superuser admin connection and dropped (role,
/// database, and any lingering backend connections to it) on `Drop`,
/// best-effort, regardless of test outcome. Disposable-test-PG-only: the
/// admin connection must be a superuser (or at least `CREATEROLE`+
/// `CREATEDB`) connection, and this must never run against a persistent or
/// shared-production PostgreSQL server.
pub struct IsolatedDatabaseCluster {
    pub databases: Vec<IsolatedValidatorDatabase>,
    admin: Config,
}

fn unique_suffix() -> String {
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), (nanos & 0xffff_ffff) as u32)
}

fn admin_client(admin: &Config) -> postgres::Client {
    let mut config: Config = admin.clone();
    config.ssl_mode(SslMode::Disable);
    config.connect(NoTls).unwrap_or_else(|error| {
        panic!("failed to open superuser admin connection for test database provisioning: {error}")
    })
}

impl IsolatedDatabaseCluster {
    /// Creates `count` freshly named, uniquely suffixed
    /// `sre_fv_iso_<suffix>_v<index>` databases, each owned by its own
    /// freshly created same-named login role with a unique per-role
    /// password, with `PUBLIC` privileges revoked on each database.
    #[must_use]
    pub fn provision(admin: &Config, count: usize) -> Self {
        let suffix: String = unique_suffix();
        let mut client: postgres::Client = admin_client(admin);
        let current_database: String = client
            .query_one("SELECT current_database()", &[])
            .unwrap()
            .get(0);
        assert_eq!(
            current_database, "sunrise_edge_test",
            "refusing to create test roles or databases outside sunrise_edge_test"
        );
        let is_superuser: bool = client
            .query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .unwrap()
            .get(0);
        assert!(
            is_superuser,
            "isolated database test requires a disposable superuser test service"
        );

        // Construct the cleanup guard before the first DDL statement. If a
        // later CREATE DATABASE or REVOKE fails, unwinding still removes the
        // roles/databases that this invocation already created.
        let mut cluster: Self = Self {
            databases: Vec::with_capacity(count),
            admin: admin.clone(),
        };
        for index in 0..count {
            let role: String = format!("sre_fv_iso_{suffix}_v{index}");
            let database: String = role.clone();
            let password: String = format!("pw{suffix}v{index}{}", unique_suffix());
            // `CREATE ROLE`/`CREATE DATABASE`/`REVOKE` cannot share an
            // implicit multi-statement transaction block with each other in
            // PostgreSQL (`CREATE DATABASE` in particular must be the only
            // statement in its transaction), so each runs as its own,
            // separately round-tripped statement.
            client
                .execute(
                    &format!("CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"),
                    &[],
                )
                .unwrap_or_else(|error| {
                    panic!("failed to create isolated test role {role:?}: {error}")
                });
            cluster.databases.push(IsolatedValidatorDatabase {
                role: role.clone(),
                database: database.clone(),
                password,
            });
            client
                .execute(
                    &format!("CREATE DATABASE \"{database}\" OWNER \"{role}\""),
                    &[],
                )
                .unwrap_or_else(|error| {
                    panic!("failed to create isolated test database {database:?}: {error}")
                });
            client
                .execute(
                    &format!("REVOKE ALL ON DATABASE \"{database}\" FROM PUBLIC"),
                    &[],
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to revoke PUBLIC privileges on isolated test database \
                         {database:?}: {error}"
                    )
                });
        }
        cluster
    }

    /// A superuser (bypasses all grants, including the revoked `PUBLIC`
    /// privileges) direct connection config into one provisioned database,
    /// for out-of-band durable-state assertions that never use the isolated
    /// validator's own credentials.
    #[must_use]
    pub fn admin_config(&self, index: usize) -> Config {
        let mut config: Config = self.admin.clone();
        config.dbname(&self.databases[index].database);
        config.ssl_mode(SslMode::Disable);
        config
    }
}

impl Drop for IsolatedDatabaseCluster {
    fn drop(&mut self) {
        let mut config: Config = self.admin.clone();
        config.ssl_mode(SslMode::Disable);
        let Ok(mut client) = config.connect(NoTls) else {
            return; // best-effort cleanup only
        };
        for entry in &self.databases {
            let _ = client.execute(
                &format!(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = '{}' AND pid <> pg_backend_pid()",
                    entry.database
                ),
                &[],
            );
            let _ = client.execute(
                &format!("DROP DATABASE IF EXISTS \"{}\"", entry.database),
                &[],
            );
            let _ = client.execute(&format!("DROP ROLE IF EXISTS \"{}\"", entry.role), &[]);
        }
    }
}
