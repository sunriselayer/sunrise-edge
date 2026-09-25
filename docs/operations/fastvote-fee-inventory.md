# FastVote fee-escrow inventory

The operator executables verify every **present** certified fee-escrow
settlement key for one existing validator namespace. They are offline
maintenance checks, not network-capacity or rollback proofs.

## Local SQLite

`fee_escrow_inventory` targets one stopped local SQLite validator.

1. Stop the validator and keep its data directory on the same local
   filesystem. Do not run this against a live node or a mutable copy.
2. Obtain the chain ID, validator ID, domain, protocol version and exact
   ordered hash-suite schedule from the trusted network configuration. Do
   not derive the expected values from the files under examination.
3. Run the command below. Each `--suite` is
   `activation_epoch:suite_id:transaction:object:effects:code:config:certificate`;
   the six algorithm fields use decimal wire IDs (1 = SHA-256, 2 = SHA3-256).
   Add one `--suite` for every activation, beginning at epoch 0. Use a small
   page size; each row performs full cryptographic and object-history checks.

```sh
cargo run --release -p sunrise-edge-devnet --bin fee_escrow_inventory -- \
  --data-dir /path/to/stopped-validator-data \
  --chain-id YOUR_CHAIN_ID \
  --validator-id YOUR_64_HEX_DIGIT_VALIDATOR_ID \
  --domain YOUR_64_HEX_DIGIT_DOMAIN_ID \
  --protocol-version YOUR_VERSION \
  --suite 0:1:1:1:1:1:1:1 \
  --page-size 32 --timeout-seconds 3600 \
  --confirm-offline-fence-advance
```

The confirmation flag acknowledges a **persistent writer-fence advance**.
It invalidates the stopped process's prior generation; restart that process
normally after the check. If another process starts while the sweep runs,
the command fails and its partial count must be discarded **if that process
uses the supported boot path that advances the fence**. A direct SQLite writer
that bypasses boot and adopts the sweep's generation is outside this proof;
keep the database offline and under operator control. Success prints
`complete=true`, namespace/data-directory identity, claimed generation, page
count, verified rows, claims and
signed split payouts. Any error exits nonzero without a complete result.
Keep the command output with the independently recorded stop/start and
configuration evidence. Zero rows means only that this namespace contains
no present settlement keys; it is not evidence of no earlier deleted rows.

The certified nonempty two-escrow executable regression is run by
`scripts/check-fee-escrow-inventory.sh`. It uses genuine quorum-certified
prepare/apply and a closed/reopened file-backed store, then asserts two
verified rows over two pages and the advanced writer fence. That fixture
does not exercise a blob-backed object or a PostgreSQL deployment.

## PostgreSQL first-network profile

`fee_escrow_inventory_pg` uses the same verifier with an existing
PostgreSQL structured namespace and namespace-bound `PostgresBlobStore`.
Stop the validator first and deny other writers access for the entire run.
The PostgreSQL DSN must be supplied through the protected operator
environment as `SUNRISE_EDGE_OPERATOR_POSTGRES_DSN`; do not put credentials
in shell history, command arguments or captured logs. It must name exactly
one TCP host. The CLI forces TLS and authenticates its certificate against
the supplied DER-encoded root CA (convert a PEM CA to DER offline if needed).
The hostname in the DSN must match the server certificate. A local TLS
terminator proves only that client leg, not provider/server TLS policy.

```sh
cargo run --release -p sunrise-edge-operator --bin fee_escrow_inventory_pg -- \
  --tls-root-der /secure/path/to/trusted-root.der \
  --chain-id YOUR_CHAIN_ID \
  --validator-id YOUR_64_HEX_DIGIT_VALIDATOR_ID \
  --domain YOUR_64_HEX_DIGIT_DOMAIN_ID \
  --protocol-version YOUR_VERSION \
  --suite 0:1:1:1:1:1:1:1 \
  --page-size 32 --timeout-seconds 3600 \
  --confirm-offline-fence-advance
```

Supply the expected namespace, protocol version and complete hash-suite
schedule from independent trusted configuration, not the database under
inspection. The command validates the existing blob schema and namespace
before claiming the next persistent PostgreSQL writer generation, scans
under that generation, rechecks it and the deadline, and prints
`complete=true backend=postgres` only on full success. A failure after the
fence advance is still disruptive: restart the stopped validator under its
new generation. An empty result verifies only an empty *present* prefix.
The command supplies no historical protocol-version resolver: a claim that
requires one fails closed. Hash-suite changes within the configured protocol
version are supported by the ordered `--suite` entries.

`scripts/check-fee-escrow-inventory-pg.sh` runs an executable live-PostgreSQL
regression when `SUNRISE_EDGE_TEST_POSTGRES_URL` names the isolated test
database. It creates two genuine quorum-certified escrows and executes five
signed claims, including positive split/final and zero-share claims, with two
verified payout objects. It closes and reopens the PostgreSQL pool, then
launches this exact operator binary over a certificate-validated test TLS
relay. A page size of one verifies two rows over two pages; two operator runs
advance the persisted writer fence from generation one to three, and a stale
generation-two read fails closed. The relay authenticates only the client-to-
relay leg; it does not certify production PostgreSQL-server TLS or PKI.

The current Standard Asset `Coin` body is a fixed `u64`, so this genuine fee
fixture cannot create a blob-backed escrow object. The test passes the real
namespace-bound `PostgresBlobStore` through preparation, application, claims
and inventory, but does **not** execute a blob-reference object-history read.
DR-0143 records why that unreachable case is no longer a first-network gate
for this fee profile and why a future large-bodied fee resource would need
its own E2E. Representative claim rate, load/soak, restart-sweep capacity,
the Phase 3 review gate, external validator ingress and network activation
remain open. See [DR-0142](../architecture/decisions/0142-fastvote-operator-escrow-inventory.md),
[DR-0143](../architecture/decisions/0143-postgres-first-network-escrow-operations.md)
and [`TODO.md`](../../TODO.md).
