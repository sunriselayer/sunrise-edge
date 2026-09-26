# Closed PostgreSQL FastVote operator rehearsal

This is an operator-invoked, file-mediated rehearsal for the **genesis epoch**.
It does not expose FastVote over HTTP or launch a public network. Do not use
real assets or present a successful run as Phase 3, capacity, independent
validator hosting, or testnet certification. DR-0144 defines the trust
boundary; `TODO.md` tracks which executable checks have actually passed.

## Inputs and authority

Prepare these inputs independently of the database under examination:

- One canonical `GenesisManifest` file, signed by a single genesis authority.
  Its validator set must include every intended validator and one valid
  positive bond for each. Record its exact `genesis_manifest_commitment`
  digest and its chain, protocol version, epoch and complete ordered hash-
  suite schedule in trusted operator configuration. The genesis authority is
  **not** every validator and its private key is never used by this CLI.
- One canonical sender-signed paid intent file for a call admitted by that
  manifest's code, objects and fee policy. The sender key is distinct from
  the validator voting keys.
- For each validator, a different raw 32-byte Ed25519 seed file held only on
  that validator's operator machine. On Unix it must be a regular file with
  no group or other access bits (normally mode `0600`). Its derived public
  key must match the committed registration for the configured validator ID.
- A separately controlled PostgreSQL authority for each validator. The DSN
  comes from the protected `SUNRISE_EDGE_OPERATOR_POSTGRES_DSN` environment,
  never argv or a checked-in file. It must name one TCP host whose certificate
  validates against the DER root supplied by `--tls-root-der`. A shared test
  server with several namespaces demonstrates semantics only; it is not
  validator administrative isolation. On a shared rehearsal server, use a
  separate database **and** login per validator, revoke `PUBLIC` database
  `CONNECT`, and test cross-database denial. Even this proves only credential
  separation, not independent administrators, hosts, disks or backups
  ([DR-0145](../architecture/decisions/0145-postgres-phase3-capacity-and-validator-authority.md)).

The CLI consumes already signed canonical manifest and intent files; it does
not author either signature. Do not replace them with unsigned JSON or copy a
development-only fixed key into a deployment. All vote and certificate files
are untrusted delivery until checked against the committed validator set and
the independently configured context.

## Sequence

The examples use placeholders. Supply the exact trusted values, distinct
`VALIDATOR_ID`/key/DSN on each operator machine, and an output path that you
control. Do not put a DSN or raw signing seed into shell history. Stop any
other writer for the namespace before a command that advances its fence.

One-time namespace initialization (schema installation needs an explicitly
authorized database role):

```sh
cargo run --release -p sunrise-edge-operator --bin fastvote_pg -- namespace-init \
  --tls-root-der /secure/trusted-root.der \
  --chain-id YOUR_CHAIN_ID --validator-id YOUR_VALIDATOR_ID \
  --domain YOUR_DOMAIN_ID --confirm-namespace-bootstrap
```

Install or restart-verify the **same** signed manifest in every namespace:

```sh
cargo run --release -p sunrise-edge-operator --bin fastvote_pg -- install-genesis \
  --tls-root-der /secure/trusted-root.der \
  --chain-id YOUR_CHAIN_ID --validator-id YOUR_VALIDATOR_ID \
  --domain YOUR_DOMAIN_ID --protocol-version YOUR_PROTOCOL_VERSION \
  --epoch 0 --suite 0:1:1:1:1:1:1:1 \
  --genesis-manifest /secure/genesis.manifest \
  --expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --checkpoint 1 --timeout-seconds 60 --confirm-offline-fence-advance
```

Every validator then prepares the *same* sender-signed intent with its own
key. `--created-checkpoint` is the operator-configured checkpoint committed
into the prepared record; it must agree across validators for the staged
commitment to match.

```sh
cargo run --release -p sunrise-edge-operator --bin fastvote_pg -- prepare-vote \
  --tls-root-der /secure/trusted-root.der \
  --chain-id YOUR_CHAIN_ID --validator-id YOUR_VALIDATOR_ID \
  --domain YOUR_DOMAIN_ID --protocol-version YOUR_PROTOCOL_VERSION \
  --epoch 0 --suite 0:1:1:1:1:1:1:1 \
  --genesis-manifest /secure/genesis.manifest \
  --expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --signing-key-file /secure/validator-seed.bin \
  --paid-intent /secure/signed-paid-intent.bin \
  --created-checkpoint 1 --vote-output /secure/vote.bin \
  --timeout-seconds 60 --confirm-offline-fence-advance
```

Copy the canonical vote files by any channel. The channel does not authorize
votes. Assemble one quorum certificate from the independently pinned signed
manifest and at least a quorum of authentic matching votes:

```sh
cargo run --release -p sunrise-edge-operator --bin fastvote_pg -- assemble-certificate \
  --validator-set-source genesis-manifest \
  --chain-id YOUR_CHAIN_ID --protocol-version YOUR_PROTOCOL_VERSION \
  --epoch 0 --suite 0:1:1:1:1:1:1:1 \
  --genesis-manifest /secure/genesis.manifest \
  --expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --vote /secure/vote-a.bin --vote /secure/vote-b.bin \
  --vote /secure/vote-c.bin \
  --certificate-output /secure/fast-certificate.bin
```

Each validator applies that same certificate to its own prepared state:

```sh
cargo run --release -p sunrise-edge-operator --bin fastvote_pg -- apply-certificate \
  --tls-root-der /secure/trusted-root.der \
  --chain-id YOUR_CHAIN_ID --validator-id YOUR_VALIDATOR_ID \
  --domain YOUR_DOMAIN_ID --protocol-version YOUR_PROTOCOL_VERSION \
  --epoch 0 --suite 0:1:1:1:1:1:1:1 \
  --genesis-manifest /secure/genesis.manifest \
  --expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --paid-intent /secure/signed-paid-intent.bin \
  --certificate /secure/fast-certificate.bin \
  --response-output /secure/response.bin \
  --timeout-seconds 60 --confirm-offline-fence-advance
```

`--response-output` is optional; when used, it writes the one canonical
`NodeResponse` for byte-for-byte comparison across validators. Vote,
certificate and response outputs require fresh paths: the CLI refuses to
overwrite an existing file or follow an existing symlink. Use a new output
path for an exact replay and compare it with the previous output.

Every mutating invocation advances the namespace's persistent writer
generation. Stop other writers first and do not reuse their old generation.
If a command fails after its fence advance or durable commit, its prior state
may still have changed. Preserve its input bytes and retry **exactly** those
bytes or inspect the durable receipt; do not infer rollback from the absence
of a `complete=true` line. A conflicting request ID must be freshly signed
with a new ID, not forced through storage.

The first CLI profile deliberately rejects epoch transition rather than
reusing genesis policies after activation. The separate fee inventory command
can verify present escrow history while the validator is stopped. Actual
network ingress, validator admission and externally reachable testnet require
a separate authenticated transport decision and review.

## Rehearsal isolation and capacity checks

Provision a fresh database and distinct role for **each** validator before
`namespace-init`; [the PostgreSQL guide](postgres.md#validator-database-authority)
gives the privilege boundary. Run each of the four CLI sequences with only
that validator's DSN and signing-key file. Compare their response bytes after
quorum application, stop all writers, restart each operator, and replay the
same signed bytes. A second login must not be able to connect to the first
validator's database, even if it knows the chain, validator and domain IDs.

For a disposable database named `sunrise_edge_test`, the repository's
executable regression is:

```sh
# Supply SUNRISE_EDGE_TEST_POSTGRES_URL through a protected environment first.
bash scripts/check-fastvote-pg.sh
```

It runs the shared-namespace adversarial E2E, the distinct-database/role
quorum and denial E2E, and the bounded PostgreSQL fee-claim/reopen checks.
It requires a superuser login to a disposable PostgreSQL server reachable
through one loopback TCP host (`127.0.0.1`, `localhost` or `::1`) for test-only
role/database provisioning. It refuses other database names and must not
point at a persistent production server.

For a stopped validator, the fee-escrow inventory command is the finite
restart-sweep check. Its `--page-size` and `--timeout-seconds` bound each run;
it advances the writer fence, so restart the validator under the newer
generation. Record the exact row/claim/payout counts, elapsed wall time,
PostgreSQL version and instance/storage profile, and whether every page and
the final fence check completed. A partial run has no complete result.
Repository CI uses a disposable service and small fixtures; its timing does
not establish sustained claim throughput, disk life or a first-network
recovery-time budget. Representative deployment and longer soak evidence
remain separate before capacity certification.
