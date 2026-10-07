# Local SQLite validator preparation and startup

This guide prepares one original-epoch validator's independent local state
and blob databases, checks its public configuration, and starts the existing
loopback-only host. Each validator has its own database pair. PostgreSQL,
Cloudflare credentials and deployed Workers are not involved.

The authority boundaries are defined in
[DR-0195](../architecture/decisions/0195-local-sqlite-validator-startup.md).
Current completion and release gates remain only in [TODO](../../TODO.md).
Local startup does not approve public exposure, a genesis ceremony or custody
of real assets.

## Local commands

Build the shipped executables from the repository root:

```sh
cargo build --locked -p sunrise-edge-operator \
  --bin sqlite_genesis --bin sqlite_source_host
```

The following Bash example expects independently approved public inputs in
the environment. There is no network, credential or genesis fallback. Set
`SUITE_SPECS` to the complete approved schedule; the single entry shown is
only the format example used by local fixtures, not a production default.
Each specification is `epoch:id:transaction:object:effects:code:config:certificate`.

```bash
: "${CHAIN_ID:?}" "${VALIDATOR_ID_HEX:?}" "${DOMAIN_HEX:?}"
: "${PROTOCOL_VERSION:?}" "${EPOCH:?}"
: "${GENESIS_MANIFEST:?}" "${EXPECTED_GENESIS_DIGEST_HEX:?}"
: "${STATE_DB:?}" "${BLOB_DB:?}" "${CREATED_CHECKPOINT:?}"
SUITE_SPECS=('0:1:1:1:1:1:1:1')
ROOT_PINS=(
  --chain-id "$CHAIN_ID"
  --validator-id "$VALIDATOR_ID_HEX"
  --domain "$DOMAIN_HEX"
  --protocol-version "$PROTOCOL_VERSION"
  --epoch "$EPOCH"
  --genesis-manifest "$GENESIS_MANIFEST"
  --expected-genesis-digest "$EXPECTED_GENESIS_DIGEST_HEX"
)
for suite in "${SUITE_SPECS[@]}"; do
  ROOT_PINS+=(--suite "$suite")
done
DATABASE_PINS=(--state-db "$STATE_DB" --blob-db "$BLOB_DB")

target/debug/sqlite_genesis prepare \
  "${ROOT_PINS[@]}" "${DATABASE_PINS[@]}" \
  --created-checkpoint "$CREATED_CHECKPOINT"

: "${VALIDATOR_PUBLIC_KEY_HEX:?}"
target/debug/sqlite_genesis preflight \
  "${ROOT_PINS[@]}" "${DATABASE_PINS[@]}" \
  --validator-public-key "$VALIDATOR_PUBLIC_KEY_HEX"
```

Require exit zero and exactly one `complete=true` line. Preparation reports
`mode=prepare writer_fence=1`; preflight reports `mode=preflight advisory=true`
and the observed generation. Do not infer a guarantee from output left by a
failed process. Both local operations have a bounded 60-second storage context.

Only after stopping every competing writer, start the existing host:

```bash
: "${VALIDATOR_SIGNING_KEY_FILE:?}"
target/debug/sqlite_source_host \
  "${ROOT_PINS[@]}" "${DATABASE_PINS[@]}" \
  --signing-key-file "$VALIDATOR_SIGNING_KEY_FILE" \
  --listen 127.0.0.1:8701 \
  --created-checkpoint "$CREATED_CHECKPOINT" \
  --timeout-seconds 30 --max-concurrent 4 \
  --confirm-offline-fence-advance
```

The key-file loader requires a regular, protected local file, not a seed in
argv. Stop this process before running the same command again. Compare the
host's advertised generation with the previous one; it must increase. Use
different state/blob destinations and validator/key pins for each validator.

## Inputs and custody

Obtain the already signed original genesis manifest and its independently
trusted expected digest. Independently configure the chain, protocol version,
original epoch, complete hash-suite schedule, logical atomicity domain and
validator identity. The domain is local protocol configuration, not a value
authenticated by the manifest or inferred from a database filename.

Preparation accepts the defining genesis installer's supported profile: one
self-contained publication without dependencies, one Instantiate initializer,
and fee/economics resources pinned to that code and instance. It creates an
empty supported blob database; this does not establish generic paid code/body
closure. Use the ordinary paid publication and execution paths for subsequent
contracts. The Standard Asset package gains no special storage or node-core
authority from this preparation command.

Neither preparation nor preflight reads a private validator seed or signs a
transaction. Preflight requires the registered validator public key. Only the
serving host reads its protected signing-key file and derives the public key
again; a previous successful preflight is not serving authority.

## Fresh preparation

Choose two distinct unused paths in existing regular directories. Neither
main file may already exist, even as an empty file. Existing `-wal`, `-shm`
and `-journal` sidecars also refuse. Main/sidecar aliases between the two
normalized destinations, symlink ancestors and parent traversal refuse before
intentional destination creation.

Preparation initializes the ordinary namespace at writer generation 1, then
uses the existing signed-genesis and ordered-genesis installers at that same
generation. The two installers commit separately and the database files are
separate physical resources. This is not one cross-file atomic transaction.
The local clock supplies only the existing ordered pacemaker's liveness timer.

On failure, preserve any reserved or partially populated files for inspection.
There is no implicit resume, reset, overwrite or repair. A fresh attempt uses
new unused destinations; do not treat a partially prepared namespace as ready
to serve. A successful preparation synchronizes the created files and their
parent directories before advertising completion.

## Advisory preflight

Stop competing maintenance while preparing startup. Preflight inspects an
existing Ordinary/Unsealed original namespace without claiming a new writer
generation. It verifies the exact local root, fee policy, committee/live pin,
registered public key and existing ordered state. It refuses inactive imports,
Sealed namespaces and successors; the independently verified successor workflow
is described in [first-successor](first-successor.md).

The command compares two complete durable snapshot tokens around all deciding
reads. A changed namespace, domain, writer generation or mutation sequence
refuses. Successful output is explicitly advisory: another writer can change
the state immediately afterwards. The blob database is opened read-only and
its supported shape is checked, but it has no namespace-binding metadata; this
does not prove ownership of the state/blob pair.

Nonmutation means unchanged logical rows, objects, receipts, blob inventory,
writer generation and mutation sequence. Do not compare SQLite file hashes:
closing a connection can checkpoint WAL files without changing logical state.

## Serving and restart

The serving host keeps its existing flag-only invocation and requires explicit
offline-fence confirmation. Stop all other writers of this namespace first.
Every start claims a strictly newer writer generation once, then independently
rechecks its locally trusted root, fee, committee, protected signing key and
ordered state. It never installs, resets or repairs genesis or ordered state.

Keep the listener on loopback. Query context through the locally configured
transport and compare it with independent expected signing context before
submitting anything. The existing [FastVote network guide](fastvote-network.md)
describes quorum clients, paid Publish/Instantiate/Call, exact saved-artifact
replay and transport policy. Those rules are unchanged by SQLite preparation.

For a restart, stop the process, preserve both database files and all sidecars,
and start the same host with the same public pins and explicit offline-fence
confirmation. The new generation must be strictly greater than the previous
one. Never replace a running or previously prepared database with a fresh
genesis as a recovery shortcut. Subsequent epoch recovery and serving use the
existing verified successor path, not another original-genesis preparation.

For quiet local maintenance, finish client work, stop the external terminator
when present and wait for its forwarding worker, then send SIGINT to the exact
still-owned host and require an ordinary successful exit. Killing a child on
failed-test cleanup is not an orderly-stop result. Reopen the same state/blob
pair with the
same manifest, validator signing key and independently expected protocol/domain
pins; do not prepare it again. A certificate change is not permission to alter
any of those inputs or bypass explicit offline-fence confirmation.

## Local TLS and compiled CLI acceptance

### Optional direct Native termination

The original `sqlite_source_host` and both `successor_host serve` and
`serve-history` accept these additional local inputs (not `sqlite_genesis`,
activation or the single-validator devnet):

```text
--tls-cert-der-file LOCAL_LEAF.der
--tls-cert-der-file LOCAL_INTERMEDIATE.der
--tls-key-pkcs8-der-file LOCAL_PRIVATE_KEY.der
```

Supply one to four ordered leaf-first DER files and exactly one matching PKCS8
key, or omit both options for the existing plaintext mode. Each file must be a
nonempty nonsymlink regular file at most 16 KiB; the chain is at most 64 KiB.
The key requires private Unix permissions (use `0600`). Load/refusal completes
before genesis/state/blob I/O or fencing. A malformed, missing, nonprivate or
mismatched key never falls back to plaintext. Construction checks leaf/key
correspondence, not the full issuer/name/time policy of a production PKI.

Clients independently set their existing TLS server name/root and expected
protocol pins. Network config uses those per-peer TLS fields even for direct
loopback TLS endpoints. There is no mTLS, public bind, auto-renewal or reload.
For explicit stopped rotation, finish client work, SIGINT/reap the exact owned
host successfully, replace the configured leaf/key and restart at the same
endpoint with unchanged protocol/genesis/database/signing inputs. Live restart
requires offline confirmation and advances the fence; signerless history
restart claims no new generation. An unrelated CA change requires explicit new
client trust and does not revoke still-valid old leaves.

### Distinct executable fixtures

The storage-neutral process acceptance composes the real author, public
inspector, four independent prepared SQLite pairs and four serving processes.
Private loopback TLS terminators forward the actual host responses unchanged;
each peer has its own ephemeral CA and DNS identity. The separately compiled
CLI performs an ordinary paid Standard Asset transfer and replays its saved
intent/certificate/availability artifacts in the same boot and after all four
hosts restart. The private terminators retain their exact bound listeners, DNS
names and original CA files/configuration while new leaf keys/certificates are
issued by those same retained CAs. Fresh fully authenticated observations with
resumption disabled compare the actual received leaf DER, not just a successful
context query. Quiet host stops require successful owned-child SIGINT exits;
reopening advances each physical writer fence exactly 2 -> 3. Held old handles
must refuse both fresh-deadline reads and a valid captured marker commit without
changing its revision/value or any complete durable state.

A separate finite control reads and parses the selected CLI's actual ClientHello
before closing, without completing TLS or reaching a backend. Another separate
phase changes only peer 0's CA to a disposable issuer with a distinct subject,
keeping endpoint, DNS and the generation-3 host unchanged. Both held old SDK
trust and a fresh old-trust compiled CLI process must refuse precisely
with `UnknownIssuer`. Explicit new trust uses a new immutable DER file and a
cohort config changing only that peer's CA-file field. Actual new-leaf, context,
all-four stored-result replay and independent remote-domain refusal checks retain
the same complete object/receipt/nonce, record/blob and mutation-sequence oracles.

The separate DR-0219 direct-host case uses those same complete business
oracles without a relay: actual compiled hosts terminate TLS, the compiled CLI
commits a four-peer paid transfer, and same-boot/restarted saved results and
conflicting request IDs retain exact state, receipts, nonce, referenced blobs
and mutation sequences. Same-CA leaf rollover advances live fences 2 -> 3;
the separate peer-0 unrelated-CA stopped restart reopens all four hosts 3 -> 4.
Held old SDK/fresh old-trust CLI refuse exact `UnknownIssuer`, and explicit new
trust succeeds at unchanged endpoints/DNS with fresh authenticated received
DER/SPKI. Discarding a saved apply response qualifies receipt reconciliation,
not a fresh post-disconnect mutation or atomicity claim. Real direct successor
and no-fence history restart controls use the existing genuine recurring
workflow; its original recurrence/unlock and relay controls are retained.

The logical domain is the same across these replicas; the file
coordinates, validator identities, signing keys and TLS pins are distinct.

Build the actual executables before running this focused acceptance:

```sh
cargo build --locked -p sunrise-edge-operator --bins
cargo build --locked -p sunrise-edge-cli --bin sunrise-edge-cli --all-features
cargo test --locked -p sunrise-edge-operator --test local_tls_startup \
  --all-features -- --nocapture
```

These commands use disposable local fixtures, SQLite and numeric loopback
listeners. They need no PostgreSQL service or Cloudflare account. An absent
CLI binary is a failure, not a skip. Read-only public-pin negatives use an
absent key; actual selected-peer TLS and remote-context negatives use a valid
protected disposable key, so a missing-key error cannot mask a trust refusal.
Key derivation is not transaction signing, and missing output artifacts alone
are not a signature-count measurement.

See [DR-0199](../architecture/decisions/0199-local-tls-validator-startup-acceptance.md)
for full-state replay and request-ID conflict, and
[DR-0216](../architecture/decisions/0216-local-tls-stop-restart-rotation.md)
for the stopped-rotation boundary. Same-CA leaf rollover does not revoke other
still-valid leaves. [DR-0219](../architecture/decisions/0219-native-direct-tls-connection-ownership.md)
defines the separate shipped optional Native loader and lifecycle. Neither
fixture qualifies production PKI, hot reload, zero-downtime/overlapping-bundle
migration, CRL/OCSP, remote trust
distribution or a mainnet PKI/custody/power/load qualification. Passing
this focused test does not substitute for all required CI/local groups,
independent economics/ingress audits, real custody, a selected reviewed
activation profile or authorized network startup. The test TLS terminator is
not shipped authenticated ingress and must not be used to expose a validator.
