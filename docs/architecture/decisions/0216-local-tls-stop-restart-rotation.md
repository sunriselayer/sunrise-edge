# DR-0216: Owned local TLS stop, restart and explicit trust rotation

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted design after independent Codex fallback DESIGN APPROVE and
parent review against `afac7908` on 2026-10-07. This approves the local test
composition below, not source, execution, production PKI or public activation.
Current implementation and remaining qualification belong only in TODO.md.

## Context and boundary

[DR-0199](0199-local-tls-validator-startup-acceptance.md) composes actual compiled
original hosts, independent SQLite pairs and the separately compiled paid CLI.
Its private TLS relays forward real responses but recreate CA, DNS and endpoint
together on restart. Kill/reap cleanup alone does not establish an orderly host
stop. A successful context query alone does not identify the actual served leaf.

The shipped original host binds loopback plaintext and already supports Ctrl-C
shutdown and explicit stopped reopening. SDK/CLI TLS constructors already own
explicit CA/DNS pins independently of expected protocol context. No production
certificate loader, reload API, watcher or orchestration framework is needed
for this local evidence boundary. Disposable TLS keys are independent of all
unchanged validator and application signing keys.

## Decision and defining owners

Extend the existing nonignored four-validator `local_tls_startup` acceptance
once, rather than add a heavy CI lane or a second authored network. Keep every
original refusal, request-ID conflict, exact-replay and semantic paid-effect
oracle. Production code, wire bytes, schema, economics, signer selection and
required/selected-PG gate behavior remain unchanged.

- `apps/operator/tests/support/https_relay.rs` owns disposable CA/leaf identity,
  the exact bound loopback listener, bounded transparent forwarding and its
  transport counters. An explicit stop joins the worker successfully and returns
  that same still-bound listener. No port rebind or alternate endpoint fallback.
- `apps/operator/tests/support/compiled_source_host_process.rs` adds only a
  test-private orderly stop of its exact owned child. A bounded argument-array
  helper sends SIGINT to a positive, still-owned and unreaped PID; both helper
  and child waits are bounded. Reap and require successful ordinary exit.
  Retain the guard until then; forced kill/reap is failure cleanup, never the
  success oracle. Do not signal an already reaped child. No unsafe signal code.
- `apps/operator/tests/local_tls_startup.rs` owns the coherent sequence, complete
  state comparison and exact refusal/replay assertions. Reuse existing author,
  inspector, preparation, host invocation, artifact and snapshot owners.
- The [SQLite startup guide](../../guides/sqlite-validator-startup.md) explains
  explicit stopped rotation and its limits; architecture records the contract
  and TODO alone records execution/readiness.

Retain nonblocking listener acceptance and existing connection-count, lifetime,
socket/deadline, header/body/response and child-process bounds. Worker panic,
missing listener, missing executable or deadline failure is failure, never a
skip or permission to bind an alternative endpoint.

## Required coherent sequence

1. Author and independently inspect one original genesis. Prepare four original
   independent SQLite pairs and start actual hosts at writer generation 2.
   Peer `i` owns CA `A_i`, DNS `N_i`, leaf `L_i1` and bound listener `E_i`.
   Observe the actual initial leaf and commit the ordinary paid transfer.
   Save its exact intent, FastCertificate, availability certificate, result,
   canonical queries and complete per-namespace business snapshots.
2. Under each retained `A_i`, issue `L_i2` with fresh leaf key material. Require
   unchanged CA DER and distinct old/new leaf DER and keys. Finish client work,
   explicitly stop/join relays and retain `E_i`, then SIGINT and successfully
   reap the four actual hosts. Keep original files/sidecars, seeds, manifest,
   validator identity, committee and all independent protocol/domain pins.
3. Start the identical original host invocation with explicit offline-fence
   confirmation. Require persisted and reported writer generation exactly
   2 -> 3, once per pair. Attach restarted relay workers using `L_i2` and the
   retained `E_i` to the actual new backend coordinates. Client endpoints, DNS,
   original CA files and cohort configuration remain byte-for-byte unchanged.
4. Observe the received peer leaf only after a complete authenticated handshake
   with independent `A_i`/`N_i` pins, a fresh client configuration and resumption
   disabled. Require received DER equal to independently retained `L_i2` and
   different from `L_i1`. Fixture generations share no server resumption state.
   This is an actual-leaf test oracle, not a production leaf-pinning policy.
5. Ordinary SDK and compiled CLI using original trust query and replay all four
   saved results. Require actual stored-result acknowledgements and forwarded
   POST attempts on every backend, exact canonical object/receipt/nonce/result
   bytes and unchanged complete records, referenced blobs and mutation sequences.
   Physical writer fences may differ between replicas; never compare SQLite
   file hashes or demand equal per-validator voting records.
6. Before restart, retain a generation-2 handle and a genuine existing marker's
   revision/value. After restart, fresh-deadline reads and a valid captured
   transaction commit must refuse with `WriterFenced { active_generation: 3 }`.
   Recheck complete state and marker revision unchanged. An invalid transaction
   or expired context must not substitute for the stale-writer oracle.
7. On peer 0's retained `E_0`, run one finite pre-handshake-close worker. Prove it
   accepted the selected compiled CLI connection and read an actual ClientHello
   before closing, without a backend socket, completed handshake, HTTP or signed
   result. Use the valid disposable signing key and exact handshake-closed
   diagnostic. Preserve nonvacuous transport counters, absent new artifacts and
   complete unchanged snapshots. Join before returning the listener and restoring
   the ordinary relay. Do not manufacture TLS messages or encoded failures.
8. Separately replace peer 0's TLS identity with unrelated CA `B_0` and leaf
   `L_03`, retaining `N_0`, `E_0` and the generation-3 backend unchanged. Give
   `B_0` a distinct issuer subject/DN from `A_0`, not the stable leaf DNS name:
   same-subject unrelated keys can produce a signature error instead of the
   required exact `UnknownIssuer`. Preserve the old CA file/config bytes.
   Both a held old SDK transport and fresh old-trust compiled CLI must refuse
   at the same endpoint with that exact certificate error. Compare old/new
   trust using compiled context and the selected-peer paid refusal helper.
9. Create a new immutable `B_0` DER file and cohort config changing only peer 0's
   CA-file field. A fresh explicit-new-root SDK/CLI authenticates the actual
   `L_03`; observe its received DER, unequal to `L_02`. Query and replay all four
   saved results unchanged, with actual all-backend delivery. This CA phase
   restarts no backend and advances no fence. Repeat the independent remote
   protocol/domain refusal under valid new TLS. Unknown trust never causes
   automatic re-pin, fallback or repair.

Selected-peer trust/context and peer-close negatives use valid key inputs and
precise diagnostics, no forwarded POST/new artifact progress and complete
unchanged durable state. Key loading/derivation precedes the context/fee-policy
query, but actual paid signing follows verified context. Missing artifacts alone
are not an in-memory signature-count measurement. Keep wrong DNS, genesis,
domain, mixed cohort and authenticated request-ID reuse controls unchanged.

## Validation and limits

After source/compiler ownership allocation, build actual operator binaries and
all-feature CLI; execute `local_tls_startup`, `remote_tls_transport` and strict
owning all-target/all-feature Clippy. Complete literal npm-ci and the full
required check-all, all seven hosted owners plus success-only check and fresh
complete exact-source review before integration. Preserve all actual unshortened
recurring and selected-PG coverage. DR-0213 native artifact A/B remains separate:
this process target does not prove release artifacts were executed.

This qualifies quiet local stop/restart and explicit test trust cutover. Same-CA
rollover cannot revoke another still-valid leaf. CA cutover is not CRL/OCSP,
compromise revocation, overlapping bundles, zero-downtime migration, a production
terminator file loader, remote trust distribution or independently controlled
PKI. Protected custody/admin roles, actual exposed-family authorization, real
host/power/ENOSPC/failover, encrypted off-host recovery, load/SLO/alerts and
independent security/release review remain separate requirements.

All execution is limited to numeric loopback, disposable keys/certificates and
privately owned local stores. No provider writes, public listener, paid service,
credential/root action, network launch or mainnet qualification is authorized.
