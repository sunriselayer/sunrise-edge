# DR-0148: Certified-only FastVote HTTP network and CLI quorum client

## Status

Accepted design, 2026-09-26. Implementation acceptance is tracked in
`TODO.md`, not established by this decision. Independent Phase 3 and ingress
security review gates remain open; this record does not
close either, does not authorize live exposure, deployment, or custody of real
assets, and adopts no load/soak/capacity target (DR-0147 defers all of that
to post-launch hardening).

## Context

DR-0130's `node_core::fast_path::{prepare, apply}` and DR-0129's
`consensus::FastPathCertifier` are real, tested, production-shaped code with
no network transport, no HTTP surface, and no CLI wired to them. DR-0144's
`fastvote_pg` operator CLI drives them one PostgreSQL namespace at a time
through file-based vote/certificate artifacts, with no server process. This
record is the "function-first network delivery" DR-0147 sequences after
Phase 3 economics completion but does not require Phase 3's own security
review gate: it makes FastVote reachable over real authenticated HTTP and
gives the Rust CLI a genuine multi-validator quorum submission path, still
entirely within one operator-composed, opt-in, experimental surface.

An independent design review (fresh Opus pass against `main`) surfaced two
must-fix findings before any of this could be considered safe to build on,
both corrected in this implementation:

1. `fast_path::prepare`'s *fresh* branch called `certifier.cast_vote` and
   durably committed a prepared record and per-object locks without ever
   verifying the resulting vote against the committed validator set's public
   key (only the exact-replay branch re-verified). A locally misconfigured
   or rotated signing key — one that claims a real, registered validator
   identity but signs with different key material — would therefore
   permanently wedge every input object behind an uncertifiable vote (phase
   1 has no rollback or expiry).
2. A certified-only HTTP router built as a boolean flag threaded through the
   existing mutating `preinstalled_wasm_structured_durable_router` could not
   structurally guarantee a direct/legacy mutating route (including the
   generic `SubmitTransaction` event path) was unreachable — only that it
   happened to be disabled by the flag's current value.

## Decision

**Core (`crates/node-core`).** `fast_path::prepare`'s fresh branch now calls
`certifier.verify_vote(&vote, &FastPathEd25519Verifier)` immediately after
`cast_vote` and before any prepared-record, lock, or nonce mutation is even
constructed — the same check the exact-replay branch already performed on
its stored vote. A wrong-key signer now fails closed with
`FastPathError::Consensus(ConsensusError::InvalidSignature(..))` before
touching durable state, proven by a regression that a claimed-real,
wrong-key validator leaves the lock, nonce-lock, and prepared-record rows
completely absent.

**Wire (`crates/node-wire`).** One new canonical transport type,
`FastVoteApplyRequest` (frame `0x6439/v1`, fields `signed_paid_intent` +
`certificate`, bounded by `MAX_FASTVOTE_APPLY_REQUEST_BYTES`), pairs the
existing `SignedPaidIntent` and `FastCertificate` byte strings for one HTTP
POST body without reinterpreting either. `FASTVOTE_PREPARE_PATH`
(`/v1/fastvote/prepare`) and `FASTVOTE_CERTIFICATES_PATH`
(`/v1/fastvote/certificates`) are the two dedicated route paths. An
independent JavaScript reconstruction (`scripts/fastvote-apply-request-vectors.mjs`)
pins the same byte-for-byte vector as the Rust encoder.

**Router (`crates/native-http`).** `fastvote::certified_fastvote_router[_with_executor]`
is a genuinely separate constructor from
`preinstalled_wasm_structured_durable_router`, not a flag branch inside it:
its body only ever merges liveness, the four bounded structured-durable
queries, `paid_execution::read_routes` (fee-policy query),
`local_execution::read_routes` (instance query), `publication::read_routes`
(code/publication query), and its own two FastVote routes. It never
references `NODE_EVENT_PATH` or any `*::mutation_routes` function, so a
direct/legacy mutating route cannot reach this router's request path no
matter how it is configured. `publication.rs`, `local_execution.rs`, and
`paid_execution.rs` were each split into independent `read_routes`/
`mutation_routes` functions so the existing mutating router keeps its exact
prior route table (same enabled-flag wiring, unchanged behavior) while the
certified router can depend only on the read half.
`PreinstalledWasmComposition::with_fastvote` is crate-private: only the
certified constructor can attach a `FastVoteComposition`, so it can never
reach the mutating router either. A `DisabledNodeStateMachine` satisfies the
shared state type's generic bound without ever being invoked (no
`SubmitTransaction` route exists to call it).

Both FastVote route handlers authenticate the exact signed bytes against the
caller's own declared chain/protocol/epoch (via
`node_core::paid_execution::authenticate_paid_execution`, which by its own
contract touches no identity/clock/storage) *before* allocating a
restart-safe identity, reading the clock, or resolving domain/context.
`fast_path::prepare`/`apply` then re-authenticate internally against that
same declared context and only afterward CAS-fence it against the durable
current epoch, so a stale-but-genuinely-signed intent still fails closed,
just after authentication rather than before it. Neither handler calls
`node_core::paid_execution::reconcile_authenticated_paid_execution`: that
function rejects a declared/current epoch mismatch before checking for an
existing receipt, which would break `fast_path::apply`'s own receipt-first
historical exact-replay guarantee for a request whose epoch has since
advanced.

Prepare also checks the declared epoch against the fixed host configuration
immediately after authentication and before runtime I/O; this includes a
genuine cached future-epoch vote. Apply preserves receipt reconciliation
first, then rejects fresh work outside the trusted execution-policy epoch.
Both fixed-pin and live-epoch refusals return
`409 fastvote-epoch-repin-required`, with explicit out-of-band re-pin
guidance in the CLI. They never refresh local trust pins or re-sign silently.

**Client (`clients/rust::fastvote_client`).** `load_trusted_fastvote_genesis`
reuses `node_core::genesis`'s exact production trust model (commitment
digest, embedded context, and authority signature all independently
verified) to turn a local genesis manifest file into a
`consensus::FastPathCertifier` — the sole, offline, locally pinned source of
validator identity and public keys; nothing here ever trusts a value from a
live server response. `FastVoteEndpoint` is a fixed, caller-configured
`(ValidatorId, Client<T>)` pair. `collect_fastvote_certificate` sends
`prepare` to every endpoint bounded by one whole-operation deadline (not
`endpoints.len()` independent per-request timeouts), rejects a returned vote
whose own `validator` field disagrees with its endpoint's configured
identity, cryptographically verifies each vote and binds its transaction
hash to the exact submitted intent before grouping the remaining votes by
`(execution_effects_hash, locked_objects_digest)`, and offers *every*
group — not only the first — to `FastPathCertifier::try_form_certificate`.
One unreachable or actively Byzantine endpoint (wrong header, foreign
validator, garbage bytes) can neither block a certificate the remaining
honest endpoints still reach quorum for, nor get treated as an
authoritative anchor merely for answering first. `apply_fastvote_to_all`
submits to every endpoint and reports each outcome independently; it never
aggregates these into an invented "all validators" or "durable/final" claim,
and a committed charged-trap result is reported as `Ok`, not a failure.

## Evidence

- `crates/node-core/src/fast_path/tests.rs::prepare_rejects_a_fresh_vote_whose_signature_does_not_match_the_registered_public_key`
  (new), plus the existing `node-core` regression suite.
- `crates/native-http/src/tests/fastvote_router.rs`: production-constant
  direct/legacy mutation-path inventory crossed with GET/POST/PUT/PATCH/DELETE,
  liveness/read/
  FastVote route presence, and a construction-time policy-context-mismatch
  rejection. The real HTTP E2E checks the same path×method matrix; the existing
  native HTTP suite remains part of the gate.
- `clients/rust/src/fastvote_client.rs` tests (real Ed25519
  signatures and the real `FastPathCertifier` for quorum cases): a same-header
  malicious first responder with an invalid signature, one unreachable endpoint, an
  insufficient-quorum negative, a fully valid quorum for an unrelated
  transaction, a spoofed-endpoint-identity rejection, a slow first peer
  bounded by the per-request cap while quorum still forms from the
  remaining honest peers, endpoint-config preflight (duplicate ids/labels,
  unknown validator, empty/oversized configuration), and apply-side
  rejection of an unrelated or uncertifiable certificate before any POST,
  plus zero/excessive/elapsed budget rejection without a POST and checked
  monotonic-clock addition.
- `apps/operator/tests/fastvote_network_e2e.rs`: the original
  `fastvote_network_prepares_certifies_and_applies_a_real_transfer_over_real_http`
  (four real `certified_fastvote_router` HTTP servers, each with its own
  SQLite durable/blob store, served over real loopback TCP, installed from
  one real signed four-validator genesis manifest, driving a real signed
  Standard Asset `transfer` through real prepare → local quorum certificate
  formation → apply, plus exact replay and certified-only route-denial
  checks), plus both handlers' wrong media type / oversized body / malformed
  body / canonically encoded bad signature / wrong chain / wrong protocol
  rejection with zero observed identity, clock, store, commit and blob calls.
  Positive controls prove the counters wrap the actual components. The
  concrete WASM engine has no synthetic counter; absent code/object/blob
  prerequisites establish that these unauthenticated requests cannot execute.
  File-backed epoch regressions cover old/future requests, a genuine cached
  future vote, live epoch advancement refusing new work with unchanged state,
  and byte-identical historical receipt replay without fee reapplication.
- `apps/operator/tests/fastvote_startup_pin.rs`: the shared production startup
  check against an installed file-backed SQLite store rejects an advanced live
  epoch or a mismatched live validator-set digest. Production invokes this
  helper before fence advancement and again before listening.
- `apps/operator/tests/fastvote_host_pg_cli_e2e.rs::fastvote_host_pg_cli_multivalidator_e2e`
  (new, live PostgreSQL, gated behind `SUNRISE_EDGE_TEST_POSTGRES_URL`,
  wired into `scripts/check-fastvote-pg.sh`): four real `fastvote_host_pg`
  subprocesses, one per validator, each opening only its own
  already-bootstrapped PostgreSQL namespace (bootstrapped by the real
  `fastvote_pg` CLI), driven entirely through `sunrise_edge_cli::run` (the
  same entrypoint the shipped binary's `main` calls). In order: a charged
  application trap (real fee reserved/settled, effects discarded, receipt
  committed) reported as rejected rather than a fresh-retryable success; a
  real ordinary `contract paid-call --fastvote-network` transfer reaching
  quorum and applying across all four hosts; exact `contract fastvote-replay`
  of that success from the mandatorily-persisted artifacts; a request-id
  reuse conflict rejected with the certificate record, fee-coin object, and
  sender nonce independently re-verified unchanged; exact replay of the
  charged trap proving non-reapplication; a stale-writer-fence rejection
  (a rival process claiming a fresh fence over the same namespace leaves
  the original process's direct `prepare_fastvote` failing closed); and a
  real close/reopen of the validator's host process (killed and restarted
  against its already-populated namespace, never installing a second
  genesis) with exact replay of both the success and charged-trap
  certificates proving persistence survives the restart. Original and
  replayed `--result-out` bytes are equal for success and the charged trap.
- `apps/cli/src/commands/fastvote_network.rs` unit tests: network
  config parsing (comments/blank lines, loopback and fully-configured
  remote-TLS lines, wrong field count, partially-configured TLS, invalid
  hex validator id, endpoint-count bound), a real-certificate mixed
  loopback/remote-TLS cohort rejection and a distinct-per-peer-TLS
  acceptance (both via real `rcgen`-issued certificates), and mandatory
  artifact persistence (`create_new` never overwriting, bounded file-size
  rejection). `fastvote_network_tests.rs` additionally exercises the real
  Client's context/fee-policy/object/nonce/publication/interface/instance query
  methods through one budgeted transport, the actual paid-command path with a
  slow loopback HTTP preparation response and no POST, configured-peer
  selection, invalid flag/budget rejection, pre-POST output failures, retained
  handles, directory-sync errors, corrupt replay artifacts and exact success/
  charged-trap result bytes in both replay modes. Post-ack persistence failure
  is injected directly into the production persistence function, not after a
  live-network acknowledgement; directory-sync rejection is not a power-loss
  or crash-recovery experiment. Path-identity checks are Unix-specific.

### Function-first implementation and acceptance boundary

The three functional components have been implemented and exercised by a
real, non-mocked, four-process live PostgreSQL E2E driven through the compiled
CLI library entry point, not a separately executed CLI binary
(`apps/operator/tests/fastvote_host_pg_cli_e2e.rs::fastvote_host_pg_cli_multivalidator_e2e`,
gated behind `SUNRISE_EDGE_TEST_POSTGRES_URL` and wired into
`scripts/check-fastvote-pg.sh`), plus the pure SQLite/in-process coverage
below:

- **PostgreSQL hosting binary** (`apps/operator/src/bin/fastvote_host_pg.rs`):
  a long-running, certified-only FastVote HTTP host following `fastvote_pg`'s
  security-critical conventions (TOCTOU-safe signing-key loading, TLS-only
  DSN, trusted-genesis-manifest verification). Both binaries now use the
  tested shared `apps/operator/src/common.rs` implementation.
  It never installs or resets genesis (only reads an
  already-committed manifest/fee-policy and verifies its local signing key
  against the committed registered validator), verifies the namespace's
  installed live epoch and exact configured validator-set digest before
  claiming the writer fence, then rechecks before listening. It claims the
  writer fence exactly once at startup (`--confirm-offline-fence-advance`
  is mandatory), binds loopback-only, and serves via
  `native_http::certified_fastvote_router` until `ctrl_c`.
- **CLI wiring**: `contract paid-call --fastvote-network` builds and signs a
  real ordinary paid `Call` through the exact same generic construction path
  `paid-call` already used directly (`apps/cli/src/commands/paid_execution.rs`),
  branching only at final submission between a direct POST and the network
  prepare/quorum/apply flow
  (`apps/cli/src/commands/fastvote_network.rs::run_network_submit`).
  Endpoint-to-validator mapping is verified against the local genesis pin
  *before* any fee-policy query or signing. The mandatory signed-intent and
  certificate artifacts, plus optional result output, are all reserved
  (`create_new`) before the first mutation. Original file/directory handles
  are retained and `write_all` plus file and directory `sync_all` must succeed
  before the corresponding prepare/apply POST; existing paths are never
  overwritten. File synchronization alone does not establish crash-durable
  creation of a directory entry. A
  new `contract fastvote-replay` action reads back exactly those saved
  bytes -- never a fresh nonce, never a re-sign -- and handles both the
  "certificate not yet formed" and "certificate already saved" cases,
  including exact non-reapplication of an already-committed charged-trap
  result. Explicit missing or corrupt certificate input is an error; omission
  of `--certificate` intentionally selects collection from the saved intent
  and requires a new certificate-output path. Unsupported/ambiguous replay
  flags are rejected instead of ignored. Both modes support exact result
  output for success and charged traps.
- **Per-peer TLS**: `--fastvote-network`'s config file supplies one
  `validator_id endpoint tls_server_name tls_ca_cert_der_file` line per
  peer (loopback plaintext via the `-`/`-` sentinel), so K remote peers use
  K independently configured hostnames/CAs, never one global pair reused
  or a system trust-store fallback; a config mixing loopback and remote-TLS
  peers in one cohort is rejected before any endpoint is dialed.

Additional correctness hardening to the client library found necessary
while integrating the above: `collect_fastvote_certificate` now verifies
each returned vote against the pinned certifier *before* grouping it (a
same-header malicious-first-responder with an invalid signature is now
rejected as an error for that attempt, never silently grouped as valid),
binds the expected `tx_hash` to the digest of the exact authenticated
signed intent being submitted, and preflights endpoint count/distinct-id/
distinct-label/membership bounds before any network mutation. The whole
prepare→certify→apply workflow shares one deadline, with each peer
request additionally bounded by an independently configured per-request
cap, so one slow/unavailable first peer cannot consume the entire budget
and starve the remaining honest peers. `apply_fastvote_to_all` and the CLI
replay path both independently re-verify a supplied certificate against
the pinned local validator set and the submitted intent's own digest
*before* any apply POST. The CLI creates a checked deadline immediately
after flags, before preparation, and uses it for every preparatory query
through the exact selected cohort client. Global TLS flags, unrelated read
endpoints and orphaned network flags fail locally. These properties have
focused negative regressions in addition to the PostgreSQL happy path;
implementation acceptance still requires the complete integrated gate and
fresh exact-head tech-lead review. See `TODO.md` for those and the separately
open independent security and cross-validator handoff gates.
