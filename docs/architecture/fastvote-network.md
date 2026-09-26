# FastVote HTTP network architecture

[DR-0148](decisions/0148-certified-fastvote-network.md) makes DR-0130's
`node_core::fast_path::{prepare, apply}` and DR-0129's
`consensus::FastPathCertifier` reachable over authenticated HTTP, as one
operator-composed, opt-in, experimental surface distinct from the generic
`SubmitTransaction` event path. It does not close the Phase 3 independent
security gate or establish acceptance of the added ingress, and adopts no
live-network, load, soak, or capacity target.

## Components

- **Wire** (`crates/node-wire`): `FastVoteApplyRequest` (frame `0x6439/v1`)
  pairs an already-encoded `SignedPaidIntent` and `FastCertificate` for one
  HTTP POST body. `FASTVOTE_PREPARE_PATH`/`FASTVOTE_CERTIFICATES_PATH` are
  the two dedicated route paths, each with its own body-size bound.
- **Router** (`crates/native-http::fastvote`): `certified_fastvote_router`
  is a genuinely separate constructor from the mutating
  `preinstalled_wasm_structured_durable_router`, not a boolean flag branch
  inside it. It only ever merges liveness, four bounded structured-durable
  read queries, the read halves of publication/local-execution/
  paid-execution, and its own two FastVote routes. It never references the
  generic event path or any mutation-route function, so a direct/legacy
  mutating route cannot reach it regardless of configuration.
  `PreinstalledWasmComposition::with_fastvote` is crate-private: only this
  constructor can attach a `FastVoteComposition`. Both routes authenticate
  the exact signed bytes against the caller's own declared chain/protocol/
  epoch *before* allocating identity, reading the clock, or resolving
  domain/context; `fast_path::prepare`/`apply` then re-authenticate
  internally and only afterward CAS-fence against the durable current
  epoch, so a stale-but-genuinely-signed intent fails closed just after
  authentication rather than before it, and a request whose epoch has since
  advanced can still be replayed against its own already-committed receipt
  (receipt-first historical exact replay).
- **Client** (`clients/rust::fastvote_client`): `load_trusted_fastvote_genesis`
  reuses `node_core::genesis`'s exact production trust model to turn a local
  genesis manifest file into a `consensus::FastPathCertifier` -- the sole,
  offline, locally pinned source of validator identity and public keys.
  `collect_fastvote_certificate` verifies every returned vote against that
  pinned certifier *before* grouping it, binds the certificate's expected
  transaction hash to the digest of the exact authenticated signed intent
  being submitted, and bounds the whole prepare/quorum workflow by one
  overall deadline plus an independently configured per-request cap (so one
  slow or Byzantine endpoint cannot consume the entire budget or block
  quorum from the remaining honest peers). `apply_fastvote_to_all`
  independently re-verifies a supplied certificate against that same pinned
  set and the submitted intent's digest before any apply POST, and reports
  each peer's outcome independently -- never an invented "all validators
  applied" or global-durability claim.
  Deadline addition is checked, and zero or excessive per-request caps fail
  before sending. The 300-second cap is a client resource ceiling, not an
  adopted latency or throughput target.
- **Host** (`apps/operator/src/bin/fastvote_host_pg`): a long-running,
  certified-only PostgreSQL-backed FastVote HTTP host, reusing
  `fastvote_pg`'s security-critical conventions (TOCTOU-safe signing-key
  loading, TLS-only DSN, trusted-genesis-manifest verification) rather than
  duplicating its one-shot-subcommand design. It never installs or resets
  genesis, only reads an already-committed manifest/fee-policy and verifies
  its local signing key against the committed registered validator; it
  claims the namespace's writer fence exactly once at startup
  (an explicit, mandatory offline confirmation, not an automatic
  background renewal); and it listens on loopback only, with explicit
  external-TLS-termination guidance -- it never terminates TLS itself.
  Its per-generation identity sequence becomes permanently exhausted after
  the last representable nonzero sequence, rather than wrapping and reusing
  an identity under the same writer generation.
- **CLI** (`apps/cli`): `contract paid-call --fastvote-network` builds and
  signs a real ordinary paid `Call` through the exact same generic
  construction path `paid-call` already uses directly, branching only at
  final submission between one direct POST and the network prepare/quorum/
  apply flow. Endpoint-to-validator mapping against the local genesis pin
  is verified before any fee-policy query or signing. Every configured
  remote peer gets its own independently configured TLS server name/CA
  (never one global pair reused, never mixed with a loopback peer in the
  same cohort, never a system trust store). The signed-intent and
  certificate artifacts are created with `create_new` and file-synchronized
  (`write_all`+`sync_all`) before their respective mutating POSTs, and
  never overwritten. `contract fastvote-replay` resubmits exactly those
  saved bytes -- never a fresh nonce, never a re-sign.

## Trust and pinning model

Every participant in a FastVote exchange independently pins its own local,
offline expected context: the ordinary CLI's `--expected-*` protocol
context, and separately, the FastVote genesis manifest and its expected
commitment digest (`--fastvote-genesis-manifest`/
`--fastvote-expected-genesis-digest`). Neither is ever replaced by a value
read from a live endpoint's response. A configured epoch/validator set is
required to remain fixed for one running host and one CLI invocation: a
changed live epoch is rejected for fresh work and requires an explicit,
out-of-band operator re-pin, while an already-committed historical receipt
remains exactly replayable regardless. See
[the epoch-transition handoff design note](decisions/0132-fastvote-epoch-transition.md)
for the broader multi-epoch/validator-set-change protocol this development
surface does not yet automate; a live multi-validator epoch change or
validator-set replacement on this HTTP surface requires a separate,
explicitly reviewed correctness gate before production use, not merely
passing today's fixed-epoch tests.

## Known Phase 1 limitations

`fast_path::prepare`'s durable prepared record and per-object/per-sender
locks are unpriced and have no expiry in this phase. Within a fixed epoch,
applying the certificate completes the prepared path; abandoning the request
does not release its locks. This means a caller's own subsequent unrelated
operation against the same object or sender nonce fails closed -- effectively
a self-inflicted wedge, not a bug -- until that first request's certificate
is applied. `crates/node-core/src/fast_path/tests.rs::a_locked_object_blocks_a_direct_commit_and_leaves_its_tracked_state_untouched`
is the executable regression for this documented limitation; there is no
priced-admission or automatic-expiry claim for this development surface.

## Required acceptance boundaries

Before using this experimental host, implementation and negative tests must
establish the fixed configured epoch/set pin at startup and on preparation,
while preserving receipt-first historical exact apply replay. CLI preparatory
reads must use a configured peer's TLS policy and the same checked deadline
as prepare/apply. Recovery files require all-output preflight and both file
and parent-directory synchronization before mutation. The pending acceptance
and independent review gates are recorded in `TODO.md`; the happy-path E2E
does not substitute for them. The host currently uses an empty hash-suite
history, so cross-suite historical replay fails closed. Its created-checkpoint
value is trusted operator input, not evidence of a committed checkpoint.

## Operating this network

See [the operator/CLI guide](../guides/fastvote-network.md) for the
executable sequence (bootstrap namespaces, start hosts, configure the
network file, submit and replay), and
[the closed PostgreSQL FastVote rehearsal](../operations/fastvote-pg-rehearsal.md)
for the underlying `fastvote_pg namespace-init`/`install-genesis`
prerequisites this host never performs itself.
