# FastVote HTTP network architecture

[DR-0148](decisions/0148-certified-fastvote-network.md) makes DR-0130's
`node_core::fast_path::{prepare, apply}` and DR-0129's
`consensus::FastPathCertifier` reachable over authenticated HTTP, as one
operator-composed, opt-in, experimental surface distinct from the generic
`SubmitTransaction` event path. It does not close the Phase 3 independent
security gate or establish acceptance of the added ingress, and adopts no
live-network, load, soak, or capacity target.
[DR-0151](decisions/0151-integrated-network-delivery-and-lightweight-stores.md)
extends the same composition to ordinary paid Publish and Instantiate as well
as Call. PostgreSQL is this host's implementation profile, not a mandatory
protocol database.

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
  internally. Prepare additionally rejects a declared epoch different from
  the fixed host pin before any runtime I/O, including the cached-vote path.
  Fresh apply checks the trusted execution-policy pin after receipt
  reconciliation, then CAS-fences against the durable current epoch. A
  request whose epoch has since advanced can still return its own
  already-committed receipt (receipt-first historical exact replay), without
  fee or application reapplication.
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
  Each apply acknowledgement binds its application kind and package origin or
  instance target to the submitted intent, and its effects transaction hash to both
  the exact signed paid intent and the submitted certificate. These unsigned
  acknowledgements still do not establish durable or network-wide finality.
  Deadline addition is checked, and zero or excessive per-request caps fail
  before sending. The 300-second cap is a client resource ceiling, not an
  adopted latency or throughput target.
- **Host** (`apps/operator/src/bin/fastvote_host_pg`): a long-running,
  certified-only PostgreSQL-backed FastVote HTTP host, reusing
  `fastvote_pg`'s tested shared `apps/operator/src/common.rs` boundaries
  (flag parsing, TOCTOU-safe signing-key loading, TLS-only DSN and trusted
  genesis verification). It never installs or resets
  genesis, only reads an already-committed manifest/fee-policy and verifies
  its local signing key against the committed registered validator; it
  verifies the installed live epoch and exact validator-set digest before
  advancing the writer fence, and rechecks the pin after that claim before
  listening. It claims the namespace's writer fence exactly once at startup
  (an explicit, mandatory offline confirmation, not an automatic
  background renewal); and it listens on loopback only, with explicit
  external-TLS-termination guidance -- it never terminates TLS itself.
  Its per-generation identity sequence becomes permanently exhausted after
  the last representable nonzero sequence, rather than wrapping and reusing
  an identity under the same writer generation.
- **CLI** (`apps/cli`): `contract paid-publish`, `paid-instantiate` and
  `paid-call --fastvote-network` build and sign ordinary paid intents through
  the same generic construction used directly, branching only at
  final submission between one direct POST and the network prepare/quorum/
  apply flow. A checked operation deadline starts immediately after flag
  parsing, before input reads or signing. Every preparatory query uses a
  budgeted transport borrowing the selected configured peer's client, with
  the same overall deadline and per-request cap used for prepare/apply.
  Endpoint-to-validator mapping against the local genesis pin is verified
  before any fee-policy query or signing. Every configured
  remote peer gets its own independently configured TLS server name/CA
  (never one global pair reused, never mixed with a loopback peer in the
  same cohort, never a system trust store). Global TLS flags and an endpoint
  outside that cohort are local errors. All requested outputs are reserved
  with `create_new` before the first mutating POST; retained file and parent
  directory handles synchronize the signed intent before prepare and the
  certificate before apply. Aliases and existing destinations fail closed.
  Optional result output persists exact success or charged-trap bytes.
  `contract fastvote-replay` resubmits exactly saved bytes -- never a fresh
  nonce, never a re-sign. An explicitly supplied missing or corrupt
  certificate fails; omitting that flag intentionally collects a certificate
  from the saved intent instead.

## Certified lifecycle and recovery

All application kinds use `build_paid_admission` and the complete `0x6424/v1`
staged-effects commitment. Prepare persists only its preparation and locks;
it does not install published definitions or instances, advance the sender
nonce or publish final application objects/receipts. Certified apply rederives
the staged outcome and atomically commits definitions/instances/authorities,
object effects, fee escrow/settlement, nonce and receipt. No direct-mutation
fallback or Standard Asset-specific core branch is used.

The top-level `create-asset`, transfer, split, merge, mint and burn use this same
network submission when the network flags are selected. Standard Asset is
ordinary public code and ABI; the human-facing commands do not confer extra
node authority.

Missed-prepare recovery applies saved certified Publish → Instantiate → Call
in declared dependency order, without signing or voting. Missing definitions
are supplied only by their own authenticated Publish entry, never imported
from an opaque snapshot. Each entry rederives its full commitment against exact
local prerequisites; a batch may commit a prefix before a later entry fails.
Strict absent-lock checks, tombstone protection, commit-time writer fencing
and receipt-first exact replay remain unchanged. This is not complete history
discovery, shared-operation ordering or activation-authorized state handoff.

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

The implementation includes fixed epoch/set startup checks, receipt-first
historical replay, cohort-bound budgeted preparatory reads, all-output
preflight, and strict file/directory synchronization. Negative tests exercise
these boundaries, not only the happy path. Final implementation acceptance
and independent review gates remain recorded in `TODO.md`; passing an E2E
does not substitute for those reviews. Path-identity comparisons are
Unix-specific, and other platforms have not been validated. The host
currently uses an empty hash-suite
history, so cross-suite historical replay fails closed. Its created-checkpoint
value is trusted operator input, not evidence of a committed checkpoint.

## Operating this network

See [the operator/CLI guide](../guides/fastvote-network.md) for the
executable sequence (bootstrap namespaces, start hosts, configure the
network file, submit and replay), and
[the closed PostgreSQL FastVote rehearsal](../operations/fastvote-pg-rehearsal.md)
for the underlying `fastvote_pg namespace-init`/`install-genesis`
prerequisites this host never performs itself.
