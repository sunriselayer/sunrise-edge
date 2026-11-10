# AGENTS.md

This file applies to the entire Sunrise Edge repository. A more deeply nested
`AGENTS.md`, if one is added later, may refine these instructions for its
subtree.

## Mission

Build Sunrise Edge as a production-oriented, serverless-native blockchain state
machine. Preserve deterministic protocol behavior, historical compatibility,
cryptographic domain separation, and portability across runtimes.

The core principle is:

> A blockchain node is a state machine, not a process.

Do not introduce a daemon, persistent connection, background loop, or cloud
provider as a protocol assumption.

## Read before changing code

Inspect the affected [`TODO.md`](TODO.md) row, source, owning tests, and the
relevant subsystem from the [architecture index](docs/architecture/README.md).
Follow a decision, E-number, or historical-roadmap link only for the criterion
at issue; the full catalogs are lookup references, not default context. Read
[`README.md`](README.md) when project orientation is needed. For a
protocol-critical change, also search existing type IDs, enum tags, hash
domains, error patterns, and canonical encoders before defining new ones.

`TODO.md` owns status and remaining gates, not subsystem design. The preserved
roadmap distinguishes original binding criteria from historical observations
and aspirational examples. Existing canonical
bytes, stable test vectors, accepted decision records, and released protocol
behavior are compatibility constraints. Do not rewrite them merely to match an
aspirational example.

Prioritize closing an existing unchecked TODO criterion. Before adding a new
fixture, decision record, or prerequisite, identify the criterion and its
shortest completion path. Do not expand evidence merely because it is possible
while an independent unmet condition still prevents completion.

## Non-negotiable architecture rules

- Keep vendor-specific dependencies out of protocol crates.
- Pass all state explicitly or load it through runtime traits. Do not add global
  mutable protocol state.
- Do not use `spawn`, infinite loops, background workers, persistent sockets, or
  process lifetime as a correctness requirement.
- Treat clients, relays, transports, schedulers, Tick senders, and cloud
  providers as untrusted.
- Treat atomicity-domain IDs as logical protocol configuration. Never derive
  them from provider/database coordinates or accept an untrusted request's
  domain as authoritative; physical placement is separate fenced deployment
  metadata.
- Keep validator identity, membership, voting power, bond, and economics
  separate. Bond amount must not silently determine voting power.
- Route owned/non-conflicting transactions toward the fast path and shared or
  conflicting transactions toward consensus; do not impose global ordering on
  all state access.
- Preserve deterministic execution and effects across machines and runtimes.
- Avoid whole-state migrations. Use versioned data and deterministic lazy
  migration.

## Protocol-critical change checklist

Treat a change as protocol-critical if it can alter canonical bytes, a digest,
a signature payload, execution effects, object identity/versioning, quorum
behavior, fee/bond arithmetic, governance outcomes, or persisted state layout.

For every protocol-critical change:

- Include explicit `chain_id`, `protocol_version`, and `epoch` replay boundaries
  wherever the message lifecycle requires them.
- Use `CanonicalStruct`; do not hand-build ambiguous concatenations.
- Give structures, enum variants, fields, algorithms, schemes, and domains
  explicit stable identifiers.
- Search all `*_TYPE_ID`, discriminants, and encoding tests before allocating an
  identifier. Never reuse an identifier within a canonical namespace.
- Frame variable-length data and collections with explicit lengths/counts.
- Define byte order explicitly. Do not use floats.
- Canonically sort unordered inputs before encoding or aggregation.
- Use checked arithmetic for amounts, gas, power, counters, epochs, heights,
  views, lengths, and deadlines.
- Add deterministic resource bounds before accepting attacker-controlled lists,
  byte strings, modules, signatures, keys, or schedules.
- Reject unknown or unsupported values explicitly. Never downgrade or silently
  fall back.
- Preserve old digest verification and historical state readability across
  upgrades.
- Add a stable encoding vector when adding or changing a wire type.
- Add negative/adversarial tests, not only happy-path tests.

If a required change breaks a stable encoding or consensus result, introduce an
explicit protocol/encoding version and document the activation and compatibility
policy. Do not edit an old vector and call the change compatible.

## Cryptography

- Hash algorithms are agile but never negotiable per transaction.
- Resolve the active `HashSuite` from protocol configuration and epoch.
- Use self-describing `Digest32` values for protocol references; do not spread
  naked `[u8; 32]` hashes through protocol APIs.
- Use the centralized hashing and signature framing APIs. Callers must not
  invent ad hoc prefixes.
- Keep general-purpose hashes and ZK/state commitment schemes separate.
- Adding an identifier is not the same as implementing or activating an
  algorithm. Unknown/unimplemented algorithms must fail closed.
- Do not add new cryptographic primitives from memory alone. Verify parameters,
  standards, and test vectors against primary sources.

## Consensus and untrusted delivery

- Consensus transitions consume explicit persisted state and exactly one event.
- Validate message context, membership, leader selection, signature scheme,
  signature, quorum, view/height relationships, and lock safety before voting or
  committing.
- Delivery must remain safe under duplication, replay, reordering, delay, and
  stale messages.
- Quorum/certificate bytes must not depend on vote arrival order.
- A Tick may affect liveness only; it must not manufacture authorization,
  quorum, or a commit.
- Keep state retention bounded and preserve idempotency when pruning.

## Rust rules

- Add `#![forbid(unsafe_code)]` to protocol and runtime crates.
- Do not add new Rust `unsafe` without explicit user authorization and an
  architecture decision explaining why a safe design is impossible.
- The existing `contract-sdk` raw WASM host-ABI layer is the sole current
  exception. Keep unsafe operations confined there and expose checked safe
  wrappers to contracts.
- Use typed errors with actionable variants. Do not panic on malformed external
  input.
- Avoid `unwrap`, `expect`, `panic!`, `todo!`, and `unimplemented!` in library
  paths. They are acceptable in focused tests when failure is the assertion.
- Prefer immutable values and deterministic collections (`BTreeMap`/
  `BTreeSet`) where iteration can affect protocol output.
- Avoid unnecessary clones, but favor correctness and explicit ownership at
  state-transition boundaries.
- Document public APIs and security-sensitive invariants.
- Keep dependencies minimal and declare shared versions in the workspace root.

## Crate boundaries

- `protocol-types`: dependency-light stable identifiers and core protocol types.
- `canonical-encoding`: the only canonical framing implementation.
- `hashing`, `crypto`, `commitments`: cryptographic abstraction and framing.
- `objects`, `abi`: versioned state and declared access.
- `execution`, `contract-sdk`, `chain-ir`, `system-modules`: deterministic
  execution surfaces.
- `fees`, `bonds`, `governance`, `protocol-upgrades`: protocol economics and
  controlled evolution.
- `validator-set`, `consensus`: epoch membership and shared-object ordering.
- `runtime`: storage, signing, transport, clock, and scheduler abstractions plus
  test adapters.
- `protocol-config`: the canonical commitment point for active protocol
  parameters.
- `signing-view`: dependency-light hardware profile decoding and exact
  signed-byte clear-signing policy; it must not depend on `execution`, a
  runtime, or any Ledger/USB/HID vendor crate.

Keep foundational crates low in the dependency graph. Avoid cycles and avoid
making protocol primitives depend on execution engines, runtimes, or adapters.

## Cloudflare CLI

Use Cloudflare CLI (`cf` or `cloudflare`) for future Cloudflare operations.
Do not directly invoke Wrangler. This is the user's selected CLI policy.
Discover commands with `cf cli search` using anonymous descriptions of the
action and resource type; exclude domains, names, IDs and credentials.
Inspect the discovered command's help or schema before using it.

## Local Node versions

Use the existing nvm for future local Node version management. Select the exact
Node version required by the chosen validation profile; do not substitute another
installed minor version or change the global default solely for a task. A missing
task runtime must fail explicitly rather than silently fall back to system Node.

## Workflow

1. Inspect `git status`, the relevant base/PR chain, and the affected TODO row;
   preserve unrelated changes.
2. Identify protocol, architecture, implementation, test, or documentation
   scope. Add a dated decision record only when an architecture decision itself
   changes. Keep applicable architecture documentation in sync with behavior.
3. Implement the smallest coherent change and add tests proportional to its
   risk. Extend the owning test rather than duplicating its implementation or
   assertions. Run the owning focused checks while iterating.
4. Select validation for the claim being made. The authoritative required,
   full, and isolated recipes are in
   [repository validation](docs/architecture/repository-validation.md) and
   `scripts/ci-gates.sh` / `scripts/ci-execution.sh`; do not restate their
   selectors here. All seven hosted required lanes and the aggregate `check`
   are the minimum routine PR gate on the selected source. They do not by
   themselves authorize a merge: the applicable original conditions in
   `TODO.md` section G and the maintainer's direction still govern. A local
   serial run is not an additional requirement for every edit or handoff.
5. When an affected TODO acceptance or release claim explicitly requires the
   local complete profile, run literal `npm ci --prefix adapters/cloudflare-workers`
   and `./scripts/check-all.sh` on the final frozen source as well as its
   separately required CI and release evidence. Do not substitute hosted CI
   for that local result. A prior run stays tied to its exact tree; it cannot
   qualify a later documentation commit for an M2/M7 acceptance claim.

Record the exact source, commands, actual results, and unrun checks. A failed,
cancelled, skipped, partial, or ancestor-source result is not success. Do not
start a duplicate validation while another owner runs the same source/cache/
target. For documentation/status-only edits, review the changed text and
relevant links. Such an edit alone does not trigger a new local serial run.

PostgreSQL is an optional deployment profile, not a protocol assumption.
DR-0172 separates its retained full integration/fault suite from ordinary
required validation. For PG implementation/dependency changes or a PG
deployment claim, configure the disposable live prerequisites and run
`./scripts/check-all.sh --full` (or the separate complete PG workflow) before
acceptance. Missing configuration must fail, not count as a successful skip.
Record the selected source/profile and actual fault flags. Never claim PG,
D1 or real-provider readiness from the DB-free required gate.

Dependabot proposes weekly Cargo, Cloudflare npm, and GitHub Actions updates.
Never auto-merge those PRs. Review changelogs and compatibility impact, retain
immutable workflow-action SHAs, and require the complete repository gate before
accepting an update.

Explain any environmental limitation precisely and keep the corresponding
acceptance or release claim open.

## Documentation and pull requests

- Keep `README.md` focused on human orientation, setup, stable design goals,
  and safety warnings. Current status belongs only in `TODO.md`.
- Keep `docs/guides/devnet.md` as the exact local devnet/CLI operator
  walkthrough and restart comparison; do not duplicate that runbook into the
  README.
- Keep this file focused on durable agent/contributor instructions.
- Keep the documents under `docs/architecture/` synchronized with implemented
  behavior and accepted decision records.
- Keep `TODO.md` as the current-status, completion-gate and roadmap owner;
  subsystem design belongs in `docs/architecture/`. Do not mark work complete
  unless the implementation and validation exist.
- In PR descriptions, separate implemented scope, compatibility impact,
  deferred work, and exact validation commands.
- Do not mix unrelated cleanup into a protocol change.

## Roadmap source of truth

`TODO.md` is the only source of truth for current implementation status, active
roadmap sequencing, deferred work, and completion gates; do not copy changing
milestone status into this file or the README. Architecture documents record
implemented behavior and accepted decisions, not the live work queue. Before
writing or merging, re-check the exact checkout, relevant PR chain, and TODO
row because repository state may have advanced.
