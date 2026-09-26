# DR-0151: Integrated network delivery and lightweight validator stores

## Status

Accepted, 2026-09-27. Implementation, validation and readiness status belong
in `TODO.md`. This decision records the functional-delivery and storage
discussion together; it does not authorize public deployment or real custody.

## Context

The immutable paid contract platform can publish, instantiate and call user
code through the direct local path. DR-0130/0148 deliberately restricted
certified multi-validator execution to `Call`, and DR-0150 recovered only
declared certified Calls. That leaves a usable-network gap: an ordinary user
cannot yet publish code and create an instance through the certified-only
network surface. More standalone codecs, inspectors or backend-specific
operations do not close that gap.

PostgreSQL was selected as the initial multi-validator deployment profile in
DR-0143, not as a protocol invariant. The runtime contracts already separate
logical atomicity domains from physical databases and providers. Nevertheless,
making PostgreSQL operational completion the default delivery objective would
obscure the serverless-native goal. Lightweight databases are valid candidates
only if they preserve the same protocol-visible atomicity and durability.

## Decision

### Four integrated functional deliveries

Organize remaining initial-network work into four usable outcomes. Internal
assignments may be smaller, but do not ship separate type/codec/loader-only PRs
as completion of these features:

1. **Generic network contract lifecycle:** paid Publish, Instantiate and Call,
   arbitrary Standard Asset creation and its existing operations, fees, exact
   replay and declared same-epoch catch-up on a validator that missed prepare.
   Standard Asset uses the ordinary public WASM/ABI/authority path; no asset
   ID, native balance decoder or privileged admission branch is introduced.
2. **Network economics and validator operations:** order shared mutations
   explicitly, then expose reward distribution/claims, bond operations and
   equivocation evidence/slashing through authenticated surfaces. Existing
   single-store CAS and offline operator execution are prerequisites, not
   evidence of cross-validator ordering or converged results.
3. **Validator membership and epoch handoff:** verify the required code,
   object/state and settlement history before adding, replacing or restoring a
   validator or activating a new epoch/set. Reject eligibility when catch-up
   completeness or activation-bound state verification is missing. Local epoch
   CAS or replaying a supplied list alone is not a complete state handoff.
4. **Independent review and initial-network startup:** exercise functional
   operations, restart, exact replay and authorization with independently
   controlled validator stores; provide executable configuration/TLS/startup
   instructions; pass the separate economics and ingress security gates and
   remediate their findings before live exposure.

These are delivery boundaries, not a guarantee that precisely four PRs close
every readiness criterion. Validator-set changes, slashing and rewards remain
required, not optional features silently dropped to declare FastVote complete.
Representative sustained load/soak/capacity work follows launch under DR-0147;
no throughput, concurrency or recovery SLO is inferred. Ledger, TypeScript,
explorer/wallet UI, Unique Asset, multisig, contract upgrades/migrations and
production HA/provider certification remain separately deferred, not deleted.

### Storage capabilities, not a mandatory database product

Keep PostgreSQL as a supported deployment profile; do not require it in the
protocol or in every future validator host. Make lightweight profiles explicit
first-class implementation targets: SQLite-backed Durable Objects for
Cloudflare and a separately verified durable SQLite host for native execution.
Neither target is considered production-supported merely by this decision.

Every authoritative store must preserve:

- complete version/read assertions and all-or-nothing state/object updates;
- atomic receipt, nonce, certificate/witness and settlement publication, and
  typed outbox publication whenever the invoked path requires an outbox;
- immutable object versions, retained deletion revisions and ABA resistance;
- trusted namespace/domain placement and commit-time writer-generation fencing;
- explicit committed/rejected/indeterminate outcomes, durable reconciliation
  and exact replay without execution or fee reapplication;
- authenticated blob-before-reference ordering, bounded reads/writes/scans and
  restart-recovery evidence proportional to the deployment being claimed.

The initial lightweight profile keeps one independently controlled validator's
logical atomicity domain within one transactional store/actor. A validator is
not a single global actor shared by the whole chain. Provider replication is
not a substitute for independently authenticated validator quorum.

Per-object, per-sender or per-contract databases are **not** a drop-in mapping:
one generic transaction can touch several such units plus fee/nonce/receipt
state. A certificate proves an authenticated outcome; it does not make writes
to independent databases atomic. Cross-domain execution requires a separately
designed durable commit/visibility protocol or an explicitly enforced
single-domain access rule. Do not silently restrict arbitrary contracts or
weaken atomicity to fit a provider. Domain IDs stay logical protocol identities,
never provider database/actor IDs supplied by an untrusted caller.

### Provider options and their boundaries

The following are capability comparisons, not implemented Sunrise adapters:

| Option | Useful capability | Important boundary |
| --- | --- | --- |
| Cloudflare SQLite-backed DO | Co-located computation, private strongly consistent transactional storage | Transactional authority is scoped to one DO, not multiple DOs |
| Cloudflare D1 | Serverless SQLite and atomic statement batches | Writes go to a primary; asynchronous read replicas and session bookmarks are not globally local write authority |
| Deno Deploy / Deno KV | Versionstamp-conditional multi-key atomic updates | Provider transaction/key/value bounds must fit the protocol profile; tombstones, fencing and ambiguity still need an adapter |
| Turso / libSQL | SQL-over-HTTP for portable edge clients, plus local database options | Remote authoritative commits and local-first push/pull synchronization are different modes; sync is not validator consensus |
| Rivet Actors | Per-actor SQLite with managed or self-hosted deployment | Self-hosted multi-node control-plane/storage operation may still require PostgreSQL or another distributed backend |
| Native regional VM/container / SQLite | Direct Rust execution with local transactional persistence | Requires durable filesystem semantics; LiteFS single-primary asynchronous replication does not by itself preserve acknowledged writes after failover |

Prefer DO as the Cloudflare authoritative-state candidate; D1 may serve
derived search/aggregation where useful. Do not add a second database simply
to tick this comparison. A full Cloudflare profile must run the actual core
and paid contract path, not only relay to a PostgreSQL-backed service or prove
an unrelated counter. Existing SQLite developer tests and provider API docs
are not production or cross-provider conformance certification.

### Immediate implementation order and acceptance

The user explicitly selected **delivery 1 before DO implementation**. Use the
existing provider-neutral core and verified SQLite/PostgreSQL compositions to
complete the certified contract lifecycle. Retain PostgreSQL evidence without
expanding PostgreSQL-only operational scope. The lightweight profile is a
separate follow-on delivery with actual contract/restart/replay evidence, not
a prerequisite invented for delivery 1.

Extend the common paid admission/staged-commit pipeline, rather than replacing
certification with direct mutation. Preserve authentication and historical
receipt reconciliation before fresh policy/module/object reads. Prepare may
reserve sender/input locks but must not publish code, instances, created
objects, nonce advancement or final user receipts. Apply and signerless
recovery must rederive and bind the complete existing certified commitment,
including publication/instance/authority effects and their exact prerequisites.
Recovery imports definitions only by applying authenticated certified Publish
in declared dependency order; there is no opaque database-copy shortcut.

The Rust CLI/SDK must bind acknowledgements to the correct application kind,
publication/instance target, exact intent and certificate; pin context, genesis
and peer TLS before signing; retain synchronized exact replay artifacts and
reserve outputs before mutation. Standard Asset creation and existing verbs
use the same submission path. Canonical intent/object/receipt/vote/certificate
formats and existing vectors remain unchanged unless a separately documented
versioned change proves necessary.

One integrated acceptance scenario publishes real user-selected WASM/ABI,
instantiates it and exercises paid calls/assets through independent validator
hosts, with a missed-prepare validator recovering the complete declared
lifecycle. Compare exact receipts, definitions/instances, object versions,
nonce and certified fees/settlements; exercise successful and charged failed
execution, close/reopen replay, conflicts, invalid artifacts, dependency order,
fencing and divergent prerequisites. Shared ordering, complete history
discovery, state-root completeness and live epoch activation remain distinct.

Run the complete repository gate and require fresh exact-final-head tech-lead
approval plus CI before merge. Those reviews do not replace independent
security audit or authorize public ingress.

## Consequences

This supersedes the active sequencing and mandatory-profile assumption, not
historical evidence, in DR-0143/0147. It extends the Call-only feature boundary
of DR-0130/0148/0150 when implementation and validation exist. Readiness and
remaining work stay in `TODO.md`; README gains no current-status section.
Existing deployment behavior is unchanged until its implementation is accepted.

## Primary references

Capability comparison checked 2026-09-27; recheck provider limits before
implementing a new profile:

- [DO transactional storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
- [D1 batch API](https://developers.cloudflare.com/d1/worker-api/d1-database/)
  and [read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/).
- [Deno Deploy databases](https://docs.deno.com/deploy/reference/databases/)
  and [Deno KV transactions](https://docs.deno.com/deploy/kv/transactions/).
- [Turso SDK and remote/sync modes](https://docs.turso.tech/sdk/introduction).
- [Rivet self-hosted control plane/storage](https://rivet.dev/docs/deploy/self-host/control-plane/).
- [LiteFS primary, replication and split-brain behavior](https://docs.fly.io/litefs/how-it-works/).
