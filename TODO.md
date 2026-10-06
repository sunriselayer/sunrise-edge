# Sunrise Edge implementation and mainnet roadmap

Updated: 2026-10-06 (Asia/Singapore).

This is the only live implementation queue and readiness tracker. Design and
responsibility contracts belong in [architecture](docs/architecture/README.md),
actual code owners in the [code map](docs/development/code-map.md), and dated
rationale in [decision records](docs/architecture/decisions/README.md).
[DR-0200](docs/architecture/decisions/0200-maintainability-and-mainnet-roadmap.md)
defines this consolidation. The [preserved roadmap](docs/development/history/roadmap-through-2026-10-06.md)
retains original criteria, exact revisions, failed/interrupted attempts and
scoped validation. Archiving evidence does not waive a gate.

## Established baseline

- [x] CLI Developer MVP: local Rust CLI, object queries, generic paid contract
  Publish/Instantiate/Call and ordinary Standard Asset create/transfer/split/
  merge/mint/burn. No Standard Asset-specific node-core authority.
- [x] Delivery 1: certified network contract lifecycle, replay and declared
  catch-up (PR #228). This is not complete state handoff.
- [x] Delivery 2: shared ordered claims, bonds, evidence/slashing and
  reactivation (PR #232). Membership is not user ownership or voting power.
- [x] Delivery 3: recurring original-root membership/recovery through the actual
  configured e8 withdrawal unlock, changed five-member committees, restart,
  fencing and replay (PR #269/#270, normal merge `952c77f`). Complete local
  owners passed at functional ancestor `65b2ee8`; reviewed final documentation
  head `b7c034b` passed every required CI owner. This is functional acceptance,
  not independent audit, real provider activation or mainnet certification.
- [x] Semantic refactoring: writer-free shared business preparation; domain-bound
  observations/transaction assembly; immutable `VerifiedGenesisRoot`; one
  structural committee validator; shared reconstruction policy binding and
  native SQLite/DO SQL engine. Accepted callers and scoped evidence are retained
  in the archived verified-architecture checkpoints, not inferred from file size.
- [x] Explicit local SQLite prepare/preflight (PR #271, normal merge `54d9c3f`)
  and offline public Standard Asset genesis authoring (PR #272, normal merge
  `eae9e69`). Local preparation does not select a production provider.

Validator-set changes, slashing and reward/claim distribution remain FastVote
completion requirements. Their functional implementation does not close the
independent economic/security release gate.

## Active integration and ten-hour execution

Human-authorized window: 2026-10-06 13:28:30–23:28:30 UTC, ending
2026-10-07 07:28:30 Asia/Singapore. The existing thread heartbeat owns
continuation and stops starting new slices at that deadline. Ten hours is an
implementation budget, not a promise that external mainnet gates will pass.

Current verified main baseline is `eae9e6972baa293e4ad3ffde5d3ed931b85a6ef5`.
This planning branch explicitly stacks on PR #276 at `c89acfdd`; it must not be
described as already merged or independently validated runtime code.

| Pending prerequisite | Actual head and remaining acceptance |
| --- | --- |
| PR #273: independently pinned offline genesis inspector | `77090388`; complete exact-head Opus source approval and all seven required CI owners plus `check` passed; normal merge pending |
| PR #274: complete published-code reference comparison | `ffbd9ed0`; complete source approval and required CI passed; TODO-only standalone conflict is already resolved in the reviewed PR #275 normal-merge history |
| PR #275: real four-validator SQLite/TLS/compiled-CLI startup | `13b0b76`; complete exact-head source approval and actual three-case TLS process target passed in CI; final recurring-sqlite/check still pending |
| PR #276: storage-neutral startup guide and truthful evidence | `c89acfdd`; complete exact-head two-file Opus source approval; its own final recurring-sqlite/check still pending |

Recheck live heads and required checks before integrating; pending never means
passed. Preserve Draft #235 as extraction material and do not auto-merge
dependency PRs. Avoid duplicate builds and long tests already running elsewhere.

### Responsibility-oriented refactoring queue

The contracts and acceptance for R0–R4 are in
[implementation structure](docs/architecture/implementation-structure.md#maintainability-work-packages).
These are coherent outcomes, not one obligatory PR per helper or file.

- [ ] **R0 — one truthful plan and gate inventory:** consolidate this queue,
  preserve original requirements/evidence, repair links, reconcile merged and
  pending startup work, and obtain independent plan/source review. Current
  status stays here; README does not acquire progress reports.
- [ ] **R1 — public contract and dependency ownership:** establish the defining
  owner for shared data/codec/error contracts consumed by node, wire, SDK and
  host. Migrate actual consumers and remove copied rules or reverse coupling.
  Start with the independently reviewed coherent boundary, not an invented
  foundations crate containing execution. Canonical size bounds must be owned
  once; adapter framing overhead and local resource budgets remain distinct.
  Complete SDK decoupling is not assumed from one migrated boundary.
- [ ] **R2 — narrow core/runtime responsibilities:** make the facade compose
  admission, evaluation, completion, reconciliation and storage contracts;
  separate object/receipt/outbox repositories and memory implementations by
  semantic owner. Remove obsolete duplicate paths only after their callers move.
  A move with unchanged bodies is mechanical progress, not semantic completion.
- [ ] **R3 — attributable tests and economical CI:** reuse bounded signed input
  and environment builders while keeping expected outcomes independent; separate
  pure, real-store, HTTP and compiled-CLI owners. Remove duplicate setup/work
  where equivalent coverage is proved. Keep every real recurrence, delay,
  restart/fencing/fault and optional selected-PG case. Prove any CI reuse from
  exact relevant executable/build inputs; do not add path-filter skips or call
  partial/ancestor/interrupted tests exact-head passes.
- [ ] **R4 — audit and launch seams:** assemble exact source/build/configuration
  provenance, exposed-family authorization inventory, signer/store capability
  inventory and executable startup/stop/restart/recovery evidence for the audit.
  Remove misleading unsupported advertised compositions and stale architecture
  claims; do not build another consensus or general orchestration framework.

Sequence R0 and the ready startup integrations first; review R1's contract
before implementation. R2/R3 may run in parallel only with disjoint owners and
isolated writer worktrees. After a useful accepted slice, continue the next
unchecked item; do not reopen completed Delivery 3 without a relevant change.

## Delivery 4: first public testnet

This is a separately reviewed bounded release profile, not mainnet. Each item
needs real evidence for the selected profile, not fixtures from a different one.

- [ ] Integrate the reviewed operator/startup prerequisites and pass the actual
  required gates. Reproduce author → independent inspection → four separate
  stores → authenticated TLS → compiled CLI → restart/exact replay/refusal.
- [ ] Complete independent economics/FastVote and ingress/lifecycle delta
  audits of the final implemented scope; remediate and independently verify
  findings. Tech-lead APPROVE is not the independent security audit.
- [ ] Human selects the initial hosting/store profile, independent validator
  operators and administrative/key boundaries, genesis authority/chain pins,
  economic configuration, supported routes and release artifact. Keep PG optional.
- [ ] Verify actual endpoint authentication/TLS, all accepted event families,
  rate/request/work bounds, liveness scheduling, logs/alerts and spend limits.
  Unimplemented/unaudited families stay disabled, not generically proxied.
- [ ] Author and independently verify the real genesis; execute the key/config
  ceremony and separate-validator installation. Development keys and a shared
  test database are not independent operational custody.
- [ ] Rehearse on the authorized selected topology: outside-client submission,
  fees/claims, bonds/slash, membership/epoch changes, stopped-validator catch-up,
  safe stop/restart and recovery, verifying receipts and canonical state.
- [ ] Approve the launch profile and startup/rollback/stop instructions before
  actually creating resources or admitting public traffic. This work window
  does not itself authorize deployment or public-network startup.

## Mainnet completion

The following groups consolidate existing S4/S5, Phase 15–17 and cross-phase
release criteria; they do not replace them with a smaller checklist. Every
group is open until its original required evidence is complete or the human
explicitly approves a documented scope change.

- [ ] **M1 — independently reviewed release:** complete final code/deployment
  threat and delta audits, including generic contracts, all economic operations,
  handoff/activation, authenticated ingress, storage and signing. Fix significant
  findings and independently verify corrections; retain residual-risk decisions.
- [ ] **M2 — protected keys and signing:** production custody, separation of
  operators and authority, secret handling, recovery/rotation/revocation and
  signer refusal/failure evidence. The historical complete S4 Ledger gate stays
  open while physical/HIL/UI/release validation is deferred; another signer is
  not an automatically approved substitute.
- [ ] **M3 — selected-profile durable state:** atomic object/state/nonce/receipt/
  outbox, bounded indexed delivery, full-read revision/ABA assertions, restart,
  fencing and ambiguity reconciliation. Verify actual host/power/storage faults,
  ENOSPC/resource exhaustion, real writer failover and TLS failure/rotation at
  the selected profile's owning boundaries. Local process reopen and simulated
  commit-loss are narrower evidence, not complete durability certification.
- [ ] **M4 — checkpoint, backup and disaster recovery:** publish/verify the
  required checkpoint/state-root and immutable body manifests; encrypted off-host
  backup, isolated restore with exact history/receipt/blob checks and fresh
  fencing; migration/upgrade and safe rollback/stop rehearsal. Use PITR/WAL and
  PG-specific exercises only for a PG profile; do not impose PG on lightweight stores.
- [ ] **M5 — production ingress and operations:** actual auth/TLS PKI and
  rotation, every exposed family's authentication/authorization, bounded retry/
  backpressure, request and capacity budgets, monitoring/alerts and incident
  response, validator/liveness operations and spend controls. Initial testnet
  may precede representative load/soak, but mainnet capacity evidence remains open.
- [ ] **M6 — economics and genesis approval:** approve real validator sets,
  voting powers, bond/fee assets and schedules, treasury/supply/distribution,
  security/unbonding parameters and governance authorities. Verify ceremony,
  supply invariants and independent custody. Never invent production values to
  make an automated example launchable.
- [ ] **M7 — reproducible release and supported-runtime qualification:** pin
  source/compiler/dependencies/build provenance, reproduce release artifacts,
  preserve canonical bytes/digests/effects/consensus/proof parity, complete
  conformance/property/fuzz/adversarial/long-running coverage and tested upgrade/
  migration/restore instructions. Actual Phase 16/17 provider criteria remain
  required for advertised supported profiles; a local adapter test is not provider
  certification. Narrowing historical all-provider release scope needs approval.
- [ ] **M8 — public testnet and final go/no-go:** complete Delivery 4 and collect
  actual public-operation/recovery evidence; review all remaining experimental,
  unsupported, mock and deferred items against the production criteria. Mainnet
  genesis and launch need explicit human approval after the gate review.

### CLI-First Node Production Gate

Historical complete gate = Software Production Gate (S0–S3 plus S5) **and**
Hardware Signing Release Gate (all S4) **and** independent security/release
criteria. Ledger deferral permits non-Ledger software work; it does not complete
S4 or silently waive the mainnet constraint. The exact original criteria remain
in the [archived production gate](docs/development/history/roadmap-through-2026-10-06.md#cli-first-node-production-gate).

| Original requirement owner | Consolidated open groups |
| --- | --- |
| S4 physical/HIL/UI/release and production key management | M2, unchanged; alternate signer/scope needs human-reviewed decision |
| S5 and Phase 15 To-Be exit criteria 1–10 | M1–M5/M7; exposed-family auth, durable contracts, operations and certification are not completed by refactoring |
| Post-MVP persistence order and production correctness contract | M3/M4/M5/M7; all fault/checkpoint/backup/capacity criteria retained, implementation follows selected profile capabilities |
| Cross-phase production release gate | M1/M2/M5/M6/M7/M8; experimental/deferred criteria must be closed or explicitly respecified, not hidden |
| Phase 16/17 production-provider criteria | M3/M5/M7; local adapters are insufficient, supported-profile scope must be explicit |
| Phase 3 economic audit and initial-network profile | Delivery 4/M1/M6/M8; claims/bonds/slash/membership remain FastVote completion requirements |
| PG rehearsal and retained optional PG faults/workload | Selected PG acceptance, M3/M4/M5 when PG is selected; never a generic every-PR dependency |

### Decisions still requiring the human

- Initial-network and mainnet supported hosting/store profiles and independent
  operator custody. Native SQLite is a local reference, not already certified.
- Whether mainnet retains the historical full Ledger S4 prerequisite or uses a
  separately reviewed protected-signing scope. Do not silently choose one.
- Supported-provider release scope and any deliberate revision of historical
  all-provider criteria; budget/SLO and production economic/genesis values.

These future release choices do not block local refactoring or audit preparation.

## Deferred product and scale capabilities

TypeScript client, explorer/wallet UI, Unique Asset, multisig, contract
upgrade/irreversible authority relinquishment/atomic migration, ZK acceleration,
cross-domain atomicity, full provider expansion and additional HA/scale products
remain explicit future capabilities. Unsupported operations fail closed.
Do not make them testnet prerequisites or advertise them as implemented.
Their relevant production criteria are not waived by this deferral list.

### CLI Developer MVP Gate

Core Rust CLI criteria 1–6/10/11 are established; historical criteria 7–9
(TypeScript/explorer/wallet) stay deferred. See the [original gate](docs/development/history/roadmap-through-2026-10-06.md#cli-developer-mvp-gate)
for scope and residual limitations, not a second live queue.

### Initial Code Security Audit Entry Gate

The earlier scoped entry gate and remediations are established. Later generic
contracts/economics/ingress/handoff/operator surfaces still require independent
delta/final audits; earlier findings or tech-lead reviews do not cover them.
The [original audit criteria](docs/development/history/roadmap-through-2026-10-06.md#initial-code-security-audit-entry-gate)
and immutable audit evidence remain retained.

## Validation and completion discipline

- Local SQLite, loopback and disposable development keys only in this window.
  No production D1 writes, deployed Workers, paid-plan changes, cloud resources,
  live PG service or public launch without separate authority.
- Run focused checks while iterating, then `npm ci --prefix adapters/cloudflare-workers`
  and the complete required `./scripts/check-all.sh` for acceptance. Preserve all
  seven required CI owners plus the success-only `check`; no softened recurrence
  delay, skipped owner or fabricated fault. [Profiles](docs/development/validation.md)
  distinguish required validation from selected PG/provider qualification.
- PG implementation/dependency changes and PG release claims additionally need
  complete fresh selected-source PG acceptance. Do not revive PG-every-PR CI.
- Each refactor names the invariant, defining owner, migrated callers, removed
  duplicate mechanism, unchanged bytes/outcomes and actual verification.
- Commit/push coherent reviewed slices. Use fresh independent explicit complete
  exact-head review and passing required CI before normal merge, never squash
  or rebase. Review actionable findings; approval is not an execution result.
- Check actual Git/PR/process state at every continuation. Mark completion only
  with owning implementation and evidence; distinguish ancestor checks from
  exact-head checks and interrupted from passed. Update this file, not README.
