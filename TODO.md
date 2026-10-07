# Sunrise Edge implementation and mainnet roadmap

Updated: 2026-10-07 (Asia/Singapore).

This is the only live queue and readiness tracker. Responsibility contracts
belong in [architecture](docs/architecture/README.md), actual owners in the
[code map](docs/development/code-map.md), and dated rationale in
[decision records](docs/architecture/decisions/README.md).
[DR-0200](docs/architecture/decisions/0200-maintainability-and-mainnet-roadmap.md)
consolidates implementation and semantic refactoring; file splitting is not its
completion criterion.

The [original roadmap](docs/development/history/roadmap-through-2026-10-06.md)
and [preserved execution queue](docs/development/history/execution-queue-through-2026-10-07.md)
retain original criteria, exact revisions and failed/interrupted/scoped attempts.
Historical pending statuses and the expired ten-hour window are not the current
queue. The human's later instruction is to continue toward resolving the TODOs;
no new deadline or deployment authority is inferred.

## Established baseline

- [x] CLI Developer MVP: local Rust queries, generic paid Publish/Instantiate/Call
  and ordinary Standard Asset create/transfer/split/merge/mint/burn. Standard
  Asset has no node-core admission or balance privilege.
- [x] Delivery 1: certified network contract lifecycle, replay and declared
  catch-up (PR #228), not complete state handoff.
- [x] Delivery 2: shared ordered claims, bonds, evidence/slashing and reactivation
  (PR #232). Membership, ownership, bond and voting power remain distinct.
- [x] Delivery 3: recurring original-root membership/recovery through actual
  configured e8 withdrawal unlock, changed five-member committees, restart,
  fencing and replay (PR #269/#270, normal merge `952c77f`). This is functional
  local acceptance, not an independent audit or public/mainnet qualification.
- [x] Semantic foundations: writer-free business preparation, domain-bound
  observations/assembly, immutable `VerifiedGenesisRoot`, one committee record
  validator and reconstruction-policy owner, and shared SQLite/DO SQL decisions.
- [x] Local SQLite preflight, offline Standard Asset genesis, exact publication
  reference checks and real four-validator SQLite/TLS/compiled-CLI startup
  (PR #271–#276). Development composition is not operational custody.
- [x] Native/SDK/certified-relay integration (PR #285): exact `fb3e6884` received
  complete independent Codex fallback source approval, literal npm-ci plus
  `./scripts/check-all.sh` PASS, all seven required hosted owners plus `check`,
  and normal merge `4d919b0d` at 07:28 UTC. Merge tree equals the approved head;
  local main equaled origin/main and was clean. PR #281–#284 are merged ancestors.

Validator-set changes, slashing and reward/claim distribution remain FastVote
completion requirements. Functional acceptance does not close their economic
and security release gates.

## Current local integration

[DR-0208](docs/architecture/decisions/0208-native-sqlite-first-and-protected-signing.md)
selects Native plus SQLite first and Cloudflare DO later. PostgreSQL remains
optional. Ledger-specific product completion is no longer mandatory for mainnet;
protected keys, trusted content review, recovery/rotation/revocation and
independent qualification remain required. Ledger itself is deferred, not complete.

Branch `codex/native-sqlite-release-integration-1007` locally combines the slices
below with normal merge commits. This is not yet main integration. Source review,
owning checks, complete local acceptance and hosted CI are separate evidence.
Do not attribute a component/ancestor run to the combined head.

| Slice | Exact source and verified scope | Remaining acceptance |
| --- | --- | --- |
| PR #286: consensus verifier owner | `f797d049`; complete source approval, consensus 259/0 and genuine core successor controls 5/0 plus strict owning Clippy | Full combined acceptance, final CI and integration |
| PR #287: SQLite physical ownership | `621d1a07`; complete source approval, 141/0 real owning tests and strict Clippy | Full combined acceptance, final CI; actual power/ENOSPC/failover remain M3 |
| PR #288: external signing preparation | `85b8a0a2`; complete source approval, SDK/CLI 491/0 and strict Clippy; actual operator owner compiled with strict Clippy | Genuine operator execution in complete acceptance; actual custody stays M2 |
| PR #289: source-free inactive recovery | `7065a1dd`; complete source approval, 3/0 compiled owning tests and strict Clippy | Full combined acceptance, final CI; encrypted off-host/general recovery stay M4 |
| PR #290: protected custody design | `dba52ddd`; complete four-document source approval, no provider selection or protected-key implementation | Human threat/review/key-role choices and actual M2 implementation |
| PR #291: ordered local signatures | `5980522b`; complete final source approval; identical functional `5c05215e` passed 1226/0/7 ignored and strict owning Clippy | Complete acceptance/CI; ignored tests were not executed by the scoped run |
| PR #292: Native release evidence | `2f043f45`; complete final source approval, parent verified 104 compiler/DB/network-free controls and CI recipe/mutation contract; raw BOM refusal is marker-local | Fresh combined-source review/preflight, actual fresh A/B builds, complete acceptance/CI |

Initial failed source/test attempts remain in the preserved queue and immutable
evidence; they are not passed. The `8974634a` ordered test failed one timing
assertion, then was corrected without production changes or weakened assertions.
The earlier `2e191ae5` missing-marker and `69a2992d` raw-BOM source blocks are
preserved; 104 corrected controls are still not actual native-build evidence.
Package compilation does not prove the expensive original operator recurrence.

Next, finish the release-input refusal correction, freeze/review the complete
combined source, verify the actual offline closure and eleven targets, and
compare two fresh sequential native builds under the accepted resource budget.
Then run literal npm-ci and the complete required gate, check final-head CI and
actionable review findings, and normally merge. Reconcile live heads before each
step. Preserve Draft #235 and do not auto-merge dependency PRs.

## Responsibility-oriented work packages

Contracts and acceptance are in
[implementation structure](docs/architecture/implementation-structure.md#maintainability-work-packages).
These are coherent outcomes, not an obligatory PR per helper or facade.

- [x] **R0 — one truthful plan:** one live queue, preserved original requirements
  and attributable history, architecture/code-map/ADR ownership, working links
  and independent review. The complete 662eda8f review verified the exact
  558-line archived body and every original criterion mapping; links passed.
  Implementation/release acceptance remains separate. Keep this queue
  synchronized with actual integration.
- [ ] **R1 — public contract and dependency ownership:** migrate actual consumers
  to one defining data/codec/error/bounds owner and remove copied rules/reverse
  coupling without changing bytes, error priority or authority.
  DR-0201's envelope/list and acknowledgement owner is merged. DR-0209's one
  consensus Ed25519 adapter and all actual consumers are in the integration
  above. Remaining core/SDK type coupling is explicit, not solved by inventing
  a foundations crate containing execution. Complete SDK decoupling is not
  inferred from these migrated boundaries.
- [ ] **R2 — semantic core/runtime responsibilities:** admission authorizes,
  evaluation proposes, completion assembles one atomic transaction, reconciliation
  exposes confirmed exact output, and repositories expose their actual capability.
  DR-0203/0206 removed duplicated state preparation and unreachable native
  execution-capability paths in PR #285. DR-0210 centralizes native connection
  settings/lock-safe attachment ownership; DR-0215 binds actual local signatures
  to invocation identity before retention/exposure. Preserve receipt-first replay,
  actual CAS/ambiguity, legitimate prefix progress and real memory reconstruction.
  Further extraction needs a concrete changing owner, not a file-size target.
- [ ] **R3 — attributable tests and economical CI:** share bounded signed-input
  setup, not the implementation-derived oracle; separate pure/store/HTTP/CLI
  owners. Remove equivalent duplicate work only with exact-input coverage proof
  and measured benefit. DR-0202's private recurrence observations are merged.
  Keep every actual recurrence, unlock delay, restart/fence/fault and selected-PG
  case. The release fixture runs once in the existing cheap contract owner;
  no new heavy CI lane, path-filter skip or unproved ancestor reuse is introduced.
- [ ] **R4 — audit and launch seams:** bind exact source/build/configuration,
  exposed-family authorization, signer/store capabilities and executable
  startup/stop/restart/recovery evidence. DR-0204–0207 relay/native/SDK evidence
  is merged; DR-0212 recovery and DR-0213 release evidence extend the actual
  audit handoff. TLS identity is not protocol authority, local workerd is not
  provider rollout, and an evidence manifest grants no serving/signing authority.

Continue a useful accepted slice rather than reopening completed Delivery 3 or
requiring unrelated facade extraction before functionality. Concurrent writers
need independent owners/worktrees; shared compiler and source ownership stay explicit.

## Delivery 4: first public testnet

This needs a separately approved release profile and real evidence, not fixtures
from another profile. The accepted
[protocol-v3 activation constraint](docs/architecture/core-protocol.md) still
requires atomic composition, authentication/authorization for every accepted
external family, protected signing under DR-0208, S5 and independent security/
release gates. It also applies to public testnet. Any bounded exception needs
explicit human approval and release review.

- [ ] Integrate the reviewed startup/operator prerequisites and pass complete
  gates: author → independent inspection → four independent stores → authenticated
  TLS → compiled CLI → restart/exact replay/refusal.
- [ ] Independently audit the final economics/FastVote, generic contracts, ingress
  and lifecycle scope; fix and independently verify findings. Tech-lead approval
  is not a security audit.
- [ ] Review locked production and build/tooling advisories before exposure.
  Historical seven high tooling findings and zero omit-dev findings are not
  clearance; establish actual exposure/remediation without forced bulk upgrades.
- [ ] Select independent validator operators, custody/admin roles, real genesis/
  chain pins, economics, supported routes and exact release artifact. Native plus
  SQLite is selected first, not already production-certified.
- [ ] Verify actual auth/TLS and rotation, every accepted event family, bounded
  requests/retries/work, liveness, logs/alerts and spend controls. Unsupported or
  unaudited families stay disabled, never generically proxied.
- [ ] Author and independently verify real genesis; rehearse the key/config
  ceremony and independent installations. Development keys/shared test DBs are
  not operational independence.
- [ ] On an authorized topology, rehearse outside-client submission, fees/claims,
  bonds/slash, membership/epochs, stopped-validator catch-up, safe restart/stop
  and recovery with exact receipt/canonical-state checks.
- [ ] Approve launch, rollback and stop instructions before creating resources
  or admitting public traffic. Continued implementation does not authorize deployment.

## Mainnet completion

Every group remains open until original evidence is complete or an accepted
human decision explicitly supersedes it. This consolidates S4/S5, Phase 15–17
and cross-phase criteria; it does not shorten them.

- [ ] **M1 — independent release review:** final threat/delta audits of code and
  deployment, generic contracts, economics, handoff/activation, ingress, storage
  and signing; remediate significant findings, independently verify fixes and
  retain residual-risk decisions. Updating the proposed SECURITY policy still
  needs human approval; current SECURITY.md has not been changed.
- [ ] **M2 — protected signing:** actual custody, operator/authority separation,
  exposure controls, exact operation-specific content verification, refusal/
  failure, recovery/rotation/revocation. DR-0208 removes only Ledger-specific
  product completion. DR-0211's prepared SDK/CLI owners keep immutable identity/
  frame/trust inputs and independently verify provider output without fallback;
  DR-0215 covers actual ordered returned signatures and retained rereads. Neither
  implements protected key storage. Proposed DR-0214 is independently reviewed
  but leaves local-OS, separate-host and hardware threat models unselected.
  Select a real trusted review surface and independent key/recovery roles before
  implementing the backend; plaintext seeds and opaque generic bytes do not qualify.
- [ ] **M3 — selected-profile durability:** atomic object/state/nonce/receipt/
  outbox, bounded indexed delivery, full-read revision/ABA, restart, fencing and
  ambiguity reconciliation. DR-0210's real SQLite process/lock tests are narrower
  than host/power/storage faults, ENOSPC/resource exhaustion, real writer failover
  and TLS failure/rotation. Qualify those actual selected-profile boundaries.
- [ ] **M4 — checkpoint, backup and disaster recovery:** publish/verify required
  checkpoint/state-root and immutable body manifests; encrypted off-host backup,
  isolated exact history/receipt/blob restore, fresh fencing, migration/upgrade
  and safe rollback/stop. DR-0212 proves one saved-business-cut inactive import
  with original paths unavailable and genuine WAL creation failure, not arbitrary
  crash continuation, off-host backup, old-writer exclusion or activation authority.
  Use PITR/WAL and PG-specific operations only for a selected PG profile.
- [ ] **M5 — production ingress/operations:** actual auth/TLS PKI/rotation, every
  exposed family's authorization, retry/backpressure/request/work/capacity budgets,
  monitoring/alerts, incident response, validator/liveness operations and spend
  limits. Initial testnet may precede representative load/soak; mainnet capacity
  evidence remains required and its real workload/SLO needs a human decision.
- [ ] **M6 — economics/genesis approval:** real sets, independent roles, voting
  powers, bond/fee assets/schedules, treasury/supply/distribution, security and
  unbonding parameters, governance authorities, ceremony and supply invariants.
  Never invent production values or infer power from bonds to make examples launchable.
- [ ] **M7 — reproducible supported-runtime release:** pinned source/compiler/
  dependencies/build provenance, two actual fresh artifact builds and byte
  equality, canonical/digest/effects/consensus/proof parity, conformance/property/
  fuzz/adversarial/long-running coverage, tested upgrade/migration/restore and
  advisory review before activation. DR-0213's cheap fixtures/source preflight are
  not native-build execution, hermeticity or complete M7 evidence. Actual Phase
  16/17 criteria remain for advertised providers; a local adapter is insufficient
  and narrowing historical all-provider scope needs approval.
- [ ] **M8 — public operation/final go-no-go:** complete Delivery 4 and actual
  public-operation/recovery evidence; review experimental, unsupported, mock and
  deferred capabilities against the original criteria. Mainnet genesis and
  launch need explicit human approval after the gate review.

### Original requirement mapping

Retain the exact [CLI-first production gate](docs/development/history/roadmap-through-2026-10-06.md#cli-first-node-production-gate)
with DR-0208; Ledger is deferred, not complete. Other original conditions remain.

| Original owner | Open completion groups |
| --- | --- |
| S4 custody/physical/HIL/UI/release | DR-0208 defers Ledger product evidence; M2 retains protected signing/content/recovery/revocation |
| S5 and Phase 15 To-Be exit criteria 1–10 | M1–M5/M7, including exposed-family auth, persistence, operations and certification |
| Post-MVP persistence and production correctness | M3/M4/M5/M7, including actual fault/checkpoint/backup/capacity evidence |
| Cross-phase release, Coding Requirements, Required Integration Tests, Security Invariants | M1–M8; close or explicitly respecify disaster recovery, keys, validators and experimental/deferred criteria |
| Phase 16/17 advertised providers | M3/M5/M7; selected scope and actual provider qualification, not local adapters |
| Phase 3 economics and initial network | Delivery 4/M1/M6/M8; claims/bonds/slash/membership remain required |
| Optional PG rehearsals/faults/workload | Complete selected PG acceptance, M3/M4/M5 when PG is selected; never PG-every-PR |

### Human decisions still required

Protected-signing threat/backend, trusted content-review surface and independent
key/recovery/operator roles; SECURITY policy approval; supported-provider scope;
real workload/SLO and genesis/economic values; any bounded protocol-v3 testnet
exception and eventual public launch. These choices do not block independent
safe local implementation, but cannot be replaced with fixture values.

## Deferred products

TypeScript client, explorer/wallet UI, Ledger, Unique Asset, multisig, contract
upgrade/irreversible authority relinquishment/atomic migration, ZK acceleration,
cross-domain atomicity, full provider expansion and further HA/scale products
remain deferred. Unsupported operations fail closed. Do not make these initial
testnet prerequisites or advertise them as implemented; their applicable
production criteria are not waived.

The [original CLI Developer MVP gate](docs/development/history/roadmap-through-2026-10-06.md#cli-developer-mvp-gate)
retains deferred TypeScript/UI criteria 7–9 and residual limits. The
[original audit entry gate](docs/development/history/roadmap-through-2026-10-06.md#initial-code-security-audit-entry-gate)
and immutable earlier remediations do not audit the later final release scope.

## Validation and completion discipline

- Local SQLite, loopback and disposable development keys only. No production
  D1/Worker writes, cloud resources, public listeners, paid-plan changes, live PG
  service or public launch without separate authority.
- Focused checks during iteration, then literal
  `npm ci --prefix adapters/cloudflare-workers` and complete required
  `./scripts/check-all.sh`. Preserve all seven required CI owners and success-only
  `check`; no softened recurrence delay, skipped owner or fabricated fault.
  [Validation profiles](docs/development/validation.md) separate required from
  selected-PG/provider qualification.
- PG implementation/dependency changes and PG release claims need complete
  fresh selected-source PG acceptance; do not revive PG-every-PR CI.
- Name the invariant, defining owner, actual migrated callers, removed duplicate
  mechanism, unchanged bytes/outcomes and actual verification for each refactor.
- Commit/push coherent slices; complete independent exact-head source review,
  required local acceptance/CI and actionable-finding resolution precede normal
  merge, never squash/rebase. A review approval is not an execution result or audit.
- Recheck actual Git/PR/process state and compiler/source ownership. Keep ancestor,
  scoped, compiled-only, ignored, failed/interrupted and exact-head passes distinct.
  Update this file with real progress; do not put status in README.
