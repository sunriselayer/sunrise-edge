# Sunrise Edge implementation and mainnet roadmap

Updated: 2026-10-08 (Asia/Singapore).

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
selects Native plus SQLite first and Cloudflare DO later; PostgreSQL remains
optional. Ledger is deferred, not complete. Protected keys, trusted content
review, recovery/rotation/revocation and independent qualification remain required.

PR #293 merged normally as `364e2ec8` after exact source `3ec8d7bd` passed
complete independent source review, literal npm-ci and `./scripts/check-all.sh`,
two fresh sequential Native A/B builds with all eleven retained artifact pairs
byte-equal and both owned cleanups successful, and all seven hosted owners plus
success-only `check`. PR #286–#292/#294/#295 are merged components. The merge
tree equals the accepted source tree; main and origin/main were verified clean
and equal. This closes that local integration, not M1–M8 or provider qualification.

PR #296, the direct Native TLS follow-up under
[DR-0219](docs/architecture/decisions/0219-native-direct-tls-connection-ownership.md),
merged normally as `99c75e0c` after exact head `c35a9dec` passed fresh complete
independent source review, literal npm-ci and `./scripts/check-all.sh`, genuine
seven-successor/full e8 withdrawal and extended integration controls, and all
seven required hosted owners plus success-only `check`. The merge tree equals
the approved tree; local main and origin/main were verified clean and equal.
Prior fixture/runner and hosted prerequisite failures remain failures in the
preserved evidence; the corrected final gate does not relabel those attempts.
This closes that local TLS integration, not production PKI, M5 or public readiness.

PR #297, the phase-only ordinary-write policy responsibility refactor,
merged normally as `322dfa3e` after exact head `db466a02` passed fresh literal
npm-ci and `./scripts/check-all.sh`, all seven hosted owners plus `check`,
and complete independent exact-head/source/terminal review. The isolated whole
gate included all three extended owners, seven successors and real epoch8
withdrawals. Main equals origin/main with the accepted tree. Its first failed
whole attempt remains a failure, not a passing gate or a later-source result.

The Native operations slice under
[DR-0222](docs/architecture/decisions/0222-native-stop-and-operational-observations.md)
has independently reviewed stop/drain/observation code and local owning
acceptance at `aa236916`: a fresh initially empty-target capture passed all six
stages, including formatting, CLI build, 185 Native HTTP cases, 66 operator cases,
four real SQLite/TLS cases and strict Clippy. All thirteen new controls and the
actual SIGTERM/INT restart, exact saved-intent replay and stale-writer fixture
passed. Independent terminal review verified ordinary exit, all child/process
group/cgroup release and both compiler leases removed. The first `f6626f5f`
invocation remains NONPASS at Clippy; its tests or target were not adopted as
retry acceptance. Whole required validation and final-head CI/review remain
mandatory integration gates. This local acceptance does not close all M5.
PR #297 is included through normal main ancestry, not execution-evidence reuse;
compiler work stays serialized.

Prior failed/interrupted/source-blocked attempts and component evidence remain
in the [preserved queue](docs/development/history/execution-queue-through-2026-10-07.md#native-integration-and-direct-tls-observations-2026-10-08).
Production PKI/custody, locked advisories and M1–M8 remain open. Reconcile live
heads and ownership before each gate; preserve Draft #235 and never auto-merge
dependency PRs.

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
  consensus Ed25519 adapter and all actual consumers are now merged through
  PR #293. DR-0217 gives the publication-query result, codec, bounds and
  four-category error one execution owner in that accepted integration. Actual
  SDK, original/successor HTTP, Rust DO and operator consumers migrate directly;
  old core definitions and the SDK admission-error conversion are removed.
  Core durable authority and all wire bytes/error priority stay separate. Nine
  pure framing controls and stronger actual SDK error assertions are added.
  Complete source approval and eleven-stage scoped execution passed at
  `bdfee63a`; combined source/gate/CI acceptance subsequently passed at
  `3ec8d7bd` before normal PR #293 integration. This is not the direct-TLS
  follow-up head's full acceptance.
  Remaining core/SDK type coupling is explicit, not solved by inventing
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
  PR #297 shares only ordinary-write phase refusal in
  `runtime::validate_ordinary_write_lifecycle`, consumed by both Memory and
  shared SQL commit pairs under their existing lock/transaction and preceding
  authority checks. PostgreSQL's different checks remain unchanged. Applied
  source bytes match the independently reviewed proposal, with 16 literal phase
  cases and genuine Memory/SQLite import, Seal and SQLite serving refusal
  controls using complete existing snapshots. Normal formatting, the three owning
  crates' tests (288 nonignored passes, zero failed/ignored), all five new and one
  strengthened named controls, and strict owning Clippy passed in a fresh local
  scope. The shared SQL library has zero standalone cases; its consumers are
  exercised by the actual SQLite suites. Earlier formatting and test-build
  failures remain failures. Exact `db466a02` subsequently passed fresh whole
  required, all hosted owners and independent final integration review before
  normal merge `322dfa3e`. This closes the phase-only extraction, grants no new
  authority, closes neither all R1 nor all R2, and is not an M4/M5 prerequisite.
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
  The isolated ENOSPC capability preflight returned ENVIRONMENT_UNAVAILABLE
  (78): unprivileged tmpfs refused required `noswap`. No fault/SQL fixture ran;
  the bounded memory/swap resource decision remains with the human.
- [ ] **M4 — checkpoint, backup and disaster recovery:** publish/verify required
  checkpoint/state-root and immutable body manifests; encrypted off-host backup,
  isolated exact history/receipt/blob restore, fresh fencing, migration/upgrade
  and safe rollback/stop. DR-0212 proves one saved-business-cut inactive import
  with original paths unavailable and genuine WAL creation failure, not arbitrary
  crash continuation, off-host backup, old-writer exclusion or activation authority.
  Use PITR/WAL and PG-specific operations only for a selected PG profile.
  A corrected Native/SQLite checkpoint-and-backup proposal is underway
  separately; it is not accepted or implemented.
- [ ] **M5 — production ingress/operations:** actual auth/TLS PKI/rotation, every
  exposed family's authorization, retry/backpressure/request/work/capacity budgets,
  monitoring/alerts, incident response, validator/liveness operations and spend
  limits. Initial testnet may precede representative load/soak; mainnet capacity
  evidence remains required and its real workload/SLO needs a human decision.
  [DR-0219](docs/architecture/decisions/0219-native-direct-tls-connection-ownership.md)
  implements optional direct Native TLS under the existing connection/work
  owners, immutable bounded startup loading and explicit stopped rotation.
  The corrected exact `c35a9dec` source completed its actual whole required
  gate, genuine successor/history recurrence, final-head independent review and
  complete hosted CI before normal PR #296 merge. Earlier failed/scoped
  attempts remain distinct. This is local transport integration, not all M5.
  [DR-0222](docs/architecture/decisions/0222-native-stop-and-operational-observations.md)
  now defines shared original/live-successor/signerless-history SIGINT/SIGTERM
  stop ownership, permanent work-admission closure, actual queued/detached-work
  drain and one fixed bounded secret-free termination record. Code and thirteen
  new unit controls plus the extended real four-SQLite TLS restart fixture are
  independently source-reviewed and passed the fresh six-stage local owning
  gate at `aa236916`. Whole required validation and final-head CI/review are
  mandatory for integration; this is neither all M5 nor provider qualification.
  No alert/SLO/capacity, globally bounded shutdown or forced-kill safety claim
  follows from these source changes.
  The M5 lock delta only adds direct edges to already locked versions; no PG
  dependency/version changes occur. Locked Rustls 0.23.43 remains affected by
  RUSTSEC-2026-0285 (patched in >=0.23.45). The shared upgrade and local PG
  acceptance authority need the pending human decision; no clearance or old-lock
  exposure recommendation follows. Production PKI, caller authorization,
  protected custody and revocation remain open.
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
  Two fresh same-host Native builds passed at `3ec8d7bd`; this is not complete
  M7 qualification. The original builtins-only isolated-runtime S0 attempt and
  its separate descriptor diagnostic failed. A separately reviewed own-unit
  three-syscall denial subsequently passed the builtins-only checks; it did not
  execute acquired code or prove package isolation. Its exited unit was retained
  for 28.010 seconds before stopping, so a strict twenty-second deactivation
  bound was not met. The corrected two-archive DATA plan is independently
  approved only as a plan; no archive/helper invocation or package acceptance
  follows. Acquired package/native code has not been executed in that isolation
  profile; no runtime clearance is inferred.
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
real workload/SLO and genesis/economic values; the isolated memory/swap resource
boundary and shared Rustls upgrade/local PG acceptance; any bounded protocol-v3
testnet exception and eventual public launch. These choices do not block
independent safe local implementation, but cannot be replaced with fixture values.

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
