# Sunrise Edge implementation and mainnet roadmap

Updated: 2026-10-10 (UTC).

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
Historical pending statuses and expired implementation windows are not the
current queue. The first 2026-10-09 eight-hour window ended at 08:34:32 UTC;
a separate direct human request authorized eight more hours of ordinary
Native+SQLite source work from 08:58:27 through 16:58:27 UTC, which also ended.
The direct 2026-10-10 request to resolve TODO resumes ordinary implementation;
the recurring automation is CI-only, not implementation or local-state polling.
The newer direct request to resolve dependency acquisition authorizes only
missing exact locked Rust inputs from official crates.io, without package code
execution. Acquisition still needs its own admitted bounded protocol; the disk
floor-policy choice remains unanswered. Source work does not admit unresolved
runtime prerequisites, global-cache substitution, live PG, deployment, public
launch, custody or global-host changes.

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
- [x] Native SQLite integration (PR #293): normal merge `364e2ec8`, tree
  `00e1d340`, equals independently reviewed frozen `3ec8d7bd`. Literal npm-ci
  and full required `./scripts/check-all.sh` both exited 0 on that exact source;
  fresh eleven-target native A/B byte equality was independently verified.
  All seven hosted required owners plus success-only `check` succeeded in
  run `37610011266`. Components #286–#292/#294/#295 are merged. This local
  profile acceptance is not a security audit or completion of M1–M8.

Validator-set changes, slashing and reward/claim distribution remain FastVote
completion requirements. Functional acceptance does not close their economic
and security release gates.

## Current native baseline and next gaps

[DR-0208](docs/architecture/decisions/0208-native-sqlite-first-and-protected-signing.md)
selects Native plus SQLite first and Cloudflare DO later. PostgreSQL remains
optional. Ledger-specific product completion is no longer mandatory for mainnet;
protected keys, trusted content review, recovery/rotation/revocation and
independent qualification remain required. Ledger itself is deferred, not complete.

PR #293 normally merged the combined source into main at `364e2ec8`; its tree
equals `3ec8d7bd`. The component source/scoped observations below remain
separate from the exact combined full gate, native A/B and hosted CI above.
Do not relabel an earlier component/failed/ancestor attempt as that combined run.

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

PR #299, the Native operations slice under
[DR-0222](docs/architecture/decisions/0222-native-stop-and-operational-observations.md)
merged normally as `ffcf5767` on 2026-10-08 at 15:25:58 UTC. Exact final head
`535ca4cb` passed literal npm-ci and the complete required gate, all seven
hosted owners plus success-only `check` in run `37758494656`, and a fresh
independent final exact-head integration review. The normal merge tree equals
the approved head tree. The gate retained all thirteen new controls, the real
four-SQLite TLS SIGTERM/INT stop/restart/exact replay/fencing fixture, all three
extended owners and genuine seven-successor/full epoch8 withdrawals. Its
earlier scoped acceptance at `aa236916` and first Clippy NONPASS remain distinct.
Actual child/process-group/cgroup and lease release was independently verified;
only the finished owned unit was stopped. This technical integration does not
close M5, protected custody, security or public/mainnet qualification.

Initial failed source/test attempts remain in the preserved queue and immutable
evidence; they are not passed. The `8974634a` ordered test failed one timing
assertion, then was corrected without production changes or weakened assertions.
The earlier `2e191ae5` missing-marker and `69a2992d` raw-BOM source blocks are
preserved; their corrected fixture controls are not relabeled as native builds.
Package compilation does not prove the expensive original operator recurrence.

Historical frozen `afac7908` received complete source approval and passed
the actual offline-closure/eleven-target preflight. Its first genuine native A
build completed and all eleven independent snapshots were verified; cleanup A
then failed on an internal Cargo hardlink's own unlink metadata transition.
Build B did not start. Preserve that incomplete run rather than reuse/adopt it.
The accepted DR-0213 clarification requires closed in-tree link groups and
byte-verified own-unlink transitions. Corrected `c3f9e3e4` has complete independent
source approval and 134 parent-verified cheap controls plus the CI contract.
The later exact `3ec8d7bd` sequence independently verified BOTH new native
builds and byte equality. No failed A is reused or relabeled.
The PR's later `70702fbe` bot correction changes only a local SDK provider-length
diagnostic. Its precise 63/65-byte refusal controls passed in the `bdfee63a`
scoped paid SDK target, then the exact `3ec8d7bd` combined gate passed.
That pass is not inherited from `afac7908`; its failed cleanup remains failed.

DR-0216's quiet local TLS leaf rollover, separate CA cutover and finite peer-close
controls at `2ba302a2` completed all six scoped stages at 09:49 UTC: format,
actual operator/CLI builds, real TLS tests, SDK remote TLS and strict Clippy.
Complete independent source approval covers all eight paths. Earlier `4643836a`
rcgen API compilation and `d1da1892` child-reap Clippy failures remain preserved;
neither is counted as a pass. These controls are not production PKI, revocation,
custody or M5 qualification.

DR-0217's complete source review and eleven scoped stages passed at `bdfee63a`
at 10:17 UTC. Actual immutable query frames, independent SDK refusal/error
chains, verified paid dependency loading, historical HTTP and compiled CLI
lifecycles are covered. This remains one migrated ownership boundary, not whole
SDK decoupling, optional PG qualification, or an independent security audit.

M4's 49-path encrypted-recovery candidate is preserved exactly in source-only
snapshot `a9aef828` before integration with accepted normal-main `ffcf5767`.
Its saved lock remains exactly `dd280028` / 82,801 bytes, not a new resolution.
The original shared-target invocation is NONPASS because a mandatory new test
was absent; the later isolated invocation is NONPASS at strict Clippy after
real 15 canonical, 184 SDK and 81 operator cases. The minimal Clippy correction
received source-only review but has not passed a corrected owning run. Those
partial results are not acceptance of the new combined source.

The combined `5c28e868` source and its proposed rev3 owning packet received
different source-only approvals; neither was a corrected runtime invocation.
They are now baseline evidence, not approval of the later writer/publication/terminal
source commits below. The inherited private Cargo home is unavailable for an
unknown reason. Human-authorized local reconstruction is not admitted: exact
local inputs are incomplete and its replacement protocol remains unqualified.
The 2026-10-10 direct request now authorizes official acquire-only missing locked
inputs. The fresh inert census still has 41 missing archives, 36 missing sparse
name files and three missing version records. No acquisition or quarantine was
created: the bounded acquisition implementation remains incomplete, including
combined evidence accounting, held-input capture and failure/release proof.
Global caches and the retained M4 target must not be substituted or repopulated.

Different complete SOURCE_ONLY_APPROVE now covers exact `37ac3197`: all 67
changed bodies and their relevant ordinary current-route contracts, including
the genuine fee/bond/slash/evidence and receipt/output defining-owner closure.
Root independently rebound all 1,045 actual tracked bodies to that clean HEAD.
This resolves source review for that snapshot only; no new build, test, input
acquisition, runtime admission or TODO-group completion follows.

Next: resolve the private-cache prerequisite within the actual authorized scope,
including the unanswered floor choice, and bind/review a NEW owning
packet before any invocation; then execute fresh required, twelve-target A/B
and final-head hosted gates. Old metadata/scoped helpers must not run with
substituted source or target bindings. M4's age edge expands shared
`futures-util` features used by PostgreSQL: the documented PG dependency
acceptance requirement remains
unresolved, even though Native+SQLite development may continue. No live PG
or waived selected-profile check is authorized. Keep the accepted
[DR-0221](docs/architecture/decisions/0221-encrypted-recovery-closure.md)
transport/restore requirements and fresh twelve-target A/B gates intact.
Rustls advisories, optional PG acceptance, production PKI/custody and M3's
environment-unavailable memory/noswap choice remain open. Reconcile exact heads
and ownership before action; preserve Draft #235 and never auto-merge dependencies.

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
  consensus Ed25519 adapter and all actual consumers are merged in the baseline
  above. DR-0217 now gives the publication-query result, codec, bounds and
  four-category error one execution owner in the merged baseline. Actual
  SDK, original/successor HTTP, Rust DO and operator consumers migrate directly;
  old core definitions and the SDK admission-error conversion are removed.
  Core durable authority and all wire bytes/error priority stay separate. Nine
  pure framing controls and stronger actual SDK error assertions are added.
  Complete source approval and actual eleven-stage scoped execution passed at
  `bdfee63a`; the separate exact `3ec8d7bd` combined source/gate/CI acceptance
  then passed and normally merged at `364e2ec8`.
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
  The bounded non-faulting private-namespace capability attempt ended
  ENVIRONMENT_UNAVAILABLE/78: required unprivileged tmpfs noswap was unsupported.
  No SQLite/ENOSPC filler or privilege fallback ran. Retained actual failure/
  refusal history remains separate; safe host/resource direction needs a human.
- [ ] **M4 — checkpoint, backup and disaster recovery:** publish/verify required
  checkpoint/state-root and immutable body manifests; encrypted off-host backup,
  isolated exact history/receipt/blob restore, fresh fencing, migration/upgrade
  and safe rollback/stop. DR-0212 proves one saved-business-cut inactive import
  with original paths unavailable and genuine WAL creation failure, not arbitrary
  crash continuation, off-host backup, old-writer exclusion or activation authority.
  Use PITR/WAL and PG-specific operations only for a selected PG profile.
  Accepted-design [DR-0221](docs/architecture/decisions/0221-encrypted-recovery-closure.md)
  specifies a corrected bounded encrypted saved-closure transport for original
  and full predecessor roles. Parent full-text review and a different complete
  DESIGN_APPROVE are finished, including C1-C3 and the C4 same-cursor real-EOF
  correction. The bounded SDK source, encrypted pack/open and genuine original/
  seven-epoch source-free restore controls were authored in the original
  48-path tuple. Earlier surplus-directory and independent L>0 layout BLOCKs
  remain preserved. Their narrow corrections include an independently fixed
  L=1 record/hash/all-role/File/Footer vector; the L=16 ceiling and negative
  controls are retained. The corrected original tuple received different
  SOURCE_ONLY approval, not execution. The later 49-path candidate and exact
  saved lock are preserved at `a9aef828` against accepted normal-main `ffcf5767`.
  Saved bounded graph DATA and narrow exact-lock adoption have separate review;
  the original metadata attempt remains NONPASS, not dependency qualification.
  The shared-target named-control absence and isolated strict-Clippy failure
  remain NONPASS; the corrected source has no new owning or whole execution.
  Actual corrected owning/full encrypted restore,
  twelve-target A/B and final-head hosted acceptance are still required. The
  unconditional age edge expands `futures-util` features shared with PostgreSQL,
  so final dependency acceptance also needs the documented selected-PG evidence
  and pending authority; unchanged PG versions do not waive that obligation.
  Advisory/MSRV/license, runtime and off-host custody qualification remain open.
  Aggregate repeated-walk/decode/deadline cost is still UNKNOWN;
  do not reset or widen the shared budget to force a pass. Both prior design
  BLOCKs remain preserved. Disposable local X25519 does not select real custody
  or off-host retention; no M4 completion is claimed.
  Separate normal local commits `bcd9afd0` and `ffed0cd0` received different
  exact-delta SOURCE_APPROVE. A fresh complete-source SOURCE_APPROVE then covered
  their combined `cf37216d` snapshot only; that is now baseline, not approval of
  later edits or runtime acceptance. The writer adds four source controls for
  repeated short writes through age finish and round-trip, nonempty write-zero
  refusal, exact partial-prefix progress
  followed by error, and final age-emission failure. Publication adds five
  Linux-only source controls for seven private operation-boundary refusals,
  independently checking original pending/final inode/bytes and unrelated
  sentinel preservation within the declared attachment field set, not every Unix
  metadata field. Normal local `576575eb` adds a private terminal gate and three
  Linux source controls: actual file-backed final-age emission refusal, natural
  late byte-identical foreign-output refusal, and ordinary publication/completion
  success. Its different exact-delta SOURCE_APPROVE is static only. The gate keeps
  finish result, stage recheck, ordinary no-clobber publication, stage completion,
  the original budget check and unchanged count-print order; returned public
  counts are not proof/import authority. Independent fixture byte/full-stamp/EOF
  oracles and unchanged staged payloads/sentinel do not establish full CLI output.
  Normal local `76a1603b` adds a Linux test-only same-instance completion-entry
  observer and source assertions of 0/0/1 for those three terminal controls;
  these are unexecuted expectations, not observed counts. Normal local
  `15ba7f7a` adds shared-budget admission as the first ordinary `new_file` action,
  before parent preparation/private creation. Its exact-delta SOURCE_APPROVE
  does not approve the whole candidate. All three callers retain preceding
  validation; refused/expired admission deliberately prioritizes opaque Quota.
  A further Linux direct-completion source control irreversibly refuses the
  original budget and expects entry 1, Quota and an absent diagnostic. It checks
  original held payload/sentinel descriptors with bounded positive positional
  reads, original full file stamps and real EOF, plus the outer fixture directory
  identity, not a capture-root descriptor. Admission is not atomic with later
  refusal or IO; empty/partial unqualified residue can still remain.
  All 18 original named recovery controls remain; the added four plus five plus
  three plus one are source declarations, not discovered or executed counts.
  This is 31 operator recovery names (41 across the three owning libraries),
  not an inferred test-run total or the separate 35 encrypted role inventory.
  Source review found a terminal fixture contradiction: the original e0->e1
  link plus seven genuine later handoffs reaches e8 with eight predecessors,
  requiring `3 + 4*8 = 35` roles. The terminal assertion/comment and prospective
  role requirements are corrected only in source; no execution is claimed.
  A further source correction preserves the original activation Indeterminate
  reason when an exact matching Serving record is followed by failed full
  reconciliation; only complete reconciliation reports Activated. Three pure
  result-classification controls are source declarations, not executed tests
  or additions to the 41 selected recovery-library controls. The landed-storage
  reply-loss control now has one additional UNEXECUTED node-core SOURCE name:
  `ordered_economics::tests::causal_placement::control_reconstruction::frozen_completion::successor_activation::successor_activation_reply_loss::first_successor_activation_reply_loss_on_real_sqlite`.
  It compares three complete real-SQLite import/activation captures, preserves
  original CancellationRequested on a refused reconciliation read, and asserts
  same-wrapper AlreadyActivated settlement without a second commit. This is
  trait-level reply/read loss, not failed SQLite I/O, fsync or crash qualification;
  all format/compile/owning/full/CI acceptance remains pending. The 31 operator,
  41 selected recovery-library names and 35 roles are unchanged; ordinary
  pre-dispatch/already-Serving refusal paths and old controls are unchanged.
  Original and corrected-rev1 publication BLOCKs remain immutable; rev2 repaired
  the private fixture/oracle/sentinel/type and cleanup-assertion findings.
  None of these new slices has been formatted, compiled or executed. Pre-syscall
  refusal injection does not prove actual failed sync, power loss, crash
  durability, pack completion output, source-free SQL restore or off-host custody.
  The current combined-source verdict is recorded above. Owning admission and
  every execution/qualification gate above remain required.
  The 2026-10-10 source follow-up strengthens the existing compiled relocation
  fixture with exact complete pack/open stdout, independently counted original
  regular-file/link inputs and empty stdout for every existing recovery refusal.
  Invocation order, full role/state/receipt/blob checks and library selectors
  are unchanged. These new assertions are uncompiled and unexecuted; they do
  not supply a CLI-output pass or close M4's owning/full/runtime gates.
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
  gate at `aa236916`. Final `535ca4cb` then passed its genuinely fresh whole
  required gate, all seven hosted owners/check and independent exact-head
  integration review before normal PR #299 merge `ffcf5767`. These are not
  all M5 or provider qualification, and do not qualify the new M4 source union.
  No alert/SLO/capacity, globally bounded shutdown or forced-kill safety claim
  follows from these source changes.
  The 2026-10-10 source follow-up under
  [DR-0223](docs/architecture/decisions/0223-local-native-observation-export.md)
  adds default-off local observation export to all three Native serving modes.
  An existing caller-owned Unix datagram collector receives the fixed 15-counter
  record only on opt-in SIGUSR1 requests, with charged one-second cooldown and
  prioritized stop polling; the termination record and actual work drain remain
  unchanged. Source controls are uncompiled and unexecuted; static review is
  separate from whole-candidate and runtime acceptance. This does not qualify
  public monitoring, delivery, alerts/SLO/capacity or production ingress, and
  closes no M5 gate.
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
  advisory review before activation. DR-0213's exact `3ec8d7bd` fresh eleven-
  target native A/B byte equality passed and was independently verified; cheap
  fixtures alone were never native execution. This is not hermeticity or complete
  M7 evidence. The new encrypted `business_recovery` target extends the SAME
  closed release owner to twelve selected binaries; its new exact-source
  dependency review and fresh twelve-target builds are still unexecuted.
  The original S0 unknown-FD attempt and separate diagnostic remain FAILED.
  A different own-unit three-syscall denial passed only builtin checks, not
  acquired-code isolation. Its exited unit remained for 28.010 seconds before
  stopping, so the strict twenty-second deactivation bound was not met.
  A separate bounded DATA-only stage actually acquired and integrity-verified
  exactly the
  Wrangler 4.148.0 and Vitest plugin 1.3.7 archives, closed all 51 member records
  and read their manifests; the parent accepted raw exits, caps and teardown.
  No package code, native binary or install was executed. The separate fixed-
  member TEXT reader received complete different source approval, then one
  authorized local-only capture retained exactly 17,568,262 original bytes.
  Both member hashes, complete raw exit/EOF/byte evidence, source identities
  and all 27 owned child PIDs/process-group absence were parent-verified.
  This permits text-only copy analysis, not evaluation or installation.
  Actual bundled dependency
  remediation, installation/compatibility and advisory clearance remain UNKNOWN.
  Actual Phase 16/17 criteria remain for advertised providers; a local adapter
  is insufficient and narrowing historical all-provider scope needs approval.
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
real workload/SLO and genesis/economic values; shared Rustls upgrade and
complete local PG acceptance; any bounded protocol-v3 testnet exception and
eventual public launch. These choices do not block independent
safe local implementation, but cannot be replaced with fixture values. M3's
required noswap host/resource prerequisite and real off-host recovery custody/
retention remain human choices; the disposable DR-0221 test profile selects
neither. Do not weaken the actual environment refusal to manufacture a pass.

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
