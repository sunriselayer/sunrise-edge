# Sunrise Edge implementation and mainnet roadmap

Updated: 2026-10-13 (UTC).

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
its earlier eight-hour source window is 03:01:23 through 11:01:23 UTC that day.
A newer direct eight-hour request authorizes ordinary source implementation
from 06:46:39 through 14:46:39 UTC on 2026-10-10. The CI-check recurring
automation was deleted at that request; no replacement automation was created.
The newer direct request to resolve dependency acquisition authorizes only
missing exact locked Rust inputs from official crates.io, without package code
execution. Acquisition then still needed its own admitted bounded protocol; the human
has selected the [observed acquisition floor policy](docs/architecture/decisions/0225-observed-acquisition-floor-and-current-binding.md)
with stop before 5 GiB. Source work does not admit unresolved
runtime prerequisites, global-cache substitution, deployment, public
launch, custody or global-host changes.

The current direct human request resumes ordinary Native+SQLite implementation
and requires resolving acquisition blockers and all twenty open groups. It
selects monitored stop before the 5 GiB floor, not a full-duration global-space
guarantee. That policy decision alone closed no TODO group or release gate.
Current dependency preparation and actual local execution are recorded below;
older source/admission snapshots are not the current local-test blocker.

The 2026-10-11 direct human decision additionally authorizes Docker-only local
PostgreSQL and bounded isolated Docker disk-full/forced-stop experiments. Keep
host disks, swap/settings, foreign workloads and real data outside the fault
scope. This is environment/verification authority, not a successful test,
dependency-acquisition retry, public deployment or release admission. The
historical provider-stopped author is not resumed. The 2026-10-12 direct human
instruction assigns ordinary official locked-input authoring to the root;
actual platform safeguards and every acquisition/verification limit remain.

The newer 2026-10-12 direct instruction permits ordinary non-destructive
implementation, dependency preparation and local verification without repeated
approval questions. Select 700 newly materialized regular files, including
control/proof files; directories are counted separately. Existing source,
shared caches, the retained target and failed evidence are preserved. This does
not authorize public deployment, real keys, foreign-resource destruction or
fabricating completion of the launch duties below.

### Current local verification, 2026-10-13

The current working source passed `cargo fmt --all -- --check` after ordinary
formatting. With exact Node 22.20.0, the native-release fixture owner passed all
139 controls, including real descriptor closure on initial-stat failure, and
the CI gate-contract owner passed. The first release-fixture invocation used
Node 26 and failed its version guard; it remains a failure. These are fixture
and style results, not native A/B builds, Rust product tests or PG acceptance.
The dedicated validation runner confines its own compiler unit to 4 GiB memory,
no swap, two Cargo jobs and 32 MiB retained raw output, and stops its
own unit if monitored free space drops below 6 GiB. Its actual short execution,
complete pipe EOF and owned cgroup release were checked.
Focused runs default to 30 minutes. Complete ordinary local plans may explicitly
select a finite deadline up to six hours, retaining the existing long CI cases
and the original-start clock. This does not change acquisition's 300-second
budget or qualify the historical 30-minute release invocation packet.

The dedicated locked Cargo home was reconstructed and root-verified against
all 311 archive checksums and 287 complete sparse-index histories before Cargo
execution. Shared caches, the lock and retained target were not substituted.
The separate independent data reader did not finish within its original bound;
that failure remains distinct from root verification and is not independent
release acceptance. Actual locked/offline all-feature library tests passed:
canonical-encoding 15, protocol-types 11, hashing 20, crypto 31, runtime 149 and
runtime-sqlite 96, with zero failures. The two ignored SQLite cases were then
executed separately in fresh bounded Docker noswap volumes and both passed:
real ENOSPC before COMMIT and the literal COMMIT-error/reconciliation path.
Their exact owned containers, volumes and imported test image were observed
absent after cleanup. This is selected fault-test evidence, not power-loss,
referenced-blob durability, off-host custody or complete M3 acceptance.

The complete `runtime-postgres --all-targets --all-features` suite passed with
every optional live prerequisite required, no skipped live cases, zero failures
and zero ignored cases. All twelve integration targets ran, including real
SIGKILL/WAL recovery, tablespace ENOSPC, WAL exhaustion, connection exhaustion,
backup/restore, PgBouncer, blob/range reads, outbox and portable-state fencing.
There were 22 live integration controls, six library controls and 77 support
controls repeated within each integration target; repeated support cases are
not independent live-PG evidence. The same retained tmpfs, cluster identity and
concrete loopback port were checked across restart, and the bounded parent
completed with both pipe EOF and its owned cgroup absent. This clears the
previously unexecuted PG runtime/fault suite, not the separate complete PG
protocol/soak workflow or whole release acceptance.

The subsequent complete five-group PG profile also passed on the current
product source (`validation-2b62f729031f40c3a0e75ec1a9e8b8f2.json`):
pg-storage, pg-lifecycle, pg-drain-history, pg-business-audit and
pg-recovery-economics, including the original inventory and smoke-soak owners.
All required live prerequisites remained enabled. Actual exit was 0 after
707.61 seconds, with both pipe EOFs, no refusal and absent owned compiler
cgroup; the persistent supervisor independently exited 0. The same retained
cluster and fixed loopback port survived the profile. Its exact primary owner
containers and volumes were independently observed absent after cleanup.
This supplies the previously missing selected-PG local verification, not
final-head CI, independent security/custody or a completed release group.

Initial PG preparation failures remain preserved: the legacy tmpfs option
parser rejected `noswap`, mount-output terminal framing failed an inventory
comparison, readiness mistook the image's temporary Unix-only initializer for
the final server, and an empty Docker HostPort request changed after restart.
The corrected runner uses bounded owner-labelled local-driver tmpfs volumes,
TCP readiness and one concrete endpoint. No test assertion or fault was removed.
The first core/SDK/operator library build exposed four test-only API errors in
Withdraw admission controls; their constructor and array-access corrections
preserve all assertions and domain checks. The next core run passed 1,253 cases
but failed one slash-evidence fixture's missing-ancestor prerequisite, with seven
dedicated-lane cases ignored. Its correction uses real signerless authenticated
proposal observation after the original replay checks, without restoring lost
evidence or weakening the application refusal; its focused rerun passed, then
the full core library passed 1,254 cases with zero failures and the same seven
dedicated-lane ignored cases. SDK library tests passed all 190 cases.
The operator library initially passed 122 cases and failed the existing real-age
short-write round-trip control. Actual age header serialization requires a
complete write: the private CipherWriter now completes finite positive short
writes under the original byte/deadline budget, hashes/counts only accepted
bytes and permanently refuses zero progress, IO error or quota refusal.
The original control and every original assertion remain. A new same-budget
mid-short-write refusal control is outside the original 41 selected recovery
names. The corrected complete operator library passed 124 cases, zero failures
and zero ignored cases. This resolves that real transport defect, not complete
encrypted CLI relocation, the original selected-lane recurrence or M4 release.
The next complete five-group PG profile first exposed a test-helper compiler
error: an unused `_bytes` binding was present in only one branch of an or-pattern.
Changing it to the nonbinding wildcard preserves every pipe result/error rule.
The corrected profile then reached the compiled SQLite encrypted-relocation
owner and failed its exact durable receipt/object-history comparison at
`encrypted_recovery_acceptance.rs:535`. That historical failed run remains
preserved. The sole difference was a source-local synthetic FastVote prepare
receipt which DR-0170/0176 already validate and exclude from business import;
every shared original receipt and object head/version matched exactly. The
corrected oracle derives exact expected local IDs/digests from canonical
prepared records and owning key/hash APIs, validates their full empty source
records and requires their destination absence. Unknown synthetic and original
receipts remain in full equality; no production restoration, raw source bytes
or additional metadata normalization changed. The genuine compiled original
encrypted relocation and its three added negative controls passed with six
total passes, zero failures/ignored cases, complete pipe EOF and owned cgroup
release (`validation-8fc2d1fa3a504660b0ffbf9d29e0dcc4.json`). Full recurring
relocation and the complete PG/required profiles remain separate gates.

Current-source R1/R2/R3 review found one remaining duplicated pure receipt
binding in durable reconciliation. It now calls the existing envelope owner,
preserving outer lookup identity, RequestIdReuse and nested decoding/binding/
encoding error order. Independent implemented-delta review found no correctness
issue. All four added actual reconciliation controls passed, including exact
responses, absent receipt, joint-invalid outer/nested fields and malformed
bytes, with unchanged receipt storage and zero new reads/commit/outbound work
(`validation-77288c51fe0041fea36055d2813dc603.json`). Complete required attempts
also exposed formatting and strict Clippy failures; fixes do not disable lints,
drop a selector or weaken a functional assertion. Those failed attempts remain
failed. The first persistent-supervisor complete attempt
(`validation-301bd452868745298e76305c63693fb0.json`) reached its original
30-minute unit deadline during compiled e2 recurrence and exited 1; its complete
pipe EOF and absent owned cgroups do not make the partial recipe a pass.
The actual unit journal records `timeout`; the monitor's `stopped` field is
null because the inner unit's own timer acted first. Before that deadline,
all ordinary workspace Rust tests passed, including node-core 1,258 with seven
dedicated-lane ignores, SDK 190, operator 124 and Native HTTP 199. The unchanged
exact core recurrence passed in 600.85 seconds, and compiled readiness passed
in 30.54 seconds. The separate earlier supervisor interruption with exit 143
remains incomplete and its cause unknown. Sticky-signal cleanup and complete
raw capture were corrected and independently reviewed; late/missing terminal
results still refuse. That required attempt remained incomplete; the subsequent
complete five-group PG profile passed as recorded above.
Literal `npm ci --prefix adapters/cloudflare-workers` completed successfully
with exact Node 22.20.0. Its seven reported high tooling advisories remain a
separate release hold; no automatic dependency/lock rewrite was performed.
Old uncompiled/source-only captions below describe their recorded snapshots,
not a waiver or whole-source pass. Complete required,
independent review, fresh thirteen-target A/B and final-head hosted gates stay open.

The six-hour-bounded complete required attempt
(`validation-2a2023f6c25b47a4a64ed28f24249b0d.json`) failed after 12,771.86 seconds,
with actual exit 101, both pipe EOFs, no timer/floor refusal and absent owned
compiler cgroup. Strict workspace Clippy and ordinary tests passed, as did all
seven compiled successors, real e8 activation/withdrawals and the separate
terminal e8 Freeze/drain. The following `pack-saved` stage returned opaque
`recovery attachment refused`; no 35-role pack/open success or full required
PASS is claimed. Its source fixture was removed by the owning test's normal
cleanup, so the exact underlying refusal remains unproven.

A new filesystem-only 35-role/1,162-file calibration separately demonstrated
sticky observation exhaustion in 0.20 seconds under the old 262,144 limit.
Redundant generated-directory walks were reduced without removing body/hash/
stamp/inventory checks. DR-0221's dated product-profile amendment selects a
finite 2,097,152-observation ceiling, with old-limit refusal retained explicitly;
the other product, acquisition and host limits remain distinct and unchanged.
The full terminal calibration and traversal/refusal controls now passed, including
actual age encryption, publication/completion, decryption and both EOF checks.
The new complete strict-Clippy/SDK/operator run
(`validation-e5d1405528a043b6a6df38314082368c.json`) passed with 191 SDK and
131 operator cases, zero failures or ignores, both pipe EOFs and the owned
cgroup released. The filesystem calibration uses synthetic one-byte bodies,
not signed history: genuine full recurrence/relocation remains a separate gate.

The following genuine full required attempt at `4ed170f3`
(`validation-bc406c8b1e2b46bcb905451e32fea271.json`) also failed: exit 101,
both pipe EOFs, no timer/floor stop, 12,960.54 seconds and absent owned cgroups
and recorded process groups. The original plus seven recurrent successors,
e8 withdrawals and terminal Freeze/drain ran, but `pack-saved` returned
`recovery quota refused`; its specific limit is not yet established and no
35-role pack/open or complete required PASS follows. All twenty open groups
remain open. DR-0232 adds first-refusal diagnostics and bounded failed-input
reproduction; neither relaxes admission. Its separate observation-profile
amendment raises only that ceiling from2,097,152 to8,388,608 after a323-height/
2,366-file mechanical control actually exhausted the old allowance. All other
caps and assertions remain. This is not the minimum required allowance or
the unique historical failure cause; genuine recovery remains a separate gate.

The corrected observation profile passed the complete owning library run
(`validation-342ea58bd42a4b2985550ed100881745.json`):195 SDK,132 operator and
96 SQLite cases, zero failures, with the five Docker-only cases ignored in
that ordinary run and separately executed below. Both old refusal allowances,
the first-refusal/poison controls and the323-height/2,366-file full mechanical
capture/age/publication/completion/decryption/authenticated+physical EOF control
passed. This is not a genuine signed eight-link restore or complete required PASS.

All five selected Docker SQLite fault controls passed using the freshly rebuilt
exact executable, including the new public blob-publication failure boundary
(`validation-820a9b842ca945c7a69a9c1d62c08383.json`). Full physical blob rows,
twelve structured SQL tables and four portable collections remain exact across
failure/release/existing-only reopen; one explicit blob retry and duplicate
idempotence passed. Actual exit0, both EOFs, owned cgroup release and independent
successful empty owner-labelled Docker container/volume/image listings were
verified. The separate same-blob-file SQLITE_FULL probe does not reveal the
public put's hidden raw error; none of this closes whole M3 or power/custody gates.

The next fresh complete PG attempt
(`validation-1dcee620903541bea27bbc9fa2763d20.json`) failed during compilation of
the added recovery-reproducer support, before live Rust PG cases. The parent
started validation before that source handoff was complete; that sequencing
error and its compiler errors remain NONPASS. Both EOFs, exit101, cgroup release
and exact owned Docker absence were checked. Earlier complete PG results remain
their own successful scopes, not acceptance of this newer candidate.

The failure-only reproducer is now source-reviewed and tested. Its held-root
componentwise creation/readback checks preserve every original successful
relocation assertion and never execute retained DATA. The first focused run
(`validation-034bc6b328064c79b7c4727faa00e50a.json`) exposed a prefix-refusal
classification mismatch; it remains failed. Mapping only NOFOLLOW directory
NOTDIR/LOOP errors to Identity corrected that mismatch without weakening the
negative assertion. The next two-control run passed. Strict Clippy then refused
four equivalent-expression lints; those were corrected without lint suppression.
The complete workspace formatting/strict-Clippy and both controls subsequently
passed together (`validation-2946cc2a5b674a33afae638bc49cbea1.json`), exit0,
both EOFs, no refusal and absent owned cgroup. Actual input copies are limited
to256MiB retained aggregate; copying plus two readbacks is not a512MiB gross-IO cap.

The fresh frozen-current five-group PG profile also passed
(`validation-9999f12b88c94f6987e84dcbe6d409cf.json`): pg-storage, pg-lifecycle,
pg-drain-history, pg-business-audit and pg-recovery-economics, with all live
prerequisites required, the original inventory and smoke-soak owners, and the
same retained cluster/loopback endpoint. Actual exit0 after766.16seconds,
both EOFs, no timer/floor stop and absent owned compiler cgroup were observed;
pre/post source bindings matched. Repeated support tests are not additional
live controls. Complete raw-output and cleanup review remains separate from
genuine35-role recurring relocation, complete required, final-head CI and
release acceptance. The twenty readiness boxes are not checked by these
scoped successes alone.

The disposable PG runner now refuses unknown Docker cleanup state rather than
treating failed inspect as absence. All 43 actual fake-Docker cleanup controls
passed; the corrected runner also passed the real schema/conformance target
with one live case and 77 shared support controls
(`validation-0a2fb454201e4c218fec58f73d7f523b.json`). Complete pipe EOF, exit 0,
owned cgroup release and absence of its exact labelled resources were checked.
The new controls run through the existing cheap gate-contract owner; its
ordered dispatch, omission/duplication and failure-propagation tests passed.
This is additive cleanup evidence, not another full PG profile or release PASS.

All four bounded SQLite Docker ENOSPC cases also passed
(`validation-9f49f698c13548bfbff2d0162b15635b.json`): the original two inline
controls and two new positive referenced-blob controls. The latter preserve two
independently defined objects with 65,537-byte data payloads and complete
canonical bodies larger than 64 KiB, all twelve SQL tables and all four
portable collections through the definite/indeterminate fault outcomes,
same-file reopen, one authorized retry and receipt-first replay. The completed
runner exited 0 with both pipe EOFs; successful exact-owner Docker listings
confirmed its containers, volumes and imported image absent. This is actual
bounded process/filesystem-fault evidence, not cross-file atomicity, host power
failure, custody or full M3 completion. No open group is checked by counts alone.

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
source commits below. At that snapshot the inherited private Cargo home was
unavailable for an unknown reason. Local reconstruction was not admitted:
exact local inputs were incomplete and its replacement protocol was unqualified.
The 2026-10-10 direct request now authorizes official acquire-only missing locked
inputs. That inert census had 41 missing archives, 36 missing sparse
name files and three missing version records; no acquisition or quarantine had
been created at that point. The first source-author attempt hit a restricted reference-read denial;
that read scope was corrected. In the corrected Claude Code attempt on
2026-10-11, the author reported a safety classifier stopping code generation
before any source was produced. This is not an observed download, Cargo, disk
or credential failure, or a demonstrated evidence/IO-cap impossibility. The
historical stopped author is not resumed. The later direct human instruction
assigns ordinary official acquire-only implementation to the root; a real
platform denial must still stop, not be bypassed. The new root-authored candidate
had current binding, sealed execution and full readback/release checks, but its
complete different review, fresh admission and actual acquisition were then pending.
Global caches and the retained M4 target must not be substituted or repopulated.

Different complete SOURCE_ONLY_APPROVE now covers exact `39640e32`: all 67
changed bodies and their relevant ordinary current-route contracts, including
the genuine fee/bond/slash/evidence and receipt/output defining-owner closure.
Root independently rebound all 1,045 actual tracked bodies to that clean HEAD.
This resolves source review for that snapshot only; no new build, test, input
acquisition, runtime admission or TODO-group completion follows.
The later DR-0224 collector/source-documentation delta is separate from that
approval; it remains uncompiled, unformatted and unexecuted.

Next: finish current corrected core/SDK/operator and whole-required acceptance,
then the remaining complete PG protocol/soak profile, independent integration,
fresh thirteen-target A/B and final-head hosted gates. Root-verified private
dependency preparation now permits the local tests described above under the
new direct human instruction; it is not old packet/ONE or release acceptance.
Old metadata/scoped helpers must not run with
substituted source or target bindings. M4's age edge expands shared
`futures-util` features used by PostgreSQL: the documented PG dependency
acceptance requirement remains
unresolved, even though Native+SQLite development may continue. Docker-only
local PG qualification is now authorized; no selected-profile check is waived.
Keep the accepted
[DR-0221](docs/architecture/decisions/0221-encrypted-recovery-closure.md)
transport/restore requirements intact; DR-0224 adds the thirteenth target to
the same fresh A/B owner without dropping any original target.
Rustls advisories, optional PG acceptance, production PKI/custody and M3's
actual memory/noswap environment qualification remain open. Reconcile exact heads
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
  Local `61de1226` gives canonical receipt-record binding one pure envelope
  owner, consumed by core queries and wire queries without changing their
  outer-ID precedence or caller-local error projection. SDK requested-ID
  validation remains after wire binding to the returned frame. Eleven source
  controls retain full record/response bytes and refusal priority. Different
  exact-slice source review passed; formatting, compilation and execution
  remain unperformed. This does not close R1 or qualify durable receipts.
  The local submission-signature slice gives the existing E009 encoding and
  two message-family constants one execution owner. SDK preparation calls it
  directly; core retains its typed wrapper and existing public paths.
  Seven source controls independently retain complete envelope/frame/signed
  bytes, exact/+1 canonical bounds, nonzero-ID and caller-error priority.
  Formatting, compilation and execution remain unperformed. Raw structural
  encoding is not admission, full SDK decoupling, custody or R1 completion.
  The validator-set owner now publicly defines the existing generic 10,000
  validator ceiling. Four durable record-codec consumers use it directly;
  two copied constants are removed without changing bytes or error priority.
  The separate active-committee ceiling remains 256. Eight new literal-bound
  source controls are unexecuted; this does not close R1 or prove live admission.
  Consensus now publicly owns its unchanged strict certificate/proposal decoder
  byte caps; wire consumes those constants instead of two copied literals.
  Candidate/framing/status bounds, bytes and refusal order remain unchanged.
  Six appended literal-bound source controls are unexecuted, outside the original
  41 selectors. Decoder admission is not valid-capacity, encoder, quorum or
  custody qualification; R1 remains open with all execution/release gates intact.
  Frozen-frontier vote/page/entry ceilings now have one consensus owner;
  wire aliases preserve their public names/types and existing 8 KiB/512 KiB/128
  values. A compile-time guard precedes the entry-limit narrowing to u16;
  request/framing allowances and all refusal order remain unchanged. Nine
  literal-bound source controls include a complete 129-entry frame and separate
  limit-only versus joint-invalid refusals. They remain unformatted, uncompiled
  and unexecuted, outside the original 41. Structural pages and opaque envelopes
  do not qualify signed capacity, custody, persistence or R1 completion.
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
  Local `00d72db4` shares direct Atomic/Durable transaction containment and
  represented-byte refusal in the existing private transaction owner. Each
  constructor retains its distinct mutation-set admission and empty rules;
  containment still precedes the strict 64 MiB bound. Four source controls
  retain order/accounting, exact-boundary acceptance, +1 refusal and earlier
  Durable count/duplicate errors. Different exact-slice source review passed;
  formatting, compilation and execution remain unperformed. Backend CAS,
  commit outcomes and all release prerequisites are unchanged; R2 stays open.
- [ ] **R3 — attributable tests and economical CI:** share bounded signed-input
  setup, not the implementation-derived oracle; separate pure/store/HTTP/CLI
  owners. Remove equivalent duplicate work only with exact-input coverage proof
  and measured benefit. DR-0202's private recurrence observations are merged.
  Keep every actual recurrence, unlock delay, restart/fence/fault and selected-PG
  case. The release fixture runs once in the existing cheap contract owner;
  no new heavy CI lane, path-filter skip or unproved ancestor reuse is introduced.
  The existing local-datagram collector control at local `bfb7383a` now checks
  two complete ordered snapshots and independent literal full output bytes.
  Exactly one final flush is required: even after every byte is accepted, a
  refused flush remains `Output`, not a successful export. Different exact-slice
  source review passed; formatting, compilation and execution remain unperformed.
  Shared compiled-child capture now requires successful complete pipe reads and
  both reader joins before returning `Output`. Startup requires one complete
  LF-terminated line, preserving the original read error and exact bytes without
  waiting for host EOF. All ten startup calls now pass a cap derived before
  spawning from the actual fixture chain: 428 framing/field bytes plus its
  UTF-8 bytes, including LF. The shared reader probes at most cap-plus-one
  physical bytes; encountered read/UTF-8 errors retain priority. Four new
  process-free controls supplement the existing two, including independent
  maximum producer formats. All six are outside the original 41 selected
  controls and remain unexecuted. No heap, whole-EOF or all-path cleanup claim
  follows; every real CLI, restart/fence/fault and release gate remains unchanged.
- [ ] **R4 — audit and launch seams:** bind exact source/build/configuration,
  exposed-family authorization, signer/store capabilities and executable
  startup/stop/restart/recovery evidence. DR-0204–0207 relay/native/SDK evidence
  is merged; DR-0212 recovery and DR-0213 release evidence extend the actual
  audit handoff. TLS identity is not protocol authority, local workerd is not
  provider rollout, and an evidence manifest grants no serving/signing authority.
  The native release file holder now places its initial attachment stat inside
  the existing close-on-failure boundary. Three source controls require real
  descriptor closure before fixture recovery: success, sixteen first-stat
  failures and comparator second-attachment failure. They remain unexecuted.
  Original error identity is conditional on successful close; close-failure
  precedence, all thirteen targets and release prerequisites remain unchanged.
  This ordinary resource-ownership correction does not complete R4.

Continue a useful accepted slice rather than reopening completed Delivery 3 or
requiring unrelated facade extraction before functionality. Concurrent writers
need independent owners/worktrees; shared compiler and source ownership stay explicit.

## Delivery 4: first public testnet

Track the existing groups separately as SOURCE, VERIFY and LAUNCH. SOURCE
means implemented code and controls, not verified code completion. CODE
completion still requires the original applicable exact-head runtime, crypto,
atomicity, security, fault and independent acceptance gates. LAUNCH is
human-owned: real operators/key/backup ceremonies, actual genesis/economic
values, production SLO/topology/resources and public activation. Disposable
keys and parameters can verify code without choosing production values. Keep
combined-readiness checkboxes open while any applicable axis is incomplete.

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

## Mainnet code/verification and launch readiness

Every group remains open until original evidence is complete or an accepted
human decision explicitly supersedes it. This consolidates S4/S5, Phase 15–17
and cross-phase criteria; it does not shorten them.

- [ ] **M1 — independent release review:** final threat/delta audits of code and
  deployment, generic contracts, economics, handoff/activation, ingress, storage
  and signing; remediate significant findings, independently verify fixes and
  retain residual-risk decisions. Updating the proposed SECURITY policy still
  needs human approval; current SECURITY.md has not been changed.
  [DR-0227](docs/architecture/decisions/0227-fresh-ordered-slash-evidence-admission.md)
  has independently reviewed source implementation for fresh causal BondSlash:
  committed evidence identity, typed digest, both object preimages, pinned
  protocol, exact fenced committee and both signatures precede new signing.
  Twelve focused source controls cover real Evidence producers, normal slash,
  prefix completion, replay/recovery and deciding-read conflicts. They remain
  uncompiled/unexecuted, not completed security-fix or release verification.
  Historical behavior is retained; already-certified invalid locked history
  is not repaired by this fresh-only gate.
  Normal local `dd0928bb` implements the fresh registered-owner Withdraw gate
  under [DR-0228](docs/architecture/decisions/0228-fresh-withdraw-release-target-admission.md):
  the exact full committed custody reference and installed resource's current
  call context, code, instance and transfer entrypoint precede new leader/vote
  signing. The resource is read at the committed bond's historical policy
  context; deciding revisions join the existing admission CAS. Existing typed
  refusal order, prefix completion and retained/historical replay remain.
  One independent candidate review found that the original reference-only
  gate still admitted a different entrypoint. The parent confirmed that route
  and revised the source; independent approval of that revised delta is not
  claimed. Genuine recurring SQLite source controls cover both signing paths,
  wrong full references, a re-signed split target, deciding-read races and replay.
  They remain uncompiled/unexecuted, not verified remediation.
  Normal local `713edc5b` changes only the consensus Ed25519 adapter's malformed
  signature-length classification to `Ok(false)` after the unchanged key check.
  Its different five-path source review passed; three real-signature aggregator
  source controls retain quorum/order/certificate-byte expectations. Formatting,
  compilation and execution have not run. The source amendment is in DR-0209;
  neither local commit closes a finding or supplies whole-current approval.
  The final independent audit is incomplete, and required owning/full, final-
  head CI and release checks remain open. M1 and Delivery 4 stay open; these
  local source changes do not authorize public activation.
- [ ] **M2 — protected signing:** actual custody, operator/authority separation,
  exposure controls, exact operation-specific content verification, refusal/
  failure, recovery/rotation/revocation. DR-0208 removes only Ledger-specific
  product completion. DR-0211's prepared SDK/CLI owners keep immutable identity/
  frame/trust inputs and independently verify provider output without fallback;
  DR-0215 covers actual ordered returned signatures and retained rereads. Neither
  implements protected key storage. Proposed DR-0214 is independently reviewed
  but leaves local-OS, separate-host and hardware threat models unselected.
  The separately reviewed backend and trusted content-review surface remain code
  work; plaintext seeds and opaque generic bytes do not qualify. Actual key,
  administrator and recovery roles/ceremonies are LAUNCH decisions, not a
  prerequisite to implementing and verifying parameterized code with disposable keys.
- [ ] **M3 — selected-profile durability:** atomic object/state/nonce/receipt/
  outbox, bounded indexed delivery, full-read revision/ABA, restart, fencing and
  ambiguity reconciliation. DR-0210's real SQLite process/lock tests are narrower
  than host/power/storage faults, ENOSPC/resource exhaustion, real writer failover
  and TLS failure/rotation. Qualify those actual selected-profile boundaries.
  An additional nonignored Linux source fixture follows an acknowledged paid
  CLI transfer with owned-child SIGKILL/reap of all four serving hosts and
  same-path TLS restart at the next fence. It checks pre-held stale capabilities,
  complete logical business snapshots and referenced blobs, and exact saved replay
  without a second business mutation. It is uncompiled/unexecuted; parent SQLite
  handles remain open and the outbox oracle is guarded empty. This is not
  interrupted COMMIT, all-connections-lost, power, disk-failure, ENOSPC or failover
  qualification.
  Local `3e0f066e` adds three real-file SQLite source controls for the actual
  signed, request-scoped Native indexed-outbox consumer: confirmed claim/ACK
  reply-loss reconciliation, unresolved landed claim without sending, and
  unresolved landed ACK after one exact send. Independent public-codec oracles
  pin state, nonce, receipt/result and outbound bytes; full four-collection
  snapshots retain unrelated rows. The object/reference collections are empty,
  not positive object/blob coverage. Same-request/context probes require live
  lease ownership and unchanged reconciliation tokens, with post-setup sequence
  deltas +3/+2/+3 and one application invocation, not one total SQL COMMIT.
  Different exact-slice source review passed; all three controls remain
  UNFORMATTED, UNCOMPILED and UNEXECUTED, outside the original 41 selectors.
  Synthetic reply loss follows confirmed store operations, not failed COMMIT,
  physical I/O, crash/power, custody or M3 completion. See DR-0210's dated addendum.
  The bounded non-faulting private-namespace capability attempt ended
  ENVIRONMENT_UNAVAILABLE/78: required unprivileged tmpfs noswap was unsupported.
  No SQLite/ENOSPC filler or privilege fallback ran. Retained actual failure/
  refusal history remains separate. Docker-only bounded disk-full/forced-stop
  experiments are now authorized; effective noswap, resource containment and
  actual SQLite fault/recovery results still require independent qualification.
  No host-wide resource change or privileged fallback follows from that authority.
  The disposable Docker ENV probes now observed actual errno28 inside an 8MiB
  noswap allocation and PostgreSQL18.6 retaining the fixed committed fixture
  after SIGKILL/restart of the same container, with a continuous keeper of its
  512MiB noswap allocation. Exact-owned containers and volumes were removed and
  independently observed absent. These are environment-only results, not the
  Rust durability controls, complete selected PG acceptance or M3 completion.
  Two ignored Linux SQLite ENOSPC source controls now require an effective
  64MiB noswap Docker allocation before filling it. They distinguish definite
  pre-COMMIT refusal from the literal COMMIT-error path, compare all twelve SQL
  tables and four portable collections, and reconcile the original/reopened
  baseline before one explicit retry and unchanged receipt-first replay.
  Positive inline objects are covered; referenced blobs remain guarded empty.
  Different exact-two-path source review passed. Both controls remain
  UNFORMATTED, UNCOMPILED and UNEXECUTED, outside the original 41 selectors;
  Docker ENV capability evidence is not their execution or M3 completion.
  Two additional nonignored Native HTTP source controls use fresh real SQLite
  fixtures for missing and digest-mismatched supplied blob reads. Literal bounded
  HTTP 503/500 responses, full four-collection snapshots/tokens and referenced
  blob closure, original head/v1/body, nonce zero, no fresh receipt, one selected
  read and no outbound messages are required. Faults affect only the private
  supplied getter, not the original backing bytes or physical SQLite I/O.
  They remain UNFORMATTED, UNCOMPILED and UNEXECUTED, outside the original 41
  selectors; no full twelve-table, zero-COMMIT, physical fault or M3 completion
  follows. See DR-0094's 2026-10-12 addendum.
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
  thirteen-target A/B and final-head hosted acceptance are still required. The
  unconditional age edge expands `futures-util` features shared with PostgreSQL,
  so final dependency acceptance also needs the documented selected-PG evidence
  in the newly authorized Docker-only local profile; unchanged PG versions do
  not waive that obligation. Environment preparation is not PG acceptance.
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
  [DR-0224](docs/architecture/decisions/0224-bounded-local-observation-collector.md)
  adds a bounded foreground Linux receiver and shared strict live-record decoder.
  It retains the caller-owned mode-0700 directory chain, uses one setup/receive
  deadline, limits count/record size/attempts, and prints only a complete typed
  collection after descriptor closure. Existing or own closed socket leaves are
  never automatically removed. Actual-loop late-success, malformed-prefix and
  interruption controls are authored but unexecuted, as are the private-socket
  controls. Neither static review nor this command qualifies delivery, peer
  attribution, alerts/SLOs, production operations or an M5 completion.
  Normal local `12152cd7` extends the existing nonignored direct-TLS SQLite
  fixture with a first-boot-only Linux collector, one non-stopping SIGUSR1 request,
  strict complete output/real pipe EOF checks and positive admission/dispatch
  expectations. It rechecks live-host/context preservation before retaining all
  original transaction/replay/fencing/rotation/stop assertions. The different
  exact-two-test-path SOURCE approval is static only: formatting, compilation and
  execution have not run. No selector, CI lane, dependency or TODO completion is
  added; later original-host boots and the other hosts remain default-off.
  Normal local `614a99d0` reuses the same private collector in the existing
  activated-successor and signerless-history TLS fixtures. Live collection
  repeats actual authenticated context/status bytes and whole protected state;
  history collection repeats the complete material oracle with the retired key
  absent across both restarts. Only history restart zero opts in. Each collector
  retains one 300,000 ms setup-through-completion deadline, and all existing
  selectors, ignored attributes and CI owners remain unchanged. Different
  exact-three-test-path SOURCE approval is static only; these controls are
  unformatted, uncompiled and unexecuted, with no whole-source or M5 completion.
  The M5 lock delta only adds direct edges to already locked versions; no PG
  dependency/version changes occur. Locked Rustls 0.23.43 remains affected by
  RUSTSEC-2026-0285 (patched in >=0.23.45). The shared upgrade remains unqualified;
  Docker-only local PG acceptance is now authorized but unperformed. No clearance
  or old-lock exposure recommendation follows. Production PKI, caller authorization,
  protected custody and revocation remain open.
  Normal local `0c256c4f` under
  [DR-0226](docs/architecture/decisions/0226-native-certified-publication-collector.md)
  aligns the default-off Native collector with the existing 32 MiB certified
  publication-retain and canonical drain-import POST bounds in original/live
  serving. Other methods, raw paths and default/local-route limits are unchanged.
  A different exact-eight-path source review passed; selector and bounded TCP
  regression controls are authored but unformatted, uncompiled and unexecuted.
  Probe dispatch is not valid publication retention or M5 completion; required
  owning/full, selected-PG, CI and release qualification remain open.
- [ ] **M6 — economics/genesis approval:** real sets, independent roles, voting
  powers, bond/fee assets/schedules, treasury/supply/distribution, security and
  unbonding parameters, governance authorities, ceremony and supply invariants.
  Never invent production values or infer power from bonds to make examples launchable.
  The parameterized author/inspector, generic installation and checked supply
  code exist and their bounded owning controls executed successfully in the
  required run above before its later M4 failure. Final-source integrated and
  security qualification remains distinct. Actual economic values, independent
  operators and genesis/key ceremonies are human-owned LAUNCH-deferred, not
  missing-code prerequisites. This combined readiness checkbox stays open;
  twenty open readiness groups do not mean twenty unimplemented code tasks.
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
  DR-0224 then adds `native_observations` as the thirteenth, retaining all twelve
  targets in that same owner. Current qualification requires two fresh thirteen-
  target builds and full comparisons; old eleven-/twelve-target output is not
  acceptance of the new receiver, and its cheap controls remain unexecuted.
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

### Code-scope and launch decisions

Protected-signing threat/backend and trusted content-review design, SECURITY
policy approval, supported-provider scope, advisory resolution and applicable
complete local PG verification remain code/verification work or decisions.
Docker-only local PG and bounded isolated disk-full/forced-stop experiments are
authorized; their real environment and test evidence remain outstanding.

Real key/backup/recovery/operator roles and ceremonies, off-host retention,
production workload/SLO/topology, actual genesis/economic values, any public
protocol-v3 exception and eventual public launch are human-owned LAUNCH work.
They do not block implementing and verifying parameterized code with disposable
keys/values. Fixture values neither select production values nor complete an
operational rehearsal. Preserve the original noswap refusal as a failure; a new
Docker capability result must be attributable and cannot supply a historical pass.

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

- Local SQLite, Docker-only local PostgreSQL, loopback and disposable development
  keys. Bounded isolated Docker disk-full/forced-stop experiments are authorized.
  No host-wide disk filling/settings changes, foreign workload interference,
  production D1/Worker writes, cloud resources, public listeners, paid-plan
  changes, non-Docker PG service or public launch are authorized.
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
