# Functional handoff closure

Date: 2026-10-02 (Asia/Singapore)

Status: **Proposed** refinement of the [handoff contracts](architecture-contracts.md#handoff-contracts),
recorded in [DR-0186](decisions/0186-functional-handoff-closure.md).
This is not an accepted wire/storage contract, executable authority or deployment
approval. Work status remains only in [TODO.md](../../TODO.md).

[DR-0187](decisions/0187-first-epoch-ordered-seal.md) and
[ordered Seal](ordered-seal.md) supersede this proposal's first-epoch Seal
alternatives: selected-branch verification with existing retained material,
exact private acceptance terminal and hard-stop outgoing signatures/writes.
The separate activation and recurring-predecessor proposals below are not
accepted by that narrower decision.

## Implemented constraints and source evidence

- [DR-0178](decisions/0178-conditional-readiness-wire-and-retention.md) uses
  separately verified inactive staging for retained A/B/C and incoming E.
  `VerifiedImportPlan::observe_complete` compares the complete target and bodies;
  completion/readiness is not serving authority.
- [Ordered admission](../../crates/node-core/src/ordered_economics/engine.rs)
  refuses every fresh candidate after accepted DrainSet. Its existing event
  completion retains committed proofs with original outcomes and real effects.
- [Cut terminal verification](../../crates/node-core/src/business_reconstruction/cut/derive.rs)
  proves one fixed empty three-chain, not the complete live high/locked suffix.
  [Consensus](../../crates/consensus/src/lib.rs) applies normal ancestry/lock rules;
  its bounded cache pruning does not promise all future Seal traversal material.
- [Candidate intent](../../crates/node-core/src/ordered_economics/candidate.rs)
  permits 512 KiB; [readiness certificates](../../crates/consensus/src/readiness.rs)
  permit 1 MiB. [Cut transfer](../../crates/node-core/src/business_reconstruction/cut.rs)
  bounds descriptors, pages and chunks, not total history.
- [Legacy transition voting](../../crates/consensus/src/epoch_transition.rs)
  `cast_vote` signs without durable retention. [Core transition](../../crates/node-core/src/epoch_transition.rs)
  refuses fresh logical-profile activation; historical preimages remain defined.
- [Exact-key CAS](../../crates/runtime/src/lib.rs) does not assert an entire
  portable snapshot sequence. [Import completion](../../crates/runtime-sql-durable/src/engine/inactive_import.rs)
  already checks its target token inside the storage transaction.
- [Shared SQL ordinary completion](../../crates/runtime-sql-durable/src/engine.rs)
  rejects import-origin mutation. No existing guard may be weakened merely
  because a completed marker or public certificate exists.

These are dependency gaps, not evidence of an exploit in supported profiles.

## Actual completion and exposure owners

This bounded source map identifies consumers of the proposed closure. It is
not an exhaustive host/HTTP audit or a claim that the closure already exists.

| Actual owner | Existing boundary | Future closure obligation |
| --- | --- | --- |
| `commit_durable` and `commit_invocation` in [memory](../../crates/runtime/src/lib.rs) and [shared SQL](../../crates/runtime-sql-durable/src/engine.rs) | Distinct state-only and structured receipt/object ports each recheck ordinary lifecycle under the lock/transaction, independently of prior core reads | Both ports must reject sealed outgoing business; successor effects need narrow proof-backed completion, not globally relaxed ordinary checks |
| [Core mutation fences](../../crates/node-core/src/mutation_fence.rs) and [original reconciliation](../../crates/node-core/src/durable_reconciliation.rs) | Namespace origin, current epoch, precise object/nonce locks and original completed receipts are different deciding evidence | Preserve receipt-first exact replay; join fresh phase/serving observations to the real completion rather than replace them with a read-time Boolean |
| [FastVote prepare](../../crates/node-core/src/fast_path.rs) and [availability ACK retention](../../crates/node-core/src/fast_path/publication.rs) | Prepare checks epoch/set even on retained-vote replay; ACK retention checks origin/epoch/set before retained replay, then Freeze only before a new ACK | Fresh serving/exposure checks must cover cached live signatures too; a prior signature is not current permission |
| [Ordered engine](../../crates/node-core/src/ordered_economics/engine.rs) and [drain progression](../../crates/node-core/src/ordered_economics/drain_union.rs) | Real proposal/vote/Tick, certificate/observer and drain progress own persisted safety and typed completions | Classify legal empty/inherited proof progress separately from business; the pure consensus engine supplies no storage/phase authority |
| [Genesis install](../../crates/node-core/src/genesis.rs) and [legacy epoch transition](../../crates/node-core/src/epoch_transition.rs) | Bootstrap verifies signed manifests, context and installed history; logical-profile transition currently refuses | Neither initialization nor legacy activation may reset a sealed namespace or substitute for authenticated successor installation |
| [Inactive import](../../crates/runtime-sql-durable/src/engine/inactive_import.rs) and [protected readiness](../../crates/runtime-sql-durable/src/engine/inactive_import/conditional_readiness.rs) | Separate token/binding/progress-aware port families; readiness requires CompleteInactive | Activation needs its own actual completion and must disable inappropriate fresh readiness without erasing import history |
| `IndexedOutboxRepository` in [runtime](../../crates/runtime/src/lib.rs) and [shared SQL](../../crates/runtime-sql-durable/src/engine.rs) | Claim-by-request, claim-due and acknowledge mutate delivery leases/cursors under physical authority, separately from ordinary business commits | Specify legal retained delivery after retirement; it cannot create business effects, new signed work or serving authority |
| [Queries](../../crates/node-core/src/query.rs) and [retained bundle loading](../../crates/node-core/src/fast_path/drain_publication.rs) | Read-only historical inspection and proof reconstruction do not create an ACK; bundle loading is not the separate `retain_drain_publication` writer | Keep historical inspection legal; trace the actual host exposure wrapper before labeling a result live |

`StructuredOutboxExclusionGuard` inspects inventory; it is not an outbox write
authorization guard. The three indexed delivery methods do not apply the
ordinary-business lifecycle predicate in either memory or shared SQL. Their
separate post-Seal policy therefore must be specified, not inferred from the
two business commit ports. This is a design dependency, not a demonstrated
current exploit or permission to blanket-block historical reads.

## Proposed staged namespace and crash ordering

Retain DR-0178 staging for all successor members. Do not convert import origin
to Ordinary or overwrite outgoing consensus. A separately verified serving
record would authorize the successor; immutable import binding/progress remains
installation history, never fresh permission.

Keep permanent origin/import-installation state separate from the outgoing
Seal barrier and proof-backed successor authorization. Do not overload
CompleteInactive to mean retired, or pretend an imported active target has
ordinary origin. A new origin/phase encoding still needs its own closed schema
review; this proposal does not allocate one.

The proposed outgoing barrier is initialized by its protected metadata owner;
an unsealed observation proves only absence of committed Seal, not membership
or active serving. Missing mandatory barrier metadata must fail rather than
become an unsealed default. Accepted Seal changes that barrier atomically with
its actual ordered result; both ordinary business completion ports recheck it.
The accepted target never reopens through bootstrap, repair or host selection.

An imported successor uses a narrow, genuinely consumed serving completion.
Core derives its invocation-scoped warrant from authenticated predecessor/
activation proof and fresh installed observations. Storage rechecks those
deciding local observations and its own fence inside completion; it does not
choose protocol authority. Generic imported-origin commits remain forbidden.
No virtual store reports ordinary origin, synthetic commit succeeds, public
trusted flag constructs permission or metadata-prefix exemption replaces proof.

Proposed order: confirm outgoing Seal; retain outgoing transition signature;
form/verify transition quorum; confirm target-local activation; expose serving.
Each step uses its own current domain/fence/deadline. Indeterminate acknowledgement
exposes no new authority until fresh exact retained reconciliation.

No cross-namespace retirement transaction is needed **provided** the outgoing
Seal completion atomically fixes the target and closes all old business work,
and every fresh completion fences that phase. Freeze/DrainSet closure remains
mandatory beforehand. Stale hosts cannot reopen it by selecting an old epoch.
After Seal allow only narrowly specified empty/proof-completion and inherited
control recovery; preserve old locks, QCs and unique signing history. Decide
separately which exact retained outbox deliveries remain legal. Lease/cursor
updates cannot reopen business, queue fresh protocol work or bypass the final
snapshot-sequence check; they also mutate the covered local sequence.

Original completed request replay stays receipt-first, exact and execution-free
under the current local fence. Cached live votes/ACKs instead require fresh
phase/serving authorization. Historical signature verification remains legal.
Fresh readiness must not remain accidentally enabled after target activation.

Competing uncommitted Seal proposals never create a singleton target lock.
Only normal committed acceptance fixes it. An inherited competitor may commit
later: its precise deterministic no-effect result, receipt/provenance treatment
and legal post-Seal control progression remain pre-code decisions, not an
assumed `AlreadySealed` tag or permission to discard its original outcome.

## Proposed semantic target and retained companion closure

The semantic target binds chain/protocol/outgoing epoch/domain, original root
and verified predecessor, semantic cut, exact pre-Seal prefix anchor, committed
DrainSet, checked adjacent successor epoch/set and complete trusted schedule.
Reuse the cut's business/artifact roots and generation floor rather than add
a competing definition. Local tokens/fences and exact package/proof variants
are not semantic agreement. Local high/locked observations are voting checks,
not fields that force honest replicas to share identical local state.

Use a small ordered Seal reference plus a bounded companion manifest. Retain
the exact successor-set/readiness certificate, independently verifying saved
cut package and required ancestry material as immutable components before
exposing a vote. The event atomically retains their references with its signing
identity/progress. A hash alone proves neither availability nor local validity.
Failed reference commits may leave unreachable immutable content, not authority.

Reuse existing cut page/chunk mechanics and actual verifying carriers; never
restore normalized comparison subjects as certificates or source physical rows.
Exact companion variants can change ordered candidate bytes without changing
the semantic target. Preserve complete original receipts/code/body provenance.
Seal's own proof/receipt is added afterward outside the pre-Seal cut and the
manifest it commits. Final reference/manifest schemas and limits require review;
this proposal allocates no identifiers or new numeric limits.

## Proposed phase-aware suffix verification and retention

Process justified committed progress using the existing engine before fresh
Seal voting; use the resulting control phase and reobserve changed state.
For high QC, locked QC and proposed justification, verify complete authenticated
ancestry to the exact selected pre-Seal anchor. A path reaching an earlier
height must prove membership in that verified prefix, not stop on height alone.
Before Seal, post-anchor progress is proof-checked empty progress with unchanged
business roots/floor. Later phase-specific Seal controls need their own explicit
classification. Different business/control cuts need another verified binding.

Resolve inherited business through normal recovery/refusal and reservation
cleanup before deriving the cut. Missing/corrupt material stops for catch-up;
it is not a healthy refusal or a Boolean claim that a suffix is empty.
Normal HotStuff safety/view rules continue to apply. No timeout unlock/reset.

Retain exact authenticated headers, justifications and necessary candidates
before pruning can remove them. Extend the existing event archive, not the
consensus algorithm. Immutable component bodies may be staged before the CAS;
references and corresponding progress must land together. No silent archive
backfill, deletion repair or unknown-parent inference is authorized.

Bound every walk step and retained component. Bind continuation to exact anchor,
QC roots and observed consensus revision; changed observations invalidate it.
Partial traversal grants no signing authority. Total historical verification
may remain linear. Final traversal rules must cover legally superseded locks
without stranding normal recovery or accepting an unresolved business branch.

## Proposed atomic Seal and activation completion

One token-covered Seal completion in existing memory/shared-SQL owners should
recheck the freshly verified snapshot namespace/domain/fence/mutation sequence
**inside** the same transaction as assembled ordered progress, Seal phase and
original receipt. Exact deciding key/object observations remain required.
Key CAS alone cannot certify unchanged inventory or exclude phantom rows.
This is a concrete consumer of snapshot continuity, not a universal transaction
framework, metadata-only business bypass or fake successful preparation.

Target activation independently rechecks its fresh full-plan/body verification,
immutable binding, completed progress, token, local fence/deadline and expected
serving observation atomically. Immutable bodies are outside the SQL token and
must be verified through their owning bounded immutable-content contract.
Install authenticated successor policies/provenance/floor, epoch-scoped safety
anchor and serving authorization together; never copy source fences/locks.
Exact retry verifies retained identity without resetting anything. Missing,
tombstoned or conflicting mandatory records fail closed, without repair.

Core invocation phase observations do not replace backend lifecycle enforcement.
Every generic ordinary transaction entry point must refuse a sealed outgoing
namespace, including outstanding handles. Only narrowly proof-backed ordered
progress/transition completion may retain allowed post-Seal metadata, with
reviewed closed effects/receipt sections. No prefix exemption, maintenance flag
or unrestricted old writer may bypass closure. Target serving completion must
likewise preserve import origin and use the target's own fence.

Origin stays permanent. Serving checks must verify committed proof and fresh
installed observations; a stored active tag is insufficient. The narrow runtime
backstop must reject unauthorized imported-origin writes, not globally relax
`is_ordinary()`. The activation transaction does not make two namespaces atomic.

## Proposed transition, successor and recurring authority

Persist one outgoing signer/epoch-transition slot after committed Seal. It binds
that Seal and exact activation target. Initial signing requires positively
established virgin protected history, initialized by its owning transaction
and bound to the committed Seal; an absent slot alone is not that evidence.
Exact retry returns verified retained bytes without signing, conflicts/tombstones
refuse, and ambiguity exposes nothing before fresh landed reconciliation.
Verify the produced signature under the registered outgoing key before retention.
Unlike readiness, unknown absence is not permission to recreate unique history.

Review new versioned schemas, distinct signing purpose and state-key families
before implementation. Preserve historical `0x6428/v1`, transition frames and
signature rules; old certificates never fall back into new handoff mutation.
All new signatures retain explicit chain/protocol/outgoing-epoch boundaries.

Recompute the complete schedule commitment from independently trusted local
configuration at the outgoing epoch, and the successor-set digest at the
successor epoch. Original genesis does not authenticate arbitrary future local
schedule extensions. A peer's configuration or newer-epoch hint grants no trust.
Seal/activation must agree with readiness; future schedule changes need their
own authenticated authority rather than a silent resolver replacement.

Scope successor safety, leader/vote identity and applied-prefix keys by verified
epoch/predecessor. Preserve legacy chain-only rows and chain-wide original
request receipts. A fresh successor root is not a reset of outgoing safety.
Derive logical generations from verified predecessor floor/inputs, retain exact
historical economics/code authority, and distinguish old withdrawal-owner keys
from current consensus membership. Subsequent reconstruction replays each epoch,
then its authenticated activation, then the next; no genesis-only future producer.

## Callable feature boundaries and pre-code gates

The following are proposed functions with real consumers, not existing APIs:

| Proposed owner/function | Actual consumer and completion |
| --- | --- |
| Core `verify_seal_target` and writer-free `prepare_seal_ordered` | Existing ordered proposal/vote/observer paths and event assembler; no direct metadata-only live handler |
| Core `retain_handoff_transition_vote` | Outgoing post-Seal workflow; one real protected retention before exposure |
| Core `activate_verified_successor` and fresh `resolve_current_serving` | Dedicated target completion/reopen plus owned/ordered admission and cached live responses |
| Predecessor-aware reconstruction constructor | Subsequent cut/import/readiness; consumes authenticated activation history, not supplied rows/flags |

Before code, settle protected barrier/virgin-slot initialization, exact retained
delivery policy, competing Seal
results/phase tags, exact suffix/continuation rules, companion ownership/retention
limits, snapshot-covered completion shapes,
activation/provenance preimages and reviewed namespace/schema allocations. Prove
the proposed closure actually covers all fresh completion/exposure roots.
Do not ship unused ports, public permission constructors or a second engine.

Acceptance must include genuine real-SQLite staging/restart, both reply-loss
directions, stale fences/tokens, inventory races, missing/partial/variant proofs,
competing inherited Seals and unchanged old evidence. Then prove real recurring
A/B/C/D to A/B/C/E operation through D's genuine unlock epoch and retired-key
withdrawal; an unbond-delay=1 fixture cannot waive repetition.
Keep required DB-free gates and selected optional PG acceptance. This proposal
claims no PG import/activation, DO/provider activation, audit, Delivery 3, startup
or production completion. Ordinary CAS does not guarantee consistent whole-DB
rollback detection.
