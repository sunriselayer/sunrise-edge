# DR-0177: Conditional readiness and ordered Seal

Date: 2026-10-02 (Asia/Singapore)

Status: **Proposed** refinement of DR-0154 for independent design review.
The first implementation candidate is readiness only. This record grants no
code authority, wire/key allocation, schema migration or completion claim.
Current work and gates belong only in [TODO.md](../../../TODO.md).

## Context

[DR-0154](0154-complete-epoch-handoff.md) requires an eligible next quorum's
correctable conditional readiness before outgoing ordered Seal. Only the
post-Seal transition target is unique. [DR-0175](0175-first-epoch-preseal-business-cut.md)
defines complete first-epoch cut derivation; its fixed empty terminal three-chain
does not establish the live high/locked suffix. [DR-0176](0176-verified-inactive-business-import.md)
provides permanent inactive installation, not signing or serving authority.

A missing per-identity readiness cache does not prove virgin signing history.
Unlike unique ordered/transition votes, however, conditional readiness permits
multiple eligible subjects before Seal. Requiring a retry to reuse its creation
observation token would also reject legitimate retry after retention changes
the local sequence. Both distinctions need an explicit protected contract.

## Proposed readiness-only decision

Incoming E and retained A/B/C each use separate, freshly fully reverified
CompleteInactive staging. Accept duplicate state/body/replay cost rather than
adding an Ordinary-source signing exemption. Namespace selection, a completed
marker and a remote signature prove neither membership nor key ownership.
FreshImport/Importing and ordinary/live cached signatures remain guarded.

Core privately reconstructs the exact cut/raw plan and post-drain eligibility.
Require checked adjacent epoch, 1..256 unique registered members/keys, the
existing Ed25519-only activation scheme, positive weights and checked totals.
Require canonical key/signature lengths under the locally pinned profile.
Reuse existing structural and
bond/resource rules, not bond-selected power or an irrevocable Freeze advisory
set. Match the actual signer's identity/key/scheme before signing; verify the
signature under that registered key before any durable exposure.

The semantic subject binds genesis/outgoing authority, chain/protocol/domain,
semantic cut and exact adjacent-epoch next-set identity. Use a distinct readiness
signing purpose at the outgoing epoch. Exclude exact package/plan variants,
local tokens/fences and future Seal; equivalent valid proof subsets agree.
The closed signed payload binds the registered signer ID and scheme as well.
Local retention separately binds exact immutable import/package/plan/progress
and the retained record's creation observation. Corrected sets are nonexclusive; another
business/control cut needs another verified saved cut and fresh binding.

## Protected durability and retry

Retain one bounded typed record per full semantic identity and signer. Namespace
lifecycle, immutable binding, completed progress and store/schema checks remain
mandatory; missing target metadata never becomes fresh or active. Present
malformed/conflicting records and known tombstones refuse without repair.
Keep metadata outside business roots through its exact owner, not a prefix drop.
No reset/delete/pruning or tombstone-management operation is introduced.

Protected retention atomically checks CompleteInactive, exact binding/completed
progress, current fully verified target token, domain/fence/deadline and exact
slot observation. Retain and observe exact landed signed bytes before exposure.
Retry uses a new current verification token while preserving the present record's
immutable creation observation, returns
the retained signature without re-signing and never bypasses a stale token.
Ambiguous acknowledgement exposes nothing until exact fresh reconciliation.

An absent cache may be recreated only after full fresh proof, destination,
eligibility and actual-key verification. It means no cached record, not a virgin
key. Do not claim preservation of an unknown historical first observation.

## Alternative considered: whole signing ledger

A mandatory append-only ledger with global head/index walks was considered.
It adds no established readiness consensus invariant: deterministic Ed25519
recreates the same public vote, another freshly imported namespace may already
produce that vote, and certificates count the registered signer only once.
Corrected eligible subjects are also legal before Seal. A namespace-local
ledger cannot enforce global no-resign history. Therefore use per-identity
retention; an audit-history requirement would need separate justification.

Do not apply this reasoning to unique ordered votes or post-Seal transition
targets, whose signing history prevents contradictory authority.

Ordinary CAS/fencing does not detect a mutually consistent whole-database
rollback without an independent anchor. Disclose that limit rather than adding
external hardware/service assumptions. No reset/delete or generic maintenance
override is authorized.

## Bounds, subsequent authority and review gates

[The proposed contract](../conditional-readiness-seal.md) sets candidate bounds:
set 64 KiB; subject 16 KiB; vote 4 KiB; certificate 1 MiB and at most 256 votes;
at most one new signature/16 KiB record and one exact retained-slot read/CAS per
call. No global candidate cap, whole-ledger walk or whole-history public vector
is introduced. Full private reconstruction/destination comparison remains
linear; total legal history is not capped.

Readiness-only acceptance requires genuine more-than-128-row A/B/C/E SQLite
staging, actual Deposit E eligibility, proof variants/corrected sets, real keys,
mandatory-target and present-record corruption/tombstone negatives, absent-cache
recreation with identical public vote and no duplicate quorum power, restart/exact
retry, ambiguous retention, wrong key/scheme and stale token/fence refusal.

Keep the pre-Seal anchor fixed, admitting only proof-checked post-anchor empty
progress with unchanged business/floor. Phase-aware high/locked traversal,
candidate authentication and Seal companion ownership remain unresolved before
Seal code. Competing uncommitted Seal does not establish a singleton lock.
Seal uses normal ordered authority and separate proof companions, not a circular
cut root; activation/serving rollover is a subsequent reviewed capability.

Before readiness code, resolve exact closed schemas/preimages, retained-record
creation-observation bindings, token/slot CAS semantics and actual
key-bound adapter. Perform a canonical namespace sweep and independent vectors
only after design review. This Proposed record is not implementation approval.

PostgreSQL remains optional with actual selected acceptance for relevant changes
or claims. SQLite evidence is not PG import, DO deployment or network readiness.
Tech-lead review is not an independent security audit. No Delivery 3, activation,
startup, production/mainnet or deferred product gate is completed or waived.
