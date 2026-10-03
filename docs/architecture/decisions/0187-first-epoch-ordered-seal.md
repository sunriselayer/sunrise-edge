# DR-0187: First-epoch ordered Seal and permanent outgoing closure

Date: 2026-10-03 (Asia/Singapore)

Status: Accepted exact design contract after read-only Opus review.
The review approved these semantics, not an unreviewed implementation or deployment.
This supersedes the Seal-only alternatives in
[DR-0186](0186-functional-handoff-closure.md), not its separate successor
activation and recurring reconstruction requirements. Validation and progress
belong only in [TODO.md](../../../TODO.md).

## Decision

Use the existing causal three-chain to commit a small Seal reference after
genuine complete drain and weighted successor readiness. Commit the exact
original ordered outcome together with a permanent storage-owned barrier.
After accepted Seal, the outgoing epoch creates or exposes no new or cached
live signature and performs no ordinary write. Historical reads and completed
original receipt replay remain legal. A successor uses its separate verified
inactive target; this decision provides no activation producer.

The detailed closed contract is [ordered Seal](../ordered-seal.md).
It separates semantic target, immutable proof transport, fresh verification,
actual completion and permanent storage origin. No new consensus engine,
maintenance flag, provider assumption or proposal-time target lock is added.

## Why hard-stop rather than another post-Seal control state machine

In the existing profile candidates occur only at heights congruent to one
modulo three. Let accepted Seal be at h. A later candidate is at least h+3.
A vote extending Seal at height h+3 first observes its justification at h+2;
with complete known ancestry, that QC commits h. Every honest signer must
durably complete that justified prefix before any signature exposure, then
observe the barrier and stop. Thus an outgoing quorum cannot certify height
h+3 or higher after Seal under the existing HotStuff safety assumptions.
Competing forks remain subject to the existing lock and commit safety rules;
superseded local locks are not erased or made another agreement target.

This argument depends on implementation, not height arithmetic alone: exact
candidate availability, real prefix application, original completion,
no exposure on indeterminate writes, and guards before retained-signature
returns are mandatory. A supposedly newly committed post-Seal candidate is a
Stop, never an invented no-effect receipt. There is no timeout unlock.

The consensus cache already retains every proposal at or above committed
height minus two. Exact committed boundary proofs exist separately. Therefore
this first-epoch selected-branch check does not require a second uncommitted
archive or high/locked branch manifest. The normal 64-step vote-readiness
bound remains a catch-up prerequisite, not permission to accept partial walks.

## Load-bearing cut distinction

The ordinary cut's terminal proof requires three empty proposals. It is valid
before signing Seal, but not at acceptance: the prior tip is h-1 and its
authenticated child is Seal at h. Reusing that ordinary producer unchanged
would make honest Seal acceptance impossible.

Add one private, genuinely consumed acceptance verifier. It uses the same
token-covered capture, independent execution, complete source projection,
drain/body closure and business-root derivation. Only its terminal rule changes:
the prior tip is exactly h-1, its child is the exact authenticated Seal block
being accepted and its grandchild is empty. Earlier post-anchor committed
heights must be empty. Original public cut/import/readiness verification retains
the empty-three-chain rule. Lagging observers first apply the h+1 certificate
to h-1 through existing signerless recovery; they do not bypass this prerequisite.

## Alternatives rejected

- A Boolean business-free claim, old source token, key-CAS-only inventory
  check or metadata-only Seal would bypass independent business equivalence.
- Requiring every superseded high/locked branch to be business-free adds
  agreement and liveness conditions beyond the existing consensus lock rule.
- A proposal-time singleton prevents correction before committed selection.
- Continuing old signatures and adding post-Seal refusal/progress machinery
  creates another authority surface without a consumer in this first-epoch flow.
- Making CompleteInactive mean retired or ordinary-active destroys permanent
  origin. Missing mandatory barrier metadata cannot become Unsealed.

## Scope and acceptance

New Seal production is explicitly native SQLite and bounded memory test
composition, first original outgoing epoch only. All ordinary stores implement
the mandatory barrier observation/backstop; optional providers gain no Seal
capability by default. SQL/PG schema changes require the complete selected PG
acceptance, not a new PG requirement for every protocol event.

Require genuine quorum-backed cut/readiness and callable ordered/CLI flow,
independent vectors, exact certificate variants, competing proposals,
selected-branch/cut/certificate corruption, final-token and inventory races,
both reply-loss directions, real SQLite restart/refencing, old-handle closure,
cached-signature refusal and unchanged original replay/history. No successor,
Delivery 3, independent audit, provider activation or network startup completion
is implied. Whole-database rollback detection still needs an independent anchor.
