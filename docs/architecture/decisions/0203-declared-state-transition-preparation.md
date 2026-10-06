# DR-0203: One declared-state transition preparation owner

Date: 2026-10-07 (Asia/Singapore)

Status: Proposed, awaiting independent design review before production changes.
This grants no generic-ingress or authenticated-object authority.

## Context

Five core paths repeat the same sorted declared-state loading and canonical
state validation: four legacy transactional handlers and the actual structured
durable handler. The unscoped write-set and domain/durable transaction assemblers
also independently check the same writable-access and missing-observation rules.
Each specification change currently requires editing multiple copies.

The native adapter references the two legacy idempotent APIs, but its current
public routes reject every non-transaction family and reject unauthenticated
transactions on those legacy paths. Those calls are behind closed guards; they
are not successful production ingress. Preserve their internal/public-library
contracts without counting their cleanup as a network capability. Factoring
legacy metadata replay alone is not the priority.

## Proposed boundary

Add one private `state_transition` owner inside node-core for the identical
declared-state preparation rules:

- `load_declared_values` accepts the existing bounded sorted plan and an
  explicit point-read callback. Read each key once, validate its actual present
  canonical state at the original point, and retain the exact versioned value,
  absence or tombstone. Return only the value map, not verified authority.
- One writable-update checker owns undeclared/read-only refusal. Each original
  assembler calls it while visiting updates in its original order, before its
  own original mutation construction/insertion. Do not eagerly normalize all
  mutations or move a fallible constructor past another refusal.
- One declared-revision accessor owns the missing-snapshot invariant. Both
  assemblers invoke it before their original read/write constructor.
- `asserted_transition_writes` and `domain_transition_parts` keep their distinct
  assembly strategies in this owner. The former emits assertion writes for
  every untouched declared key; the latter keeps separate complete reads and
  only requested mutations. Same rule does not imply same persistence envelope.

Migrate all five actual snapshot-loading consumers and both assemblers, then
delete the copied loops and checks. Keep `NodeStateSnapshot`, public constructors,
root API paths and typed transitions where they already belong. Use ordinary
private functions, not a universal handler, provider trait, new crate or mutable
context framework.

The durable caller retains receipt-first replay, admission/profile/nonce and
lock fences, module resolution, object authorization/loading and output/object
effect validation. It supplies its already-authorized object slice separately
after state loading. The shared loader never resolves a domain, authenticates
anything, supplies object authority, commits or exposes output.

Keep every facade's access-plan/digest order, storage scope, scheduled read and
backend-specific commit/error behavior. Legacy replay and record construction
remain unchanged in this slice. Do not let a cleanup of an unsupported public
route advertise acceptance of another event family.

## Acceptance

Before production migration, commit and execute independent public-API controls
for retained legacy replay/refusals and sorted declared-state reads. Expected
errors, read traces and unchanged records/state are test-owned. Keep every
original canonical vector, conflict, read-only/absence, object, durable,
receipt/nonce/fence and native HTTP refusal test.

Test undeclared/read-only updates, complete read assertions including absence
and tombstones, missing declared observations, corrupt-state early refusal and
the distinct unscoped versus domain envelopes. Preserve partial builder failure
ordering; no transaction or output is released after refusal. Run focused owning
checks, exact-source independent review and complete required acceptance before
normal merge. Status belongs only in [`TODO.md`](../../../TODO.md).
