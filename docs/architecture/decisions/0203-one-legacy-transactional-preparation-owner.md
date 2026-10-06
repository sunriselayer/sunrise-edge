# DR-0203: One legacy transactional preparation owner

Date: 2026-10-07 (Asia/Singapore)

Status: Proposed, awaiting independent design review before production changes.
This is not permission to broaden generic ingress or replace durable authority.

## Context

The four existing generic transactional handlers repeat declared-state loading,
canonical-state validation, pure transition invocation, object-effect refusal
and output-context validation. The unscoped and explicit-domain idempotent
handlers additionally repeat metadata reservation, three-record replay checks
and dedup/outbox/delivery record construction. Both are real callers of the
native generic HTTP paths, not unused compatibility wrappers.

Their state-store scope and commit contracts genuinely differ. The unscoped
`AtomicStateWriteSet` combines assertions and mutations. The domain transaction
uses separate read and mutation sets with an explicit domain. The structured
durable path has another owning receipt, nonce, object, lifecycle/fence and
ambiguity contract. Do not flatten these differences into one universal handler.

## Proposed boundary

Add one private `transactional_invocation` module inside node-core. It owns only
the identical legacy preparation decisions, with these narrow operations:

- Load a declared snapshot through an explicitly supplied read callback. Visit
  existing sorted access keys once, validate each actual present state exactly
  where it was validated, and retain every versioned absence/read observation.
- Invoke the existing transactional machine once, then reject unauthenticated
  object effects and validate the existing output context, in that exact order.
- Derive the three legacy invocation metadata keys from the caller's existing
  layout/request, reserve their existing three slots and reject reserved access
  in the original order. The sender-nonce/publication/instance reservation
  remains the existing defining checker, not another copied prefix list.
- Reconcile already-read dedup, immutable outbox and delivery values with the
  original identity/context/error order. Return retained responses only, with
  no outbound re-enqueue. Empty records proceed; corrupt partial records refuse.
- Construct the existing typed dedup/outbox/delivery records in the original
  order. Keep their fallible encoding at each original commit assembly point,
  after application-update validation; do not reorder failures by eagerly
  encoding all records in a new generic completion object.

The public facades retain context validation, the original access-plan/digest
ordering, explicit storage scope, read scheduling and backend-specific commit
assembly. Output is still released only after commit. An exact metadata replay
still requires access-plan/reserved-namespace validation, reads all three
metadata values in their original order and performs no application read,
transition or commit.

Use plain private functions or one small metadata-key value, not a provider
trait, context framework, forwarding runtime wrapper or new crate. Existing
public paths, errors, canonical bytes and root APIs remain unchanged.

## Acceptance

Before production migration, commit and execute independent controls through
both real public idempotent entrypoints. Cover valid exact replay, unchanged
records/state, all partial/corrupt/wrong-identity metadata refusals, outbound
context failure precedence and declared/reserved access ordering. Expected
errors and I/O observations belong to the tests, not a shared producer oracle.
Retain existing original byte vectors, conflict, read-only/absence and native
HTTP/outbox behavior tests.

Then migrate all four actual generic transactional callers and delete their
copied preparation bodies. Preserve every complete read assertion, including
read-only and absent state, and all existing commit/error behavior. Keep the
structured durable reconciliation and authenticated object/nonce/fee/lifecycle
paths separate and unchanged. Run focused owning tests, exact-source independent
review and full required acceptance before normal merge. Status belongs only
in [`TODO.md`](../../../TODO.md).
