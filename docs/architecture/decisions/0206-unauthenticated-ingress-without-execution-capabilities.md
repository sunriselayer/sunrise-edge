# DR-0206: unauthenticated ingress without execution capabilities

Date: 2026-10-07 (Asia/Singapore).

## Decision

An ingress that cannot authenticate any event must not own execution or
storage capabilities. Replace the unreleased `router` and
`resolved_domain_router` constructors, including their `_with_executor`
forms, with one explicit `closed_event_router` and its shared-executor
form. The result mounts liveness and the closed canonical event endpoint;
it is not a query, execution, recovery or validator host.

Its private state contains only the bounded blocking executor. It does not
accept or retain a runtime, state store, blob store, signer, transport, clock,
placement manifest, node configuration, hash resolver, execution callback or
lease identity source. This is removal of unnecessary authority and duplicate
dispatch, not a new generic framework or a compatibility shim.

## Why

[DR-0099](0099-submit-only-event-ingress.md) already closes both legacy native
routes to every known event. Their two guards reject all eight decoded kinds
before the following node-core invocation and request-scoped outbox delivery
can execute. Nevertheless, the constructors retain those capabilities, require
transactional store traits, and duplicate a second HTTP handler and invocation
pipeline. Documentation incorrectly presents these routers as recoverable
execution hosts. Workspace consumers of the legacy constructors are tests,
not the devnet, certified validator, ordered or successor hosts.

Keeping dead execution after a rejection guard is a maintenance hazard:
loosening a guard can silently expose an unauthenticated execution path. The
new rejection owner returns an `InvocationError`, not a successful node result.
An authenticated future event family must use a deliberately constructed
authority-bearing composition; this endpoint cannot acquire that authority by
changing one classification branch.

The generic node-core library entrypoints and standalone legacy outbox
recovery remain separate, unchanged capabilities. This decision neither
certifies those compositions nor promises indefinite compatibility for them.

## Required observable contract

- Preserve `GET /health/live` as an I/O-free 204, and `POST /v1/events` with
  the original exact media type, encoding, canonical decode and body limits.
- Malformed or unknown canonical values retain their original 400 mapping.
- Every decoded `SubmitTransaction` retains the opaque
  `501 submit-transaction-requires-authenticated-route` response; the other
  seven known families retain `501 event-family-requires-authenticated-route`.
- Preserve rejection priority: content type, content encoding, body extraction,
  blocking admission, canonical decode, then event-family classification.
  Keep the permit over the blocking decode, closed admission/overload mapping,
  join failure handling, liveness independence and server connection controls.
- Preserve the authenticated structured/preinstalled-WASM event guards and
  every query, certified FastVote, paid call, publication, ordered, successor,
  fencing, replay and standalone outbox recovery path.
- No canonical byte, event tag, digest, signature, state layout, nonce,
  receipt, outcome or quorum change. The deliberate public Rust constructor
  removal is an unreleased host-composition API change, not a protocol version.

## Implementation and verification contract

The pre-implementation exact `24fa651` plan received complete independent
Opus PLAN APPROVE. The accepted advisory naming change makes refusal explicit:
`closed_event_router` cannot be mistaken for an unauthenticated execution host.
Plan approval does not accept implementation or waive execution gates.

1. Capture the existing native HTTP suite before implementation. Its actual
   all-feature baseline on parent `7853869165124b4a4dfe81d5b05eb081fa027dce`
   is preserved in the ongoing complete required gate. Before implementation,
   the actual parent-built native suite was also re-executed at byte-identical
   crate inputs: 161 passed, zero failed, binary SHA-256 unchanged
   `15032aab1959235e86216094928f10555a27bce6000fa0a0db0336e1655f06b1`.
   Do not claim the whole gate has finished merely because the native suite passed.
2. Replace both legacy host states and dispatchers with one capability-free
   closed ingress. Remove dead invocation/delivery references and public
   compatibility wrappers, not the independently used recovery functions.
3. Migrate all actual callers. Retain the exhaustive authenticated-route
   side-effect tripwires and legacy HTTP rejection vectors; replace vacuous
   counters for capabilities no longer injectable with constructor-level
   absence and direct closed-ingress tests. Exercise all eight event kinds,
   malformed values, HTTP admission/limits and liveness. Test both constructor
   forms, including exhausted and closed shared admission.
4. Update the live runtime/ingress and capability documentation. Historical
   DR-0099 remains immutable; this dated decision supersedes only its obsolete
   constructor inventory, not its security policy.
5. Run the exact owning native HTTP tests, workspace all-feature Clippy,
   formatting and documentation checks, then the complete required acceptance
   and fresh exact-head independent review before normal merge. Use a separate
   bounded local Cargo target while the existing parent gate owns its target.

Source review, local scope checks and a removed callback do not establish an
independent security audit, provider qualification or mainnet readiness.
All remaining completion groups stay in [TODO](../../../TODO.md).
