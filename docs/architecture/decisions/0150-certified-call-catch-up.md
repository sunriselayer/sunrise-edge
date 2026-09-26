# DR-0150: Same-epoch certified-call catch-up

## Status

Accepted design, 2026-09-26. Implementation and verification status belongs
in `TODO.md`. This is request-scoped recovery, not a complete state handoff,
shared-state ordering, epoch activation, deployment or real-asset authorization.

## Context

DR-0148 can certify and apply owned calls while one validator is unavailable.
The CLI durably saves the original signed intent and certificate. However,
`fast_path::apply` requires a local prepared record: a validator that missed
prepare cannot apply the certificate when it returns. Replaying a prepared
or committed request already works; batching that replay alone does not fix
the missing-prepare case.

Calling ordinary prepare first is not recovery. It signs and persists locks
before the caller knows that this replica reproduces the certified outcome,
so mismatched prerequisites can leave permanent, uncertifiable local locks.
Importing opaque retained commitment-witness fields as database mutations is
also not safe: the current witness decoder does not semantically verify all
its fields. Use authenticated intent execution and the existing full staged
commitment instead of inventing a trusted state-copy path.

## Decision

### Certificate-first, signerless recovery

Add an explicitly named core apply entrypoint that permits recovery with a
caller-composed creation checkpoint. The existing `apply` API retains its
prepared-only contract. Both use one internal implementation; an existing
prepared record always selects the original prepared path and its durably
stored checkpoint, never a caller replacement.

The certified HTTP apply route and PostgreSQL operator apply use the new
entrypoint with their existing trusted composition checkpoint. No new route,
wire frame, signature, certificate domain or commitment format is introduced.
The route remains opt-in and certified-only; direct/legacy mutation routes
remain structurally absent.

For every request, authenticate exact signed intent bytes and reconcile the
receipt before current epoch, policy, code, object or execution work. A prior
exact request returns its historical receipt without reapplication; conflicting
signed request reuse fails without application mutation. Preserve this rule
for both old and new entrypoints.

For fresh work:

1. Fence the committed current epoch and active, chain-anchored validator set.
   Verify certificate signatures/quorum, context and exact intent digest before
   execution. This is not a new validator vote or a local-operator authority
   substitute.
2. Read and fence local prepared-record presence. If present, preserve all
   original prepared metadata, nonce/object-lock and commitment checks. A
   mismatching or corrupt record never falls back to recovery.
3. Recovery requires a genuinely never-created prepared key, not a deleted
   preparation tombstone. Require every sender nonce lock and relevant input
   object lock to have no present value, fencing their observed revisions.
   Lock tombstones from earlier completed requests are allowed as absent
   values, but present foreign, own-orphan or older-epoch locks all reject.
   Never reclaim, delete, supersede or silently repair locks in recovery.
4. Stage the same authenticated paid-call admission, public WASM and generic
   custody/effect validation without committing. Bind the exact current sender
   nonce and all object/state prerequisites. Compare the full existing staged
   commitment and independently derived locked-object digest to the certificate.
   Refuse missing definitions, divergent heads/nonces, wrong checkpoints,
   policies or outcomes. Checkpoints are creation metadata whose only relevant
   authority here is reproduction of the certified commitment, not a published
   checkpoint/state-root proof.
5. Atomically commit the same certified application/fee effects, sender nonce,
   canonical final receipt, certificate/witness and initial fee settlement.
   Include prepared-key absence, every lock-absence revision, application
   state/object assertions and epoch/set fences in this final read set.
   Concurrent prepare or another mutation must cause a definite conflict or
   ordinary exact receipt reconciliation, never an unfenced write. Ensure the
   staging path itself cannot introduce stale-lock reclamation if a lock appears
   between reads. Recovery creates no prepare vote, synthetic prepare receipt,
   temporary lock or lock tombstone.

No Standard Asset native decoder or exceptional custody path is added. Existing
canonical intent, object, nonce, receipt, certificate, commitment and historical
claim bytes remain unchanged. Recover only ordinary certified `Call` intents
against exact target-local prerequisites; FastVote still does not certify paid
publication/instantiation or arbitrary definition import.

### Bounded Rust CLI replay workflow

Add `contract fastvote-catch-up` for an explicitly ordered, bounded manifest of
saved signed-intent/certificate artifact pairs. Reuse the independently trusted
genesis/context, endpoint identity and per-peer TLS configuration of DR-0148.
Authenticate and verify every pair, request-id uniqueness and all file/count/
total-byte bounds before the first POST. Reject invalid later entries without
partially starting an otherwise valid prefix. Never query a fresh nonce, sign,
collect new votes, invent a request id, infer missing artifacts or reorder the
operator's dependency sequence.

Reserve all result destinations before network mutation; retain and synchronize
input and output file/directory handles as appropriate. Apply the exact bytes
in the declared order under one checked whole-operation deadline and per-peer
caps. Preserve separate per-request/per-peer reports. A batch is not atomic:
network failure or a divergent replica can leave a committed prefix. Retain
original artifacts and replay them unchanged to fresh output paths. Unsigned
HTTP acknowledgements are not a global-finality or complete-state proof.

## Required evidence

- A never-prepared same-epoch replica recovers success and charged trap without
  a signer, prepare row/receipt or temporary lock. Original prepared application
  and historical receipt-first replay retain their exact behavior and bytes.
- Invalid certificate/context/intent, wrong checkpoint, missing definitions,
  divergent nonce/object state, corrupt/conflicting preparation, present own,
  foreign or stale locks and concurrent prepare reject safely. No certificate
  mismatch creates locks or signs a vote; the final commit fences every read.
- A real four-process PostgreSQL network keeps one validator absent during
  prepare and apply, certifies dependent success/trap/success calls with the
  other three, then starts the fourth and uses the compiled Rust CLI to replay
  exact artifacts. Compare canonical receipts, declared object/version/authority
  changes, nonce, certificate/witness and initial escrow settlement, with
  independently verified inventory. Close/reopen and repeat with no effects or
  nonce reapplication. Include out-of-order, divergent-state and preflight
  artifact/output negatives.
- Complete repository validation, fresh exact-final-head Opus approval and CI
  before merge. Existing independent Phase 3 and ingress security gates remain
  separate and open.

## Coverage limits

Recovery establishes only the explicitly declared certified requests against
their exact local prerequisites. Saved client artifacts are the source; peer
artifact retention/discovery and completeness of all chain history are not
implemented by this decision. It does not establish the absence of omitted
requests, a complete replica snapshot, whole-store rollback detection, a new
validator's eligibility, or state convergence before membership/epoch changes.
Fee claims, bond/evidence/epoch operations and their shared ordering are not
replayed here. DR-0149's offline claim mutations still require separately
reviewed settlement handoff before live re-entry. No timeout unlock, activation
route, background protocol process, load certification or release gate waiver.
