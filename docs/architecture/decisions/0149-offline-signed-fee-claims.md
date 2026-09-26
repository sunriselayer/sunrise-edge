# DR-0149: Offline signed fee-claim operator workflow

## Status

Accepted design, 2026-09-26. Implementation and verification status belongs
in `TODO.md`. This decision authorizes a closed local maintenance workflow,
not online economics ingress, network convergence, deployment or real custody.

## Context

DR-0137–0140 provide signed zero, split and final fee claims, independent
certified settlement/history verification, and exact payout commitments.
Operators can sweep PostgreSQL escrows but cannot yet inspect one entitlement,
construct an exact claim, apply it and independently verify its receipt and
payout through the shipped operator tools.

An escrow is shared state. Two distinct claims for the same generation can
win on different validator stores. Local generation/object/nonce CAS and
signed previous/next row digests prevent substitution and double application
within one store; they do not establish cross-validator delivery order.
Exposing the closed handler as an ordinary HTTP mutation would therefore
overclaim what the current network can do. Certified paid-call prepare/apply
remains the only transaction mutation on DR-0148's host.

## Decision

Deliver one usable **offline, single-namespace PostgreSQL** workflow:
inspect a certified escrow and its entitlement; prepare and save an exact
signed claim; apply or replay those same bytes; and verify the resulting
retained claim chain, receipt and exact payout. Use the operator's existing
protected DSN, certificate-validated TLS, independently pinned genesis and
namespace, bounded input/key loaders, and explicit offline-fence confirmation.
The validator must be stopped and other writers excluded for the whole
operation. Each invocation claims a new persistent writer generation; the
stopped host must restart normally afterward. Advancing a fence is not a lock
against a malicious writer or a whole-store rollback proof.
Restoring a valid writer generation is also not permission to rejoin a live
cohort after claims changed only this replica. Keep it offline until the
separate ordered settlement/state handoff and catch-up gate is verified.
Inspection-only fencing does not have that value-state replication effect.

### Generic claim preparation

Add a read-only core preparation facility instead of copying fixture-specific
Coin decoders or predicting Standard Asset bodies. Derive the operation from
the verified settlement, verify the historical entitlement and claimant
public-key binding (not proof of private-key possession during preview),
build/authenticate any embedded execution leg, run the same policy-pinned
public WASM admission and custody-effect validation used by claim apply,
and derive the exact next row digest and split payout reference from those
effects. The final signed envelope uses the existing `0x6437`/`0x6438` forms;
no canonical frame, historical vector or asset-specific privilege changes.

All new offline inspection/preparation APIs require the optional durable-key
scanner and apply DR-0141's exact bounded claim-key-set proof, including far
orphan keys and tombstones. The legacy explicit verifier and mutation handler
retain their existing structured-store API; no protocol transition depends on
the scanner. Reads still require caller-enforced offline quiescence, not a
multi-read database snapshot.

Preparation commits nothing: no object, row, nonce, receipt or audit envelope,
and no writer-generation change within core. Its output is a proposal for one
exact generation and nonce, not a reservation. Apply must independently repeat
authorization, replay reconciliation, live-context and policy checks,
execution/effect validation and all atomic CAS fences. A stale proposal fails
closed. An already-retained exact request replays without executing or moving
value again; request-id reuse with different bytes fails without mutation.
Do not weaken historical protocol-version restrictions.

### Operator artifacts and verification

Prepare and apply are separate explicit actions. Recipient, escrow, claimant
and request id are operator inputs, not inferred from an untrusted response.
Sign only after independently pinned chain/protocol/epoch and historical
claimant-key checks. Bounded artifact readers reject missing, empty, truncated
or noncanonical input. New output paths must be reserved before disruptive
fence advancement, never overwritten, and exact signed bytes synchronized
before any apply. Keep failed/partial output paths for investigation; retry
with fresh output paths, and use the original signed claim for ambiguous
commit recovery. Never silently obtain a fresh nonce or re-sign on replay.

Inspection verifies the certified history rather than trusting raw row data.
After apply/replay, verify retained history and bind reported receipt/payout
to the saved envelope. Report only this namespace's verified result, not a
network-wide reward settlement or finality statement. Inventory counts remain
coverage of present keys only. Public metadata and canonical artifacts are
not secrets; signing seeds and database credentials never appear in arguments,
outputs or captured logs.

## Required evidence

- Generic read-only preparation parity with independent apply for zero,
  positive split and final transfer; unchanged row/object/nonce/receipt/audit
  state during preparation; exact signed v2 payout provenance.
- Wrong claimant/key/context/recipient/ref, stale generation/nonce, corrupt
  artifact, request-id reuse and output-failure negatives without unintended
  value movement; authenticated apply and atomic fencing remain independent.
- Real file-backed SQLite and live PostgreSQL operator workflow, close/reopen,
  exact replay with byte-identical receipt/payout and no reapplication, and a
  rival writer generation rejecting stale work. Do not label skipped database
  tests as executed evidence.
- Existing certified-only route-denial tests remain unchanged. Bind unsigned
  FastVote SDK apply acknowledgements to the certificate transaction hash;
  these acknowledgements still do not prove durable/network finality.
- Complete repository validation and fresh exact-final-head Opus review plus
  CI before merge. Independent Phase 3/ingress security gates remain open.

## Deferred boundaries

Online shared-escrow claim ordering/certification, bond/epoch/equivocation
operator surfaces, owned-state/settlement handoff, catch-up and live activation
remain separate functional work. No activation route is added. Representative
load/soak/capacity and adopted SLOs remain post-launch hardening under DR-0147.
