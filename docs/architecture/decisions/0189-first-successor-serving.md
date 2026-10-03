# DR-0189: First successor target-local activation and authenticated serving

Date: 2026-10-03 (Asia/Singapore)

Status: **Proposed** for independent review. No implementation approval,
wire/key allocation, migration, serving activation or deployment is
authorized. Current work and evidence remain only in
[TODO.md](../../../TODO.md).

## Context

[DR-0187](0187-first-epoch-ordered-seal.md) accepts the first-epoch ordered
Seal and permanent outgoing barrier but explicitly supplies no activation
producer. [DR-0186](0186-functional-handoff-closure.md) and
[epoch-handoff.md](../epoch-handoff.md)'s "Recovery and serving authority"
section describe the aspirational target -- a verified predecessor cut and
next set deriving a fresh epoch-scoped anchor and safety state -- without
fixing exact fields, provenance rules or a reviewed contract.
[DR-0176](0176-verified-inactive-business-import.md) verifies and installs a
cut's raw plan into a permanently inactive target;
[DR-0178](0178-conditional-readiness-wire-and-retention.md) verifies and
retains conditional readiness for that target. Neither grants serving
authority. An initial detailed design for closing this gap was independently
reviewed and returned open corrections, concentrated on: evidence/warrant
separation; full per-invocation re-verification; the Logical
generation-floor/provenance rule for new activation rows; epoch-scoped safety
state; atomic installation under the permanent serving record;
re-verification after Serving without re-requiring a frozen business
snapshot; exact Seal-suffix reuse; the distinction between the new epoch
anchor and historical object/code context; consensus-signer versus
ordinary-sender refusal of a retired validator; and exact schema/namespace
allocation. This record adopts the corrected contract.

## Decision

Use [first-successor-serving.md](../first-successor-serving.md) as the
closed proposed contract. Its choices, summarized:

1. Keep source-free verified evidence (immutable genesis, outgoing
   committee, ordered history through the committed Seal, readiness
   certificate and eligibility) strictly separate from the destination's
   private activation warrant (import binding, completed progress, fresh
   writer token). The SDK and operator consume only the former; neither a
   decoded row nor a destination-reported flag constructs either.
2. Re-verify full cryptographic evidence on every invocation -- activation,
   startup and reconciliation alike. No live warrant is cached or memoized;
   signature, proof and certificate verification cost is explicit and linear
   in history length, never assumed constant-time.
3. Give every new or changed activation row (successor validator set,
   execution/paid-fee/publication policy, consensus anchor, epoch-scoped
   safety state, the protected serving record) an exact, specified Logical
   generation-floor and provenance rule derived from the verified cut
   binding's `generation_floor`, reusing `logical_generation`'s own checked
   derivation and regression guard -- never the unrelated, byte-identical
   genesis floor, and never a silent provenance-free write.
4. Scope the new ordered-economics safety state (leader/vote/high-QC/applied
   prefix) by chain, protocol and the verified successor epoch/anchor, in a
   key family distinct from the existing chain-only safety rows, created
   only at virgin `INITIAL` revisions under positively observed `Inactive`
   origin.
5. Install every authoritative fact -- next-epoch policy/committee rows, the
   consensus anchor, the new safety state and the original Seal closure
   companions -- atomically with the permanent protected serving record,
   under the target's own fence. Every ordinary commit port rechecks the
   protected serving/origin contract inside its own lock, exactly like the
   outgoing barrier.
6. After Serving, verify only immutable authority and the unmodified
   original import/Seal evidence on retry; never require the now-mutated
   business inventory to equal the raw plan again, and never rewrite
   mutable state.
7. Reuse the existing ordered-history verifier and acceptance-only terminal
   for the Seal suffix, with no caller Boolean bypass and no missing-body
   exception for an otherwise-authenticated proof.
8. Keep the new epoch anchor and height-zero safety namespace separate from
   historical object/code/escrow verification; prove new-epoch paid calls
   against imported instances and original receipts before any claim of
   independent new-epoch business.
9. Refuse a retired validator as a *consensus signer* (vote, certificate,
   readiness, activation) through the existing membership check, never as
   an ordinary request sender; document same-key-multiple-namespace and
   whole-database-rollback as an explicit operational scope/fault-model
   boundary, not a blanket accepted risk.
10. Close every field, phase, digest purpose/epoch, length, bound and
    schema/namespace allocation, including the generation-floor scoping
    (`GenerationScope`/`derive_scoped`), as closed, exact, private-only
    signature additions with migrated callers -- not an assumed interface
    and not an open implementation blocker.

## Not yet decided

Recurring Freeze/DrainSet/Seal and predecessor reconstruction for a second
successor, genuine Withdraw/Unbond unlock for a retired validator, PG/DO
activation production, and independent security audit remain separately
reviewed next work, out of this record's scope. No open design or
core-signature question remains within this record's scope.

## Consequences and acceptance

Implement the closed contract with real engine/store/operator/SDK consumers;
no second consensus engine, unused sealed port or speculative schema.
Preserve every existing accepted frame, key and vector; add only the
identifiers this record allocates. Require the genuine four-store SQLite
flow, independent vectors for every new frame, negative/adversarial coverage
for every refusal listed in the linked contract, and the unchanged full
validation gate (`./scripts/check-all.sh`, plus `--full` PG for the schema
change) before acceptance. This Proposed record completes no
implementation, Delivery 3, independent audit or production qualification.
