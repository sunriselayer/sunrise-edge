# DR-0189: First successor target-local activation and authenticated serving

Date: 2026-10-03 (Asia/Singapore)

Status: **Accepted design** after fresh independent Opus review of
`7124ea9` on 2026-10-03. This authorizes implementing this closed contract,
not serving activation or deployment before functional acceptance.
Current work and implementation evidence remain only in
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

A second independent review of that corrected contract (base `54791cf`)
returned five further blocking findings: an incomplete safety-state
family list, generic commit ports that would have defeated the warrant,
an installer that ignored a real carried-forward policy dependency,
underspecified/duplicate warrant and artifact interfaces, and an
incorrect certificate-equivalence claim. On 2026-10-03 the contract was
revised to address them and to close the remaining interfaces: a
node-core `SuccessorArtifactSource` over existing saved-cut and history
transport types, distinct `ActivationWarrant` and `LiveWarrant` types, a
runtime `SuccessorServingRepository` returning the existing
`DurableCommitOutcome`, an explicit physical namespace validator, and a
whole-transaction preflight against existing limits. Whether the findings
are resolved is for the next independent review to decide.

A further independent review at `f227c72` accepted the byte-preserving
ordered-key refactor and found two remaining design interface issues:
crate-visible raw scope enums could be constructed without a warrant,
and the SDK could not reach the private verifier. The revised proposal
uses opaque scopes with module-private inner representations and a public
read-only wrapper over the one private source-free verifier. Warrants
retain private fields; shared policy inputs contain no destination member.
Further independent reviews closed the policy's verified domain/subject
binding and causal profile preservation. The final review explicitly
approved pre-code implementation at `7124ea9`, including the shared pure
control-authentication chokepoint. Its implementation obligations are
preserved: committed-preview must propagate the typed unsupported-control
error, HTTP must map it to a permanent 4xx refusal, and readiness must
explicitly reject an already Serving slot before signing or retained
exposure. None is an implementation-completion claim.

## Decision

Use [first-successor-serving.md](../first-successor-serving.md) as the
accepted design contract. Its choices, summarized:

1. Keep source-free verified evidence (immutable genesis, outgoing
   committee, ordered history through the committed Seal, readiness
   certificate and eligibility) strictly separate from two private
   opaque destination warrants with private fields: `ActivationWarrant` before
   Serving and `LiveWarrant` only from an installed Serving slot. The SDK consumes only
   the evidence; no decoded row or destination-reported flag constructs
   any of the three.
2. Re-verify full cryptographic evidence on every invocation -- activation,
   reconciliation, startup and every live request alike. Nothing is cached
   or memoized; cost is explicit and linear in saved-cut re-execution plus
   history length, never assumed constant-time.
3. Give the three new e+1 execution/paid-fee/publication policy rows
   provenance at a generation derived under the verified cut binding
   `generation_floor`, through the existing checked derivation and
   regression guard scoped by `GenerationScope` -- never the genesis floor
   and never a provenance-free write. Excluded control families and
   protected rows need none.
4. Scope all five ordered-economics live safety families (`state`,
   `applied-height`, `leader-proposal`, `vote`, `vote-high`) by chain,
   protocol and the verified successor epoch/anchor through one private
   `OrderedKeyScope`, distinct from the existing chain-only safety rows,
   with the three singleton roots asserted virgin `INITIAL` at activation;
   per-view rows are excluded by full inventory comparison, plan refusal
   of any `epoch-` row and the in-lock token sequence.
5. Keep the generic ordinary commit ports Ordinary-only, adding only an
   in-lock `Inactive` slot recheck. A new optional runtime
   `SuccessorServingRepository` installs every authoritative fact --
   next-epoch policy/committee rows (via the real `derive_activation_set`
   dependency fold), the epoch-state root and the exact Seal closure with
   its original receipt -- atomically with the protected serving record,
   after one whole-transaction preflight against existing limits, and
   rechecks the protected serving/origin observation in its own lock for
   every later successor commit. Core maps its `DurableCommitOutcome`.
6. After Serving, verify only immutable authority and the unmodified
   original import/Seal evidence on retry; never require the now-mutated
   business inventory to equal the raw plan again, and never rewrite
   mutable state.
7. Reuse the existing ordered-history verifier for the Seal suffix with one
   required, reviewed extension that accepts a Seal candidate only at the
   terminal height; no caller Boolean bypass and no missing-body exception
   for an otherwise-authenticated proof.
8. Keep the new epoch anchor and height-zero safety namespace separate from
   historical object/code/escrow verification; prove new-epoch paid calls
   against imported instances and original receipts before any claim of
   independent new-epoch business.
9. Refuse a retired validator as a *consensus signer* (vote, certificate,
   readiness, activation) through the existing membership check, never as
   an ordinary request sender; document same-key-multiple-namespace and
   whole-database-rollback as an explicit operational scope/fault-model
   boundary, not a blanket accepted risk.
10. Specify every field, phase, digest purpose/epoch, length, bound, port
    signature and schema/namespace allocation, including
    `GenerationScope`/`derive_scoped` constructed only from a warrant, as
    exact accepted interfaces with named migrated callers.
11. Preserve the original verified causal admission profile and signed
    minimum Freeze height in the successor policy, while its context,
    domain and anchor come only from verified successor inputs. Ordered
    fencing and causal/external-lane checks remain active. Registration
    economics is absent. Candidate Freeze/DrainSet/Seal/registration kinds
    are refused with `UnsupportedSuccessorControl` as the first check in
    the one pure `authenticate_with_policy` dispatch shared by proposal,
    vote, committed preview/apply, reservation and HTTP admission. Other
    unsupported controls refuse at their entry points before signing and
    retain ordinary-namespace guards where present, never disabling the
    profile. Readiness returns its corresponding typed error on a Serving
    slot before signing or retained exposure, not an incidental inventory
    or token mismatch.

## Not yet decided

Recurring Freeze/DrainSet/Seal and predecessor reconstruction for a second
successor, genuine Withdraw/Unbond unlock for a retired validator, PG/DO
activation production, and independent security audit remain separately
reviewed next work, out of scope for this accepted design record. Design
approval does not waive their separate implementation and review.

## Consequences and acceptance

Implement the closed contract with real engine/store/operator/SDK consumers;
no second consensus engine, unused sealed port or speculative schema.
Preserve every existing accepted frame, key and vector; add only the
identifiers this record allocates. Require the genuine four-store SQLite
flow, independent vectors for every new frame, negative/adversarial coverage
for every refusal listed in the linked contract, and the unchanged full
validation gate (`./scripts/check-all.sh`, plus `--full` PG for the schema
change) before functional acceptance. This design record completes no
implementation, Delivery 3, independent audit or production qualification.
