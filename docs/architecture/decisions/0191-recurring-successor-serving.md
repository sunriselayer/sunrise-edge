# DR-0191: Recurring successor serving over a verified link chain

Date: 2026-10-04 (Asia/Singapore)

Status: **Proposed**. This is pre-code design awaiting fresh independent
review. It authorizes no implementation, serving or deployment, and it claims
no completion. Work status and acceptance evidence remain only in
[TODO.md](../../../TODO.md).

## Context

[DR-0189](0189-first-successor-serving.md) activates and serves exactly one
successor e+1 from the signed genesis epoch. It leaves recurring
Freeze/DrainSet/Seal, a second successor and a genuine `Withdraw` unlock out
of scope (its Section 15). Source inspection at `1b86d4a` shows the
single-link assumption hard-wired in several places:

- the verifier pins the predecessor to genesis and Seal tag 1;
- the policy chokepoint refuses every successor control and registration;
- reconstruction always installs genesis;
- capture and projection refuse every `epoch-` row and authenticate retained
  candidates only against the current policy;
- successor stores have no Seal port;
- historical committees cover only the adjacent epoch;
- registration and owner authority see only the current or predecessor
  committee.

## Decision

Adopt [recurring successor serving](../recurring-successor-serving.md):

1. **One chain owner.** A private `serving_authority::chain` module folds an
   ordered chain of links, each verified in full by the existing private
   DR-0189 verifier over a privately derived base. A local
   `SuccessorChainBudget` is checked before any artifact access; it is not a
   consensus cutoff, and nothing is checkpointed or reset.
2. **Private base and replay gate.** A crate-private `ReconstructionBase`
   bootstraps a private memory overlay from the previous link’s verified plan
   and destination-free activation rows. The same handlers then replay under
   a non-exportable, issuer-bound `ServingGate::Replay`. Later policies are
   derived from verified evidence, never supplied by the caller.
3. **Scope classification.** Rows of the current scope keep the original
   typed local-progress exclusion. Rows of earlier scopes are retained and
   must match the base byte for byte. Incoming or unknown scopes refuse.
   Earlier QC and manifest variants are each link’s own authenticated bytes,
   never normalized.
4. **Successor-scope policy.** Freeze, DrainSet, Seal with the new
   predecessor tag 2, and registration are authorized through the same
   owners. Bond owner authority for Unbond and Withdraw comes from verified
   genesis bonds and signed registrations, not committee membership.
   Historical certificate sets cover every verified earlier epoch.
5. **Successor Seal ports.** Two Seal retirement methods join the existing
   opt-in `SuccessorServingRepository`. Ordinary guards and
   `OutgoingSealRepository` are not widened, and PostgreSQL and Durable
   Objects stay unsupported.
6. **Additive APIs.** Recurring entry points are additive; single-link signatures
   and supported operations stay. Explicit new successor controls do not need a
   second legacy-only engine to retain an unreleased unsupported-feature refusal.

## Compatibility

- **Bytes unchanged.** No existing frame, key, digest, signature payload or
  stable vector changes.
- **Tag 2.** SealIntent predecessor tag 2 is newly defined with independent
  vectors. Tag 1 bytes are unchanged, and tags 0 and 3 or above refuse.
- **Schema and fixtures.** There is no storage schema change. The signed
  fixture (`unbonding_epochs = 7`) is unchanged.
- **One-link equivalence.** The existing defining first-link verifier and accepted
  evidence/bytes are shared. New controls are the stated semantic extension.

## Consequences and acceptance

- **Linear cost.** Per-request verification cost grows linearly with the
  number of links. That is accepted here; any bounded-cost alternative needs
  its own decision.
- **Coherent outcomes.** Core plus stores and real recurrence acceptance first;
  shipped hosts/SDK/CLI plus full process acceptance second. A port declaration,
  unused skeleton or test-only claim is not a completed functional outcome.
- **Acceptance.** The real process acceptance (contract Section 12) has to
  reach each unbonding owner’s committed unlock epoch. Under the unchanged
  fixture that epoch is the Unbond epoch plus 7, read from the committed row.
  Reduced-delay helper tests do not count.

## Not decided here

The selected boundaries in Section 13 require independent review before code.
Also out of scope:
governance changes to installed policy rows, PostgreSQL or Durable Object
successor support, bounded-cost verification and Delivery 3.
