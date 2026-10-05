# DR-0191: Recurring successor serving over a verified link chain

Date: 2026-10-04 (Asia/Singapore)

Status: **Accepted pre-code design** after fresh independent Opus APPROVE
at `5ee07de` on 2026-10-04. The review's nonblocking clarifications are
incorporated: the memory-only constructor is hidden and retains the ordinary
Seal port but no successor port; only the private gate supplies authority,
activation puts replace same-key plan rows, and registration owns its derived
live context. This authorizes implementation, not serving, deployment or
completion. Work status and acceptance evidence remain only in
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
2. **Private base and replay gate.**
   - **Bootstrap.** A crate-private `ReconstructionBase` bootstraps a memory
     overlay through one runtime constructor,
     `MemoryDurableStateStore::new_bound_from_import_batches`. It is
     memory-only and Ordinary, reuses the staged-import row validation, and
     grants no serving or provider capability.
   - **Activation rows.** The previous link’s activation mutations, derived
     through that fixture, are applied with its single real Seal receipt.
   - **Postcondition.** The existing `raw_rows` logical equality is required;
     it excludes only physical revisions.
   - **Replay.** The same handlers replay under a per-call, issuer-bound
     `ServingGate::Replay` minted by the overlay.
   - **Policies.** Later policies come from verified evidence: scoped
     predecessor checks, plus the subject digest held privately in the policy.
3. **Scope classification.** Rows of the current scope keep the original
   typed local-progress exclusion. Rows of earlier scopes are retained and
   must match the base byte for byte. Incoming or unknown scopes refuse.
   Earlier QC and manifest variants are each link’s own authenticated bytes,
   never normalized.
4. **Successor-scope policy.**
   - Freeze, DrainSet and Seal with the new predecessor tag 2 are authorized
     through the same owners.
   - Registration uses one `RegistrationScope`: immutable e_0 profile and
     resource context, genuine live context.
   - It has two modes. Admit refuses any id or key reuse against the
     registry and the provenance-bound owner registry. Existing accepts only
     a committed anchor’s own identity and reconciles same-epoch anchors.
   - Unbond and Withdraw authority comes from verified genesis bonds and
     signed registrations, not committee membership.
   - Historical certificate sets cover every verified earlier epoch.
5. **Successor Seal ports.**
   - Two Seal retirement methods join the existing opt-in
     `SuccessorServingRepository`.
   - Every Seal reader, capability check and commit resolves through one
     issuer-bound `SealPort`.
   - Ordinary guards and `OutgoingSealRepository` are not widened, and
     PostgreSQL and Durable Objects stay unsupported.
6. **Bounded frontier work (2026-10-04 clarification).** Every physical retained
   publication consumes the step budget, including exact historical carriers;
   missing prior carriers refuse. One private current index, logical accumulator
   and physical cursor share an atomic protected commit. Original and Successor
   use the same owner. Typed local metadata is validated before exact exclusion
   from semantic cuts/imports. Pages reverify actual current publications and
   preserve all public hashes and wire rules. Incomplete pre-index private state
   refuses; no unbounded or legacy-only fallback is introduced. See Section 4.1
   of the recurring design for the complete contract.
7. **Additive APIs.** Recurring entry points are additive; single-link signatures
   and supported operations stay. Explicit new successor controls do not need a
   second legacy-only engine to retain an unreleased unsupported-feature refusal.
8. **Post-Seal historical material.** Use the existing bounded history reader
   and complete fixed-target verifier with a freshly chain-derived policy,
   exact imported namespace/binding and existing fence/deadline. Keep original
   source composition and fresh live authority unchanged. A separate historical
   signing capability establishes no additional artifact-integrity property.
   Post-Seal attribution checks the real barrier against the terminal exported
   Seal. Read-only consumption is not effects, readiness or activation proof.

## Compatibility

- **Public bytes unchanged.** No existing public frame, publication address,
  digest, signature payload or stable public vector changes. Private frontier
  progress/index codecs belong to the local owner and do not promise compatibility
  with incomplete pre-index state.
- **Tag 2.** SealIntent predecessor tag 2 is newly defined with independent
  vectors. Tag 1 bytes are unchanged, and tags 0 and 3 or above refuse.
- **Schema and fixtures.** There is no storage schema change. The signed
  fixture (`unbonding_epochs = 7`) is unchanged.
- **One-link equivalence.** The existing defining first-link verifier and accepted
  evidence/bytes are shared. New controls are the stated semantic extension.

## Consequences and acceptance

Amendment, 2026-10-04: the cost and test-profile descriptions below clarify
the reviewed implementation; they do not change the trust or acceptance contract.

- **Explicit growing cost.** Each link is verified, and replay work includes
  its actual accumulated state and history. The current implementation also
  clones historical owner/committee material across links; total work can
  grow quadratically with link count. The explicit link budget is not a
  constant-cost or linear-time guarantee. A verified checkpoint or shared
  history representation needs its own decision, not an implicit trust cache.
- **Test execution.** The node-core dev/test profile uses optimization level 1
  for real cryptographic recurrence fixtures. Assertions and overflow checks
  remain enabled; no fixture signature, epoch delay or verification is skipped.
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
