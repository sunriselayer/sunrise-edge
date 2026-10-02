# DR-0185: One immutable reconstruction policy binding owner

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted bounded design under DR-0180, following read-only independent
code inspection. Implementation and fresh exact-head acceptance remain required.

## Context

PR #259 gives original genesis one immutable verified root. The business overlay
and control collector still independently repeat the same causal-profile,
context, digest, domain, committee and full-schedule relation, then independently
derive the same signed-Freeze anchor. These are identical immutable input
relationships, not two different current-authority decisions.

Other checks are intentionally distinct. Overlay history/execution companions,
strict private installation, authenticated complete control, saved-cut integrity
and fresh destination completeness cannot be replaced by a configuration wrapper.
The overlay also diagnoses an independent companion defect before an anchor
defect; combining all validation into one call would change that order.

## Decision

Adopt [reconstruction policy binding](../reconstruction-policy-binding.md).
Give the common immutable relation one private, two-stage validation owner.
Migrate the actual overlay and control consumers and delete both duplicate
predicate/anchor mechanisms. Retain each consumer's diagnostics and independent
companion order. Do not introduce a public authority capability, unused token,
universal environment, provider trait or future serving/activation producer.

Full schedule equality remains mandatory, even when the current anchor or
active suite happens to match. Canonical anchor derivation still comes from the
exact authenticated root, including its signed Freeze height; a copied policy
digest or internally consistent history pair is not a substitute.

## Consequences and acceptance

One definition prevents future policy fixes diverging between reconstruction and
control without making either verifier less independent of untrusted source
claims. Retain genuine positives and existing negative evidence; add equivalent
public-control negatives and combined-defect diagnostic precedence. Complete
required validation, fresh exact-head approval and required CI precede normal
merge. No canonical or storage schema change and no Delivery 3 completion claim.
