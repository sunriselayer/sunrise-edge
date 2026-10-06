# DR-0198: One exact published-code reference check at original genesis

Date: 2026-10-06 (Asia/Singapore)

Status: Proposed. Independent design review and actual regression execution
precede acceptance. Source inspection is not a demonstrated exploit or a
security-audit result. Current implementation status belongs only in TODO.md.

## Context

The original-genesis installer authenticates a self-contained publication and
an initialization intent. It currently compares the initializer's code origin
and artifact digest to that publication. The code reference also contains an
independent revision and publication context; its constructor checks only shape
and chain consistency. Fee, economics and object-authority code references are
then compared to that same initializer reference, not to the verified artifact.

Ordinary execution already uses
`node_core::local_execution::reference_matches(reference, verified_interface)`
to compare all four code-reference fields against one verified publication.
Original-genesis installation should use this owner rather than a weaker
copy. The separately authenticated original ordered-consensus installer checks
profile/namespace and initializes its anchor; it does not resolve and repair a
different publication reference. The complete source review suggests that a
consistently altered, legitimately re-signed original manifest could install an
unusable or differently scoped fee/instance reference. Actual before/after
execution is required to establish that hypothesis; no escalation, fund loss or
severity is inferred from it.

## Decision

Use the existing private `reference_matches` owner against the actual verified
publication interface in `install_genesis_with_history`, after its existing
initializer designation check and before instance-target construction or any
business writes. It checks origin, context, revision and artifact digest as one
relationship. Do not introduce another validator, hardcode revision 1 in a
parallel check, or infer equality from matching a raw digest alone.

Replace the two incomplete origin/digest checks with one fail-closed
`GenesisError::Invalid("initialization code reference mismatch")`. This is a
local installer diagnostic, not a new wire frame or persisted receipt. Existing
fee/resource/object-authority equality checks remain, so all those references
transitively name the verified published code. Do not loosen their context,
instance, type, schema, custody, provenance, supply or history rules.

No canonical manifest/object/policy/receipt/nonce/signature bytes, hash domain,
protocol ID, storage layout or operational activation changes. Authenticated
valid genesis inputs keep the same outputs and supported historical profiles.
Invalid inconsistent input becomes refused; do not preserve that acceptance as
unreleased compatibility or add a migration/repair route. Exact retained genesis
reconciliation remains before fresh publication checks and must stay unchanged.

This core correction is separate from inspection diagnostics and can be based
on the existing main baseline, without depending on new offline operator tools.
It grants no additional authority to Standard Asset or any contract preset.

## Required evidence

- Start with the existing genuine signed genesis fixture. Produce independent
  revision-only and publication-context-only reference variants with the same
  real origin/digest. Propagate each altered reference consistently through the
  initializer, fee policy, economics resources and every object authority;
  recompute dependent instance targets and re-sign nested initialization and
  outer manifest with known disposable test material. Root verification must
  succeed on its own locally configured digest/context.
- The deliberately uncorrected source must reproduce the acceptance at the
  actual original installer and, where applicable, the ordinary ordered
  installer, not merely at a decoder. If a defining downstream check already
  rejects the fully coherent mutation, record that cause and reassess the fix.
- The corrected original installer must refuse both variants with its exact
  reference diagnostic and no changed business rows, objects, receipts, nonce,
  profiles, marker, fence or ordered state. Do not fabricate positive rows or
  omit another broken binding to obtain an unrelated refusal.
- Preserve a valid signed positive installation and its canonical outputs,
  same-input reconciliation and historical-profile tests. Preserve preexisting
  typed error precedence except the deliberately unified reference diagnostic.
- Run the changed real owner, full required storage-neutral validation and
  fresh complete exact-head independent source review. PostgreSQL/provider
  activation and independent release audits are separate gates.
