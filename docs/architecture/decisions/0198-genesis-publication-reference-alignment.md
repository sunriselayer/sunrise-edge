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
The economics-resource context must equal both its code context and the signed
economics-policy context, which must equal the manifest context. Publication
authentication also pins the artifact to that context. These existing checks
already reject a coherently altered context; the reachable source hypothesis
is a revision-only mismatch, not a differently scoped installation.

Ordinary execution already uses
`node_core::local_execution::reference_matches(reference, verified_interface)`
to compare all four code-reference fields against one verified publication.
Original-genesis installation should use this owner rather than a weaker
copy. A consistently altered, legitimately re-signed revision-only reference
could install an unusable fee/instance reference which ordinary execution then
refuses. Actual before/after execution is required to establish that hypothesis;
no escalation, fund loss or severity is inferred from it. The independent
`install_ordered_genesis` owner initializes profile/namespace/anchor state but
never resolves a code reference, so it is not a second equality-check owner.
The actual second consumer is private signed-genesis installation during
`VerifiedBusinessReconstructor::new` in `business_reconstruction.rs`.

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
instance, type, schema, custody, provenance, supply or history rules. Preserve
the earlier `nonexecutable genesis code` origin refusal: the unified diagnostic
covers revision/digest and context defence-in-depth, not that earlier case.

No canonical manifest/object/policy/receipt/nonce/signature bytes, hash domain,
protocol ID, storage layout or operational activation changes. Authenticated
valid genesis inputs keep the same outputs and supported historical profiles.
Invalid inconsistent input becomes refused; do not preserve that acceptance as
unreleased compatibility or add a migration/repair route. Original installation
validates signed publication, initialization, policy and objects before its
step-9 installed-marker/receipt reconciliation. Keep that existing ordering.
The new check therefore also refuses restart verification and private business
reconstruction from an inconsistently revisioned retained root. A store built
from such a root is not repaired, migrated or silently accepted by this change.

This workflow prepares the initial network, does not activate a public network
or modify any deployed store, and has no known released malformed-genesis
baseline to support. That is not a claim that every external store has been
surveyed. If an actually deployed or independently retained malformed root is
discovered, stop its activation and report the refusal/required operator
decision; do not add an automatic repair or reuse its digest for different
bytes. Genuine valid retained roots keep their existing reconciliation outputs.

This core correction is separate from inspection diagnostics and can be based
on the existing main baseline, without depending on new offline operator tools.
It grants no additional authority to Standard Asset or any contract preset.

## Required evidence

- Start with the existing genuine signed, bonded genesis fixture. Produce a
  revision-only reference variant with the same real origin/context/digest.
  Propagate the altered reference consistently through the
  initializer, fee policy, economics resources and every object authority;
  recompute the instance record's dependent target and every policy/resource/
  authority instance, and re-sign nested initialization and
  outer manifest with known disposable test material. Root verification must
  succeed on its own locally configured digest/context.
- The deliberately uncorrected source must reproduce the acceptance at the
  actual original installer, not merely at a decoder. If a downstream check
  rejects the fully coherent mutation, record that cause and reassess the fix.
- The corrected original installer must refuse the revision variant with its exact
  reference diagnostic and no changed business rows, objects, receipts, nonce,
  profiles, marker, fence or epoch state, on fresh and restart paths. Do not
  fabricate positive rows or omit a binding to obtain an unrelated refusal.
- Exercise the real private original-genesis business-reconstruction constructor
  with the verified altered root; require its existing installation-refusal
  diagnostic, no published snapshot/activation and unchanged external state.
  Preserve a genuine valid private reconstruction and retained-root replay.
- Keep a context-only negative control and record the existing economics or
  manifest-context refusal; do not demand old acceptance or the new revision
  diagnostic from a context variant which cannot satisfy those bindings.
- Preserve a valid signed positive installation and its canonical outputs,
  same-input reconciliation and historical-profile tests. Preserve preexisting
  typed error precedence except the deliberately unified reference diagnostic.
- Run the changed real owner, full required storage-neutral validation and
  fresh complete exact-head independent source review. PostgreSQL/provider
  activation and independent release audits are separate gates.
