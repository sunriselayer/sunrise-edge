# DR-0174: Independently reconstruct frozen member completion

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted extension of the DR-0170 reconstruction boundary. Current
implementation and validation status belong only in [TODO.md](../../../TODO.md).

## Context

DR-0168 deliberately permits a committed DrainSet member to complete after
Freeze without an aggregate availability certificate. The outgoing quorum
has already selected and durably retained the complete verifying obligation.
DR-0170's initial audit instead requires an availability certificate for every
applied owned target. It therefore refuses a legitimate drained source.

The missing certificate must not be fabricated, the completed source must not
be relabelled unapplied, and ordinary open-epoch admission must not be weakened
to make the audit pass. Source result and receipt rows remain comparison data.

## Decision

Treat normal publication-authorized completion and committed frozen-member
completion as distinct replay carriers of the same authenticated owned
producer. Both authenticate the original signed intent, full FastCertificate,
logical witness and exact artifact closure. A comparison-target application
hint alone does not select an executable authority.

Normal replay retains its existing aggregate availability verification and
accepted-Freeze barrier. Frozen replay must first independently execute the
original authenticated ordered prefix through accepted Freeze and DrainSet.
Rebuild the selected signed frontier streams, complete local publication
possession and union through their existing owning handlers; never transplant
source progress, ready flags or a DrainSet row into private execution.

Only then enter the existing narrow `apply_drain_member` path. It freshly
verifies the committed selection, exact member and retained proof closure and
rederives paid execution, logical generation, fees, effects, receipt and nonce.
No general private maintenance flag, source execution shortcut, new consensus
round or Standard Asset privilege is introduced.

Resolve exact authenticated prerequisites in causal order using the existing
non-recursive dependency scheduler. A producer that needs frozen authority
cannot be flushed through normal recovery before Freeze. Missing or
contradictory prerequisites, an uncertified partial prepare, foreign selection
or an uncommitted control stop reconstruction. Retained-but-unapplied
publications stay unapplied during source audit.

Verify completion companions as a complete tuple before comparing independently
produced output. Absence of an aggregate availability row is legal only for
the independently verified frozen carrier. Preserve exact original completion
bytes and normalize equivalent full certificate subsets only after verifying
their common producer identity. Keep source reads immutable and local
reservation-resolution audit separate from portable business authority.

## Acceptance and limits

Require a genuine production-path frozen completion without aggregate
availability, exact semantic state/receipt/nonce/fee equality, independent
valid positive controls, and negatives for missing or wrong committed controls,
membership, incomplete completion tuples and corrupt material. Existing normal
reconstruction, Freeze precedence, charged traps, dependency cycles, local
projection, restart and fencing coverage must remain intact.

This closes a source-family reconstruction gap. It does not itself derive a
complete pre-Seal cut, prove all selected members have completed, install a
persistent incoming validator, grant readiness, Seal or activation, or complete
Delivery 3. Those capabilities keep their separate authority and acceptance
boundaries in [epoch handoff](../epoch-handoff.md).
