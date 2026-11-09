# DR-0287: Seed-free bond-registration structural preview

Date: 2026-11-08 (Asia/Singapore)

Status: Implemented structural preview. It grants no protected signing,
trusted approval or release qualification.

Later scope note (2026-11-08): [DR-0288](0288-successor-bond-registration-structural-preview.md)
supersedes only this record's original-only successor-pin refusal. The original
preview behavior and all nonauthorization limits remain unchanged.

Later scope note (2026-11-09): [DR-0289](0289-bond-outer-key-custody-and-split-approval.md)
selects the outer-key boundary and separate approvers, without approving this
preview, the inner generic leg or an actual protected signing path.

## Context

DR-0211 retains the exact signed custody leg and predicted bond row in the
original and successor prepared registration owners. The existing CLI's
`economics bond-registration-prepare` loads a development seed and emits only a
signed structural claim. It is not an attended content review. DR-0214 requires
operation-specific content and semantic policy before protected approval, while
TODO M2-N3 leaves bond registration's protected authority unselected.

## Decision

Add `economics bond-registration-preview` as a separate, seed-free inspection
command for original scope only. It accepts the existing locally pinned genesis
scope, request ID, signed leg and predicted row, plus an explicit expected
public authorization key. It rejects signing and output-artifact flags. It uses
the existing original prepared owner, then independently re-encodes
the canonical signed leg and row, recomputes the row digest and outer signing
frame, and prints the full canonical leg, predicted row, unsigned outer intent
and frame as bounded hex with the exact trusted ordered domain, context and
amount fields. Successor pins fail closed before reading any artifact.

The command writes no artifact, makes no signing call, and labels the output
`approved=false`, `signed=false`, `executed=false`, and
`leg_semantics=unreviewed`. It does not interpret arbitrary contract code or
grant permission to a protected backend. The existing development signing
command and its envelope bytes stay unchanged.

## Verification and remaining boundary

The existing bond-registration CLI test owner must compare preview bytes with
the prepared owner and reject malformed inputs, changed signed or
structurally inconsistent leg/row inputs, a wrong key, and signing/output flags
without creating output. A coherent replacement of all untrusted inputs is a
new structural claim, not something this preview can recognize as previously
approved. Successor preview is outside this slice; the existing successor
development signing path is unchanged. Full required validation and
exact-source CI remain separate.

Selecting bond authority, recognized leg semantics, trusted human review,
protected custody, recovery and revocation remains M2 work. This preview
closes no M2 or release checkbox.
