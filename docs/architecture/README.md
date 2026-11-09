# Architecture

Start with the one subsystem relevant to the change. Use the
[full architecture catalog](catalog.md) only when the owner is unclear. The
[decision register](decisions/README.md) preserves dated rationale, including
proposals and superseded alternatives; a link is not an acceptance claim.
Current work, validation, and release gates belong in [TODO.md](../../TODO.md).

| Change area | Start here | Follow when relevant |
| --- | --- | --- |
| Canonical protocol, consensus, execution, economics | [Core protocol](core-protocol.md) | [Code ownership map](../development/code-map.md) |
| Host, HTTP, provider adapters | [Runtime and ingress](runtime-and-ingress.md) | [Host compositions](compositions-and-capabilities.md) |
| Stores, snapshots, recovery | [Persistence](persistence.md) | [Operator persistence](../operations/persistence.md) |
| Generic contracts and Standard Asset | [Generic contracts](generic-contracts.md) | [Smart contracts](../smartcontract/README.md) |
| First Seal, import, serving, recurring links | [Handoff contracts](first-successor-serving.md) | [Recurring successor](recurring-successor-serving.md), [Seal](ordered-seal.md) |
| Signing, review, custody | [Signing preparation](signing-preparation.md) | [DR-0214 comparison](decisions/0214-protected-custody-and-review-boundary.md), [8a5 route snapshot](signing-route-test-map.md) |
| Native release and validation | [Release handoff](native-release-handoff.md) | [Validation profiles](repository-validation.md) |
| Product and operator flows | [Product surfaces](product-surfaces.md) | [Operator guides](../README.md) |

For a concrete signing family, use its applicable decision and source owner;
the route map is a dated 8a5 snapshot, not a live inventory.
[DR-0284](decisions/0284-conditional-readiness-protected-worker-proposal.md)
and [DR-0285](decisions/0285-successor-protected-host-proposal.md) record the
selected trusted-local-OS boundary for readiness and successor separately.
[DR-0286](decisions/0286-standard-asset-genesis-protected-review-worker.md)
records the later offline genesis author boundary. Implementation and
qualification are source-specific in TODO. Do not infer generic administrative
or other family authority from these selections.
[DR-0289](decisions/0289-bond-outer-key-custody-and-split-approval.md)
selects only bond outer-key isolation and distinct collateral/registration
approvers. [DR-0291](decisions/0291-original-bond-inner-standard-asset-profile.md)
selects the first original-genesis Standard Asset collateral operation and
source-owner key boundary; protected approval and qualification remain open.

Historical design alternatives remain available in the
[catalog](catalog.md) and [decision register](decisions/README.md). Read an
older proposal only when a current contract or TODO entry cites its exact
criterion; later accepted records control the portions they explicitly replace.
