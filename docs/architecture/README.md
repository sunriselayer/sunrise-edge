# Architecture

Start with the one subsystem relevant to the change. Use the
[full architecture catalog](catalog.md) only when the owner is unclear. The
[decision register](decisions/README.md) preserves dated rationale still in the
active tree; fully replaced proposals remain in Git history. A link is not an
acceptance claim.
Current work, validation, and release gates belong in [TODO.md](../../TODO.md).

| Change area | Start here | Follow when relevant |
| --- | --- | --- |
| Canonical protocol, consensus, execution, economics | [Core protocol](core-protocol.md) | [Code ownership map](../development/code-map.md) |
| Host, HTTP, provider adapters | [Runtime and ingress](runtime-and-ingress.md) | [Host compositions](compositions-and-capabilities.md) |
| Stores, snapshots, recovery | [Persistence](persistence.md) | [Operator persistence](../operations/persistence.md) |
| Generic contracts and Standard Asset | [Generic contracts](generic-contracts.md) | [Smart contracts](../smartcontract/README.md) |
| First Seal, import, serving, recurring links | [Handoff contracts](first-successor-serving.md) | [Recurring successor](recurring-successor-serving.md), [Seal](ordered-seal.md) |
| Signing, review, custody | [Signing preparation](signing-preparation.md) | [Original bond protected signing](original-bond-protected-signing.md), [protocol custody](local-protocol-custody.md) |
| Native release and validation | [Release handoff](native-release-handoff.md) | [Validation profiles](repository-validation.md) |
| Product and operator flows | [Product surfaces](product-surfaces.md) | [Operator guides](../README.md) |

For a concrete signing family, use its current architecture contract and source
owner. [Signing preparation](signing-preparation.md) distinguishes the selected
role-specific boundaries from mechanical signature preparation; the
[original bond contract](original-bond-protected-signing.md) gives its narrower
development profile. Source-specific evidence and release qualification belong
in TODO. Historical alternatives remain in the [catalog](catalog.md),
[decision register](decisions/README.md) and Git history; read them only for a
specific criterion. Later accepted decisions control the portions they replace.
