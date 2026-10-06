# Documentation

Sunrise Edge keeps only contributor entrypoints at the repository root. The
detailed design, operator guides, and specialist references live here.

## Development

- [Code ownership map](development/code-map.md): where a feature enters,
  changes protocol state, and is tested.
- [Validation and build profiles](development/validation.md): storage-neutral
  required checks, selected PostgreSQL acceptance and assertion-preserving
  signature-heavy test builds.

## Architecture

- [Architecture index](architecture/README.md)
- [Generic contract architecture](architecture/generic-contracts.md)
- [Core protocol](architecture/core-protocol.md)
- [Runtime and ingress](architecture/runtime-and-ingress.md)
- [Persistence architecture](architecture/persistence.md)
- [Developer product surfaces](architecture/product-surfaces.md)
- [Implementation structure and refactoring boundaries](architecture/implementation-structure.md)
- [FastVote HTTP network](architecture/fastvote-network.md)
- [Ordered network economics](architecture/ordered-economics.md)
- [Ordered Freeze and immutable frontiers](architecture/frozen-frontier.md)
- [Quorum-retained DrainSet and member drain](architecture/quorum-drain.md)
- [Authenticated ordered-history export](architecture/ordered-history.md)
- [Architecture decision records](architecture/decisions/README.md)

## Smart contracts

- [Smart-contract documentation index](smartcontract/README.md)
- [Publication, instances, and calls](smartcontract/lifecycle.md)
- [Standard Asset and fees](smartcontract/assets-and-fees.md)

## Operations and guides

- [Local devnet and Rust CLI](guides/devnet.md)
- [Prepare, inspect and restart an original SQLite validator](guides/sqlite-validator-startup.md)
- [Local contract validation](guides/contracts.md)
- [Production persistence requirements](operations/persistence.md)
- [PostgreSQL reference design](operations/postgres.md)
- [Offline FastVote fee-escrow inventory](operations/fastvote-fee-inventory.md)
- [Offline PostgreSQL fee claims](operations/fastvote-fee-claims.md)
- [Closed PostgreSQL FastVote operator rehearsal](operations/fastvote-pg-rehearsal.md)
- [Certified-only FastVote HTTP network and CLI quorum client](guides/fastvote-network.md)
- [Ordered economics submission and signerless recovery](guides/ordered-economics.md)
- [Prepare and submit an initial validator bond](guides/initial-validator-bond.md)
- [Ordered Freeze and resumable signed frontier export](guides/frozen-frontier.md)
- [Quorum-retained drain and explicit member recovery](guides/quorum-drain.md)
- [Export and verify ordered history](guides/ordered-history.md)
- [Install a verified inactive business cut](guides/business-import.md)
- [Retain and verify conditional readiness](guides/conditional-readiness.md)
- [Prepare and submit a first-epoch ordered Seal](guides/ordered-seal.md)
- [Activate and serve the first verified successor](guides/first-successor.md)
- [Embedded Cloudflare validator](guides/cloudflare-validator.md)
- [Recover missed certified calls](guides/fastvote-catch-up.md)
- [Certified PostgreSQL load and recovery measurements](operations/postgres-certified-load.md)
- [Hardware signing](signing/hardware-signing.md)

## Security

- [Security policy and private reporting](../SECURITY.md)
- [Security documentation index](security/README.md)
- [Reusable threat model](security/threat-model.md)
- [Initial code-security audit scope](security/initial-code-audit-scope.md)

The authoritative implementation status, outstanding work, and completion
criteria remain in [`TODO.md`](../TODO.md).
