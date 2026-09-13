# Smart contracts

These documents define the normative **To-Be** contract-facing model. They do
not claim current implementation or activation; live status and remaining gates
belong in [`TODO.md`](../../TODO.md).

- [Generic contract architecture](../architecture/generic-contracts.md): common
  authority, type/instance/object separation, upgrades, migration and durability.
- [Publication, instances, and calls](lifecycle.md): authenticated publication,
  instantiation, signed targets, cross-contract calls and bounded delegation.
- [Standard Asset and fees](assets-and-fees.md): public asset semantics and
  contract-defined reservation and settlement.
- [Local contract validation guide](../guides/contracts.md): current developer
  workflow and its explicit non-production boundary.

Accepted rationale and compatibility-relevant history live in
[`../architecture/decisions/`](../architecture/decisions/README.md), not in a
parallel meeting-notes tree.
