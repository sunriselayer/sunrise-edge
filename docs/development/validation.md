# Local validation and build profiles

Install adapter dependencies with `npm ci --prefix adapters/cloudflare-workers`,
then run `./scripts/check-all.sh` for the unconditional storage-neutral gate.
The seven required owners cover style, native Rust/SQLite, portable adapters,
the embedded Cloudflare validator, core recurrence, readiness SQLite and
recurring SQLite. They do not require a PostgreSQL service.
Explicit PostgreSQL acceptance remains required for affected storage/schema
changes and provider claims; it is not restored as an every-PR prerequisite.
Current acceptance results and pending work belong in [TODO.md](../../TODO.md).

## Owning fixtures and observation evidence

Business fixtures keep genuine signing, genesis, quorum and execution with their
owning tests. Shared test infrastructure provides only reader capabilities,
publication counters and complete portable observation; see
[test observation contracts](../architecture/test-observation-contracts.md).
Direct versus prepared completion compares complete actual persisted rows and
referenced bodies, not merely matching outputs or a selected receipt. Independent
backend tokens are local continuity evidence, not cross-store identity.
Replay/source audit and verified cut/import are different derivations with
their own verifiers; do not hide their legitimate differences behind a universal
normalizer or a universal fixture.

## Signature-heavy tests

Genuine multi-validator reconstruction deliberately verifies real signatures,
original receipts and full state/body closure. It does not substitute fabricated
rows or a mock result for the changed authority boundary.

The workspace uses one named-package dev override: `curve25519-dalek` at
`opt-level = 3`, with `debug-assertions = true` and `overflow-checks = true`.
Cargo's test profile inherits this dev override. Workspace code remains at its
normal development optimization level, and release settings and dependency
versions are unchanged by the override. It speeds curve arithmetic rather than
removing tests, assertions, validation or refusal paths. The mechanism and
inheritance are defined by the [Cargo profile reference](https://doc.rust-lang.org/cargo/reference/profiles.html#overrides).

For focused iteration, run the owning tests before the complete gate:

```sh
cargo test -p consensus --lib readiness
cargo test -p node-core --lib conditional_readiness_
cargo test -p sunrise-edge-operator --test conditional_readiness_sqlite
```

Timing comparisons must use the same selectors and assertions and separately
report build time, test time and whole-gate time. A focused local speedup is not
a hosted-CI, provider, load or production performance claim. Keep Cargo's shared
target under one build owner; branch switches that expose stale package outputs
require a narrow package rebuild, not deleting the repository or its databases.
