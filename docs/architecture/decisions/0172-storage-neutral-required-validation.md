# DR-0172: Storage-neutral required validation and explicit PostgreSQL acceptance

Date: 2026-10-01 (Asia/Singapore)

Status: Accepted. Supersedes DR-0171's every-PR PostgreSQL requirement and
default full-suite policy, not its retained tests or historical evidence.
Implementation and exact-head acceptance belong in `TODO.md`.

## Context

DR-0151 makes persistence a capability contract, not a mandatory PostgreSQL
product. The embedded SQLite-backed DO host has its own local execution and
restart/replay tests. D1 remains a provider candidate, not an implemented or
certified authoritative store. A PG passing result cannot certify another
backend.

DR-0171 retained all regression work on every PR. The integrated PR245 run
completed in 49m41s; the genuine PG business-audit job alone took 49m24s.
The user then explicitly requested a lighter gate consistent with optional
PostgreSQL. This changes required execution policy, not protocol semantics.

The expensive scenarios are not all PG-specific: they also compose signed
multi-validator history, compiled CLI replay and closed business comparison.
Do not call their removal from the routine gate equivalent end-to-end coverage.

## Decision

Every PR and main update runs four unconditional required lanes: formatting/
Clippy and dispatch contracts; ordinary Rust/SDK/CLI tests and real SQLite
inventory; portable vectors/adapters; and the pinned WASM/Cloudflare tests.
The stable `check` requires explicit success from all four. No database service,
path filter, allowed failure or skipped required lane is introduced there.
Existing nonignored core authentication, causal reconstruction, Freeze/DrainSet,
economics, exact-replay and negative controls remain mandatory. Add compact
DB-free coverage of the production snapshot collector with real SQLite and
canonical source-row corruption refusal in the genuine core reconstruction
fixture. These do not replace the full compiled-CLI cache/restart composition. Runtime PG
targets still compile under full-workspace all-target/all-feature Clippy.

Keep the five complete live PG lanes in a separate explicitly dispatched
`postgres checks` workflow with its own success-only `postgres-check`.
Keep all six real fault configurations, isolated disposable services, native
feature anchors, fourteen protocol fixtures and the four PG auxiliary cases.
No assertions, timeouts, images, bytes, fixture sizes or test implementation
change. The additional SQLite fixture remains in the routine gate.

`./scripts/check-all.sh` is the complete required storage-neutral local gate.
`./scripts/check-all.sh --full` explicitly runs the retained complete extended
suite in its previous serial order. All grouped entrypoints remain closed.
The default required gate refuses supplied PG URL/fault configuration; callers
must explicitly choose the PG/full profile. Requesting the full or any PG gate
without a live URL fails before invoking checks, even outside CI; absence never
counts as PG acceptance.

PG-specific code/dependency changes and any PG deployment/release claim need
fresh selected-source full PG evidence, obtained explicitly by the maintainer.
Routine `check` success is not that evidence. Generic protocol changes still
require focused integration checks proportional to their impact. The manual
PG workflow is not a new nightly, backend readiness certificate or substitute
for independent review. Other durable adapters need their own real restart,
fencing, ambiguity and atomicity conformance before operational claims.

## Consequences

Routine delivery no longer waits for PG fault/CLI-history/audit/soak rehearsals.
The actual new critical path must be measured; no runtime or billed-cost
reduction is inferred from configuration alone. Full PG integration regression
is no longer automatic on every change, an explicit coverage tradeoff accepted
to keep PostgreSQL optional and functional work moving.

This does not finish cut/import, readiness, Seal, activation, Delivery 3, D1
support or production qualification. Keep these distinct in TODO and reviews.

## Reference

The separate explicit workflow uses GitHub's
[workflow_dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatch)
event. It must be present on the default branch to be manually dispatched;
dispatch selects a branch or tag, whose actual source identity must be retained
with the test results. It is not branch-protection success from an unrun suite.
