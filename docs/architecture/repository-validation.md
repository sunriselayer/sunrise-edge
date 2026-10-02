# Repository validation

Persistence is a capability contract, not a PostgreSQL requirement. There are
two explicit validation profiles. [DR-0172](decisions/0172-storage-neutral-required-validation.md)
supersedes [DR-0171](decisions/0171-partitioned-repository-validation.md)'s
every-PR PG policy while retaining its complete tests.

The closed execution plans in `scripts/ci-gates.sh` own prerequisite profiles,
lane membership and ordered action IDs. `scripts/ci-execution.sh` owns the
literal recipes and exact ignored-test discovery/execution. The entrypoint
only parses a known selection and dispatches that plan: no evaluated command
strings or provider auto-selection. `required`, `full` and isolated lanes
share these owners; `full` deliberately preserves its serial workspace feature
union rather than concatenating the isolated lanes. Independent fixed expected
plans and command baselines check the actual dispatch, including failures
inside a recipe. Workflow jobs and success-only aggregates remain separate
consumers, not a second definition of gate execution.

## Required storage-neutral checks

Every PR and main update runs these four unconditional lanes:

| Lane | Required coverage |
| --- | --- |
| `lint` | Workspace/orphan-file formatting, all-target/all-feature Clippy, independent dispatch/mutation contracts and diff hygiene |
| `rust-tests` | All nonignored workspace targets/features except `runtime-postgres`, including core/SDK/CLI, memory and file-backed SQLite tests, plus the exact SQLite inventory fixture |
| `portable-tools` | All independent protocol vectors, DB-free soak CLI argument tests and all four Deno/Vercel/Supabase/AWS adapter suites |
| `cloudflare` | Pinned release WASM and canonical oracle, locked npm dependencies and the complete type/lint/workerd suite |

Run the same complete required set locally:

```bash
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
```

No database service is required. The default refuses supplied PG URL/fault
configuration: select the explicit PG/full profile instead of accidentally
claiming a partial PG run. Common cryptographic, paid execution, causal replay,
Freeze/DrainSet and authority controls still run. SQLite reopen/fencing and
real four-validator SQLite HTTP tests are not replaced by mocks. All PG targets
still compile under full-workspace Clippy.

The required workflow has no path filters or conditional/tolerated failures.
Stable `check` runs with `always()` and accepts explicit success from exactly
these four dependencies. Missing, failed, cancelled, skipped and unknown
results are errors.

## Explicit PostgreSQL acceptance

The separate `postgres checks` workflow is manually dispatched for the selected
branch/tag. Its independent `postgres-check` requires all five lanes:

| Lane | Retained acceptance |
| --- | --- |
| `pg-storage` | Runtime PG targets/features and all six real crash/disk/WAL/connection/backup/PgBouncer configurations |
| `pg-lifecycle` | Genuine credential-isolated FastVote and compiled-CLI contract lifecycle/Freeze/frontier |
| `pg-drain-history` | Genuine complete DrainSet/member/ordered-history CLI acceptance |
| `pg-business-audit` | Genuine causal audit, cache continuation, reopen and corruption/source-fact refusals |
| `pg-recovery-economics` | Catch-up, ordered economics/capacity, PG inventory and both bounded recovery smoke phases |

Each live lane owns a separate runner/disposable PG service. Faults cannot
strike another lane's DB. Assertions, fixture sizes, operation deadlines,
debug assertions, tool/action/image pins and storage semantics are unchanged.
PG storage preserves the existing operator/Cloudflare/claim feature anchors
and CLI USB-HID; their ordinary tests intentionally repeat to preserve native
feature unions. Repeat feature comparisons if dependencies/membership change.

All nineteen ignored fixtures remain accounted for: one required SQLite case
and eighteen explicit PG cases. Exact discovery guards reject a misspelled or
zero-test selector. Independent dispatch baselines verify the four-lane
default and the retained full suite rather than comparing two reduced lists.

To run the previous complete serial extended suite, explicitly configure a
disposable PG URL and the desired real fault configuration, then run:

```bash
./scripts/check-all.sh --full
```

Missing URL makes `--full`, every PG group, and explicit PG inventory/smoke
entrypoints fail before checks, even outside CI. An unrun or unconfigured PG
suite is never successful acceptance. Report which real fault flags/images
were supplied; a URL alone is not evidence that all fault rehearsals ran.

PG implementation/dependency changes and PG deployment/release claims need
fresh full PG evidence at the selected source identity. Common `check`
success does not supply it. Protocol/CLI changes need focused integration
verification proportional to impact; the PG lifecycle/cache/restart scenarios
are valuable composition checks, not redundant SQLite unit tests.

## Evidence and provider boundaries

Record executed source identity, actual completion, selected profile and
unrun checks in reviews. Parallelization/fewer default jobs alone do not prove
a measured wall-clock or billed-cost improvement. This frequency change
explicitly removes automatic whole-PG integration on every PR.

Local DO workerd tests do not certify a real Cloudflare deployment. D1 is not
implemented by changing CI. Every supported durable profile still needs its
own atomicity, ambiguity, fencing, replay/restart and blob/outbox conformance.
No provider DB/replica becomes quorum authority.

Readiness, cut/import, Seal/activation, Delivery 3, production provenance and
security review remain distinct. Current status belongs in
[`TODO.md`](../../TODO.md), not README or this architecture reference.
