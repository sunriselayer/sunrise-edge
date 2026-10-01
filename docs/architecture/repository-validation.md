# Repository validation

The validation contract is one complete set of checks, not one runner or one
database. [`DR-0171`](decisions/0171-partitioned-repository-validation.md)
separates independent checks without reducing their coverage.

## Entrypoints and coverage

`npm ci --prefix adapters/cloudflare-workers` followed by
`./scripts/check-all.sh` remains the complete serial local entrypoint. CI
dispatches the same closed gate set in independent lanes. Unknown lane names
are errors. A live lane must refuse to run in CI without its PostgreSQL URL;
DB-free checks do not need an artificial database to run.

| Lane | Required coverage |
| --- | --- |
| Formatting and lint | Workspace and explicit orphan-file formatting, all-target/all-feature Clippy, dispatch coverage checks and whitespace hygiene |
| Ordinary Rust tests | All nonignored workspace targets/features except the separately executed `runtime-postgres` package, plus the complete SQLite inventory fixture and operator check |
| PostgreSQL storage | All `runtime-postgres` targets/features, existing operator/Cloudflare feature anchors, and required crash, data-disk-full, WAL-full, connection-exhaustion, backup/restore and PgBouncer configurations |
| PostgreSQL lifecycle | Genuine FastVote, credential isolation, compiled CLI, physical/logical contract lifecycle and Freeze/frontier checks |
| PostgreSQL drain and history | The entire genuine DrainSet/member/ordered-history fixture and compiled CLI acceptance |
| PostgreSQL business audit | The entire genuine causal reconstruction, cache/resume, reopen and corruption-refusal acceptance |
| PostgreSQL recovery and economics | Remaining certified catch-up, offline/ordered economics and capacity regressions, complete PG inventory, and both bounded smoke phases |
| Portable checks | Every independent JavaScript vector check, the DB-free soak CLI self-test and all four portable adapter suites |
| Cloudflare checks | Pinned release WASM build and oracle generation, locked npm installation and the complete adapter type/lint/workerd suite |

The ordinary-test partition must not silently remove a previously live
PostgreSQL-dependent test. Package selection preserves all-target/all-feature
coverage. Exact ignored-test discovery guards remain in place; a misspelled
selector must not become a green run of zero tests. The dispatch regression
checks bind the workflow lanes to the complete local entrypoint and verify
unique membership of required gates and ignored selectors.

The storage lane also selects the existing `sunrise-edge-operator` and
`sunrise-edge-cloudflare-validator` packages and the
`sunrise-edge-cli/usb-hid` feature. Their ordinary tests intentionally repeat:
resolved native dependency graphs showed that a PG-only selection reduced
Tokio, futures, libc, smallvec and zeroize features. These anchors preserve the
workspace feature union without a new binary-execution framework or dependency.
The ordinary-test lane excludes only `runtime-postgres`; all its other package
targets and features remain covered. This deliberate bounded duplication does
not duplicate the required ignored-selector dispatch.

## Isolation and required result

Each live CI lane owns an independent runner and disposable PostgreSQL service.
No lane stops, fills or exhausts another lane's database. Build targets and
generated validator artifacts are runner-local. Runtime source, canonical
bytes, assertions, operation deadlines and debug assertions do not change.

The final required check retains the name `check`. It runs after every lane,
including unsuccessful dependencies, and accepts only an explicit `success`
for every required dependency. Missing, failed, cancelled and skipped results
must refuse. This is deliberately stricter than treating a skipped dependent
job as completion; see the official [job dependency documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idneeds)
and [needs result context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#needs-context).

No path-based test skipping, permitted failure, release-profile substitution,
new cache dependency or nightly-only displacement is part of this partition.
Every pull request and main update still requires the complete regression set.
Per-lane job budgets are finite and separate from unchanged operation deadlines.

## Evidence boundary

Parallelization removes serial waiting; it does not prove a test is unstalled,
reduce the work inside one fixture, or establish a throughput/recovery SLO.
The actual slowest lane and total runner cost must be measured after execution.
Static dispatch checks are not a substitute for running the real lanes.

This regression gate is not release provenance or production readiness.
Dependency/toolchain provenance, SBOMs, reproducible releases, protected review
policy, real-provider conformance and independent security review remain
separate obligations. Current implementation and acceptance status belong only
in [`TODO.md`](../../TODO.md).
