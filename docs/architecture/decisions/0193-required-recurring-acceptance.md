# DR-0193: Required recurring acceptance over isolated owners

Date: 2026-10-05 (Asia/Singapore)

Status: Accepted. Extends DR-0172's storage-neutral required gate; does not
revise its PostgreSQL acceptance split or retained tests. Supersedes neither
DR-0171 nor DR-0172, which remain historical record.

## Context

PR269 and PR270's `rust-tests` job were each cancelled at exactly the 60
minute timeout while node-core's real recurring-successor coverage was still
executing. Locally, the parent measured the complete node-core library
(1174 tests, no fixture reduction) at 2870.48s (47m50s). The workspace lane
also owns expensive operator-process tests. Isolate two long functional
cases: the genuine seven-epoch recurring SQLite successor handoff in
`successor_recurring_delay.rs`, and the compiled multi-process
`conditional_readiness` CLI/SQLite acceptance case in
`apps/operator/tests/conditional_readiness_sqlite.rs`. Neither is a
benchmark; both are required correctness coverage that must keep running on
every PR, not be dropped to fit a shared timeout. The standalone recurring
case has separately been measured at roughly 93 minutes in an earlier run
whose build settings were not retained. A profile change is not a verified
explanation for the difference. Any new per-case budget must stay above both known
figures with real margin, not an unmeasured undersized guess.

## Decision

Both cases become `#[ignore]`d and move to two new distinct, unconditional
(never PostgreSQL-gated) required jobs: `core-recurrence` and
`readiness-sqlite`, each with its own finite `timeout-minutes` budget (120
each, conservatively above both the 47m50s whole-library measurement and the
93-minute earlier standalone figure) independent of the ordinary
`rust-tests` lane's unchanged 60-minute budget.
`scripts/ci-gates.sh` records their exact package/target/selector in a new
closed `CI_REQUIRED_EXTENDED_CASES` registry, parallel in shape to the
existing `CI_FASTVOTE_PG_CASES`/`CI_AUXILIARY_IGNORED_CASES` registries.
One registry-driven dispatcher, `ci_run_required_extended_group` in
`scripts/ci-execution.sh`, owns every row for its named group, reusing the
existing `ci_run_exact_ignored_test`/`ci_require_exact_ignored_test` helpers,
never a second discovery or execution engine. It rejects an unknown or empty
group, and a group whose rows duplicate one exact selector, before running
any test. Discovery itself now lists with `--ignored --exact --list` and
requires exactly one matching line; zero or more than one both fail the
gate, closing the previous presence-only grep's gap. The `required` and
`full` local entrypoints each run every registered case exactly once as part
of their own serial invocation; each case's matching standalone group runs
that same case exactly once when selected on its own, never twice within one
invocation. `check` in `.github/workflows/ci.yml` now requires six
unconditional jobs instead of four; the stable fan-in name, `always()`
dependency and fail-closed `scripts/check-ci-results.mjs` contract are
unchanged.

All nineteen previously retained ignored fixtures (one required SQLite
inventory case, eighteen explicit PostgreSQL cases) are untouched. The two
newly ignored cases are additional, bringing the total accounted-for ignored
fixture count to twenty-one.

PR270, the dependent host branch, already implements a further test building
on the baseline readiness case
(`compiled_registered_replacement_and_recurring_successor_hosts`), but that
test does not exist on this core branch. This gate never infers a selector
for a test absent from the branch it runs against; `CI_REQUIRED_EXTENDED_CASES`
here lists only the baseline case already present. That host-only recurring
process is not planned as a second row under the existing 120-minute
`readiness-sqlite` owner: it needs its own distinct, unconditional third
job (parallel in shape to `core-recurrence`/`readiness-sqlite` but not
present in this registry) with a budget of up to 360 minutes, sized once the
real selector and its measured cost exist here. Adding it is: add
`#[ignore]` to that test, append one row to `CI_REQUIRED_EXTENDED_CASES`
under a new third group, add that group to `CI_EXECUTION_PLANS` and the
`required`/`full` action lists, and add its matching workflow job and
`check` dependency, mirroring exactly how `core-recurrence`/`readiness-sqlite`
were added. The independent fixed dispatch expectations in
`scripts/test-ci-gates.mjs` must also change; the registry cannot certify itself.

### Dependent host amendment, 2026-10-05

On the dependent host branch the already-existing
`compiled_registered_replacement_and_recurring_successor_hosts` now has the
third unconditional owner `recurring-sqlite`, a separate job with a finite
360-minute upper budget. This completes the registry, `#[ignore]`, action-plan,
workflow and independent fixed-mock changes above. Local `required` and `full`
each run it exactly once; ordinary Cargo cannot silently replace the owner.
The host branch consequently has seven required jobs and twenty-two accounted
ignored cases (the original nineteen plus three required extended cases).
No PostgreSQL service, optional profile, skipped result or tolerated failure is
introduced. Full inventory duplicate identity validation is across groups as
well as within a group.

The upper budget is not measured completion evidence. Record the complete
compiled run's actual wall time and cold CI build before claiming Delivery 3;
the earlier interrupted logs do not count. The preceding six-job descriptions
record the core-only decision and remain its historical context.

## Consequences

The ordinary `rust-tests` budget remains 60 minutes; record its actual cost
after verification rather than assuming that separation alone restores a
particular runtime. The two heavy cases still run unconditionally on every
PR, just under their own budgets instead
of sharing the monolithic one. CI now has six required jobs instead of four;
`TODO.md` and PR descriptions should reflect this when referencing required
gate membership. A future case added to either new lane needs its own
measured budget check before being folded into the shared 120-minute figure
chosen here from the available evidence; the parent should confirm each new
lane's real wall-clock time against its budget once CI results are in.

## Reference

DR-0172 remains the controlling record for the required/PostgreSQL split;
this decision only adds required-lane structure underneath it.
