# DR-0171: Partitioned complete repository validation

Date: 2026-10-01 (Asia/Singapore)

Status: Accepted design. Execution evidence and work status are tracked in
[`TODO.md`](../../../TODO.md).

## Context

The user requested CI refactoring after the single validation job repeatedly
dominated delivery time. Extending a serialized job's timeout was only a
temporary diagnostic measure, not a structural solution.

Run `36828823973` reached the new business audit after roughly 66 minutes and
was cancelled at the two-hour job limit. Validation compilation took about
2 minutes 31 seconds, ordinary workspace tests about 24 minutes 57 seconds,
and subsequent completed live gates about 36 minutes 39 seconds. The genuine
DrainSet/history acceptance passed in about 20 minutes 22 seconds. The audit
then ran for 54 minutes 5 seconds without a final result before cancellation.
These are historical observations, not evidence that the audit finished or
that its internal stage was known.

A complete source-equivalent local run did pass, including the genuine
four-store business audit in 1962.34 seconds. CI's slower execution and the
serialized critical path justify partitioning before adding cargo caches or
increasing global job budgets again.

## Decision

Use the nine coverage lanes defined in
[`repository-validation.md`](../repository-validation.md). Keep the complete
serial local entrypoint and a closed, mechanically checked CI dispatch set.
Preserve every existing gate, all required ignored-test selectors and discovery
guards, all-target/all-feature semantics, pinned tools/actions/images, required
fault configurations, runtime bytes and operation deadlines.

Separate ordinary Rust tests from the full `runtime-postgres` package. Separate
genuine lifecycle, drain/history, business-audit and recovery/economics gates.
Each live lane receives its own disposable database and runner. Fixtures that
depend on several phases remain together; do not split their atomic acceptance
into independently green fragments.

Native locked/offline feature-graph inspection showed that selecting only
`runtime-postgres` changed transitive feature unions, not just Tokio signal
support. Preserve the full relevant feature union by selecting the existing
operator and Cloudflare validator packages as anchors, with
`sunrise-edge-cli/usb-hid`. Their ordinary tests intentionally repeat in the
storage lane. This adds bounded work but avoids changing the conditions under
which the existing storage tests ran. Preserve graph-comparison evidence;
all-feature flags alone are not evidence of identical dependency features.

Retain `check` as the required final job. Run it after all required dependencies
regardless of their outcomes, and accept only all-success. Explicitly test
failed, cancelled, skipped, missing and unknown results. Test unknown dispatch
groups, missing CI database configuration and unique coverage membership.

The partition does not introduce path filters, allowed failures, nightly-only
safety coverage, release-mode test substitution or shared mutation-prone build
artifacts. Root-level README scope remains unchanged.

## Consequences and limits

Fast feedback no longer waits for the slowest end-to-end fixture, and database
faults cannot disturb unrelated live lanes. Cold compilation is repeated on
independent runners; aggregate runner cost can increase even when wall-clock
time falls. Do not claim a measured speedup from static configuration alone.

The business-audit lane is provisionally the critical path. An estimate of
60-75 minutes including cold build is not an established duration or proof of
progress. Finite per-lane budgets, retained stage diagnostics and real final-head
CI results remain necessary. A test exceeding its own lane budget requires
diagnosis; it must not become an allowed failure or a skipped gate.

This is CI orchestration only. It does not complete Delivery 3, persistent
incoming-validator import, readiness/Seal/activation or production auditing.

## Integration decision, 2026-10-01

PR #241 concurrently replaced the previous complete CI entrypoint with only
Rust formatting, Clippy and workspace tests under a 25-minute job budget. The
user explicitly selected this decision's complete nine-lane policy when the
two workflow changes conflicted. Preserve the merged claim crate, dependencies,
custody-purpose encoding and genesis admission; resolve the workflow overlap
without discarding that separate functionality or removing live/fault/provider
checks.

Workspace membership and dependency changes require a fresh resolved-feature
comparison and combined-head validation. A successful run before this merge
does not establish the changed workspace's feature parity or acceptance.

## Historical execution evidence

Run `36849428430` at `039174e1dd2a3feef13caef0f7c8bb88fe2976a2` completed all
nine lanes and the final required `check` successfully. Creation-to-completion
elapsed time was 50 minutes 10 seconds; the longest job, business audit, took
49 minutes 26 seconds, including its genuine test in 2871.49 seconds. This is a
complete result, unlike the earlier incomplete 120-minute timeout, not a speedup
ratio between two comparable successful runs.

Summed job elapsed occupancy was 126 minutes 18 seconds. That is not a billed
runner-cost measurement or evidence of cost savings. The subsequent main
integration is a different immutable head and requires its own complete
validation. Current acceptance remains tracked only in `TODO.md`.
