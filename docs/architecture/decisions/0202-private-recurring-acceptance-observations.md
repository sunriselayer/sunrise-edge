# DR-0202: Private observations of genuine recurring acceptance work

Date: 2026-10-07 (Asia/Singapore)

Status: Proposed instrumentation contract, pending exact-source independent
review and required acceptance. This is not a performance or release claim.

## Context

The required SQLite acceptance intentionally follows a genuine original-root
history, the installed unbonding delay, changed committees and the actual
withdrawal unlock. It repeatedly exercises full reconstruction, compiled
operators and real local hosts. A long wall-clock duration alone does not
identify the work that should be improved. Caching a bare epoch/height result or
shortening the delay would weaken the evidence rather than explain the cost.

## Decision

Keep one test-private observation owner in
`apps/operator/tests/support/acceptance_timing.rs`. It has a closed stage enum,
an optional actual public `Epoch`, a monotonic `Instant` and best-effort stderr
records. There is no general tracing framework, new dependency, protocol clock,
environment switch, background task, persisted cache or shared authority token.

Instrument coarse owning seams in the existing compiled SQLite readiness,
Seal, first-successor and recurring acceptance. Recurring observations separate
freeze/drain, full history through the cut, cut export/import/readiness, Seal,
full history through Seal, successor activation, the actual fourth-host restart
and the computed terminal unlock. The enclosing epoch observation includes
other receipt, serving and refusal checks; nested durations must not be added
to the enclosing duration as independent work.

Only stage labels, actual public epoch values and elapsed milliseconds enter
the new records. Before an actual epoch is available, emit `epoch=-`, not an
invented epoch zero. Do not include commands, paths, keys, request IDs, payloads
or artifact contents. Existing fixture diagnostics have their existing owner;
this change does not claim to sanitize all older output.

Start and scope-end records are observations, not verdicts. During a Rust panic
unwind the span emits `observation=unwind`, never a normal scope-end record.
Ignore ordinary diagnostic write errors. The real test result, every existing
assertion and the process/CI exit status remain the acceptance authority.

Enable `--nocapture` only for the existing required
`compiled_registered_replacement_and_recurring_successor_hosts` selector so
hosted CI exposes the timing observations while work is running. Preserve all
seven required gate owners, every selector, all selected PostgreSQL cases and
all other capture flags. No path-filter skip or acceptance-cache reuse follows
from these observations.

## Invariants and verification

- Leave every original production statement, epoch bound, configured delay,
  signature/history/receipt verification and assertion in place.
- Retain five-member quorum, real restart/fencing, stale-domain refusals,
  full original-genesis reconstruction and terminal withdrawal checks.
- Test exact record framing, unavailable epoch, an ordinary broken-pipe writer
  and genuine panic unwind. Test the registry's exact selectors/capture flags.
- Run owning Rust checks and complete required acceptance on committed source;
  an observation-only local test is not an exact full-gate pass.
- Compare future optimization measurements only on equivalent selectors and
  assertions, reporting build, test and whole-gate times separately. Diagnostic
  output has a cost; this slice claims attribution, not a speedup.

Actual execution evidence and remaining optimization work belong in
[`TODO.md`](../../../TODO.md), not README or a second readiness tracker.
