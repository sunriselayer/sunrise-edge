# DR-0240: Recurring CI compilation profile

Date: 2026-10-14 (JST)

Status: Accepted bounded compilation choice. Grants no reduced workload,
timeout extension, release acceptance or production performance claim.

## Context

The unchanged compiled recurring acceptance preserves its original eight-link
fixture, configured epoch-8 withdrawals, terminal recovery and encrypted source-free
restoration of all 35 roles. Its repeated history verification can exhaust a
hosted job's finite budget while continuing to make progress. Source results,
failed runs and measured timings belong in [TODO](../../../TODO.md).

GitHub-hosted jobs have a [six-hour execution limit](https://docs.github.com/en/actions/reference/limits).
Increasing `timeout-minutes` beyond that is not a remedy. Moving stages to
independent jobs or continuing a saved partial fixture would change the owning
process-lifetime acceptance and its failure boundary.

## Decision

Only the hosted `recurring-sqlite` job sets Cargo dev and test optimization
levels to 2. Both profiles explicitly retain `debug-assertions = true` and
`overflow-checks = true`. The named curve25519-dalek level 3 override and its
safety checks remain. Ordinary dev/test builds continue at workspace level 1;
the release profile is unchanged.

Remove node-core's redundant named `opt-level = 1` override while retaining its
explicit debug and overflow checks. It then inherits the selected optimization
level. Otherwise a named override takes precedence and silently defeats the
lane's setting. Cargo test inherits dev. These are independent settings under
the [Cargo profile contract](https://doc.rust-lang.org/cargo/reference/profiles.html)
and its [environment overrides](https://doc.rust-lang.org/cargo/reference/environment-variables.html).

Keep the exact group command and selector, all eight-link/epoch-8/35-role
assertions, waits, process restarts, source deletion, refusal controls and
360-minute bound. All seven unconditional owners and the success-only aggregate
remain. No retry, resume, skip or tolerated failure is added.

## Verification and limits

The independent gate contract checks that all six optimization/safety settings
exist only in the recurring job. Mutation controls remove each field or weaken
each safety value and must reject the workflow. The manifest contract retains
the ordinary level, curve override, dev inheritance and explicit safety checks.

Before recording success, observe actual compiler flags and run the original
complete acceptance from the beginning. Record source, compiler/profile,
resource limits, terminal exit and cleanup. A proposed faster profile and
DB/compiler-free contracts do not qualify the real workload. Timing differences
between machines do not establish a production capacity or performance claim.
