# DR-0225: Observed acquisition floor and current binding

Date: 2026-10-11, Asia/Tokyo

Status: Accepted human policy and bounded source design. Acquisition code,
complete protocol fit, reviewed runtime binding and invocation admission remain
pending; this decision qualifies no acquisition or runtime result.

## Decision and scope

The current direct human request resumes ordinary Native+SQLite implementation,
asks to resolve the acquisition blockers and twenty open TODO groups, and
selects observed monitoring with stop before free space drops below 5 GiB.
The former unanswered floor choice is resolved. It does not grant a strict
full-duration global-space guarantee or remove any other release prerequisite.

This policy applies only to the separately admitted acquisition of exact missing
locked Rust inputs from official sources, without package code execution. It
creates no global-cache substitution, old-home repopulation, target replacement,
resolver change, global-resource change, live PG, custody or deployment authority.
Keep the same retained M4 target and every original acquisition boundary.

## Space measurement and reserves

Measure available bytes as `f_bavail * f_frsize` through the already-held
acquisition destination directory descriptor, with its original attachment and
filesystem binding retained. Use checked nonnegative integer arithmetic; invalid
statistics, zero fragment size or an observation error refuse. Do not substitute
`/tmp` or `f_bfree`. Bind every staging, payload and evidence writer to that
filesystem, or independently guard each actually written filesystem.

Retain the full 32 MiB payload reserve through actual writer release, plus
16 MiB for bounded metadata, evidence and reconciliation. Refuse at available
bytes less than or equal to:

```text
5,368,709,120 + 33,554,432 + 16,777,216 = 5,419,040,768 bytes
```

Neither receipt of network bytes nor completion of a buffered write refunds the
payload reserve. Pending writes and concurrently retained staging copies must
fit the original ownership/storage accounting; reserves are not extra body or
I/O allowances and do not prove a filesystem-allocation ceiling.

## Monitoring, sticky refusal and owned stop

Start monitoring before the first acquisition write and retain it until every
owned writer is actually released. Target checks every 100 ms and check fresh
space before every create/write, including normal evidence and diagnostics.
Record actual observation times and gaps; the interval is not a scheduling bound.

A threshold refusal, monitor error or the original deadline sets an irreversible
stop latch. No further normal create/write or network payload write is allowed.
Do not retry, replace inputs or force failure-report writes after refusal. Retain
existing unqualified residue and report incomplete evidence if a report cannot
be safely written.

Stop only exact ownership-proven workers or session members under the existing
bounded-stop contract, never unrelated processes or broad groups. Reconcile
actual termination, pipes, owned descendants and ownership records. A signal
request, cached process status or timeout is not actual release or success.
Termination, complete readback, independent review and actual release must all
fit the original single 300-second first-read-through-release deadline; polling
and reconciliation never reset or extend it.

## Unchanged limits and assurance

Keep 128 MiB gross data I/O, 32 MiB total network body, 16 MiB per file, 700 files
and the human-authorized 256 KiB evidence cap. Exactly locked missing inputs,
source restrictions, held-read/stamp/EOF requirements and the same target remain
unchanged. This does not amend the separate native A/B build admission or limits
in [DR-0213](0213-native-release-artifact-evidence.md).

This is conservative observed monitoring and early refusal, not a reservation
or guarantee against unrelated abrupt writers, delayed allocation, kernel stalls
or scheduling pauses. If observed free space nevertheless falls below 5 GiB,
report a floor breach/failure, not successful prevention. Actual full acquisition
capture/accounting/terminal fit, different review, root binding and invocation
admission remain separate; an accepted policy is not an admitted protocol.

## Source provenance and adoption

The preceding whole-current SOURCE approval belongs only to exact snapshot
`135f4c296d38b92b7e812786c75da90b85910fb6`. It does not cover this documentation
delta or any later acquisition implementation. This delta requires a different
implemented-source review and root adoption. Preserve historical failed attempts,
expired windows and prior scoped approvals; change no TODO checkbox or release
status. Current progress remains in [TODO.md](../../../TODO.md).
