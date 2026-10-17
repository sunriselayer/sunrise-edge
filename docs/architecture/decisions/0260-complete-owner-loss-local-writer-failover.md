# DR-0260: Complete-owner-loss local SQLite writer failover control

Date: 2026-10-17 (Asia/Singapore)

Status: Accepted for the selected local process fault fixture. Execution
results and completion status belong in TODO.md and its attributable evidence.

## Context

The original compiled direct-TLS SIGKILL fixture deliberately retains parent-side
SQLite capabilities. It proves generation-two refusal after generation-three
startup, but leaves connections alive across serving-process death. The positive
blob backend control separately kills its sole child owner after real COMMIT;
it verifies full SQL/portable/blob reconciliation without exercising an actual
replacement TLS writer accepting new protocol business.

M3 retains actual host/power/storage/fsync faults and real writer failover under
DR-0236. Combining existing results does not silently prove those missing fault
boundaries or a supported overlapping-writer procedure.

## Decision

Keep the original retained-handle SIGKILL selector and every original assertion.
Add a separately selectable Linux control using the same actual authored and
inspected four-validator genesis, database/blob files, compiled production hosts,
TLS credentials and CLI:

1. Complete the first real certified paid transfer and verify its independent
   signature, certificate, availability, object, nonce and receipt oracles.
2. Capture all twelve structured SQL tables and both blob tables through bounded
   read-only SQLite-owned connections. Explicitly roll back and close every
   observer before returning owned values. Capture the existing four portable
   collections and referenced immutable bodies. Check `/proc/self/fd` symlink
   targets for current-case main/WAL/SHM files, including deleted names, without
   opening those locked inodes. Retain no parent SQLite handle.
3. Kill and reap each owned serving PID with actual SIGKILL, using the existing
   shared absolute deadline. No database is reopened until every PID was reaped.
   Reconcile all rows and portable/blob values before replacement startup.
4. Start four genuinely distinct replacement processes through the existing
   offline-confirmed startup owner. Physical exclusion is the already observed
   death of every old writer. Advance each file's fence exactly two to three;
   compare the complete raw images allowing only that metadata field to change.
5. Replay the original saved certified request. Prove the exact result and every
   raw SQL/blob row remain unchanged, alongside the existing portable oracle.
6. Submit a fresh paid transfer with a fresh request ID and the next nonce. Spend
   the first settlement's refund Coin with its existing independent Write fee
   source. Reuse the original stopped-rotation business verifier, preserving its
   real signature/both-quorum and exact effect/object/receipt/nonce assertions.
   Fresh receipt replay must leave all twelve/two table images and the portable
   collections/bodies unchanged. Ordinary tail stop must preserve that final cut.

The raw observer has a closed column/table inventory, ordered complete rows,
1,024 rows per database, a 512 KiB cell cap and a combined 16 MiB image cap for
one structured/blob pair. It checks bounds before allocation/copy, rejects REAL
values and unknown/missing tables, and exposes no production raw connection API.
It does not compare SQLite pages, WAL lengths or mutable filesystem timestamps.
The existing small-object business fixture stores object bodies inline, so its
referenced-blob closure can be empty. Complete enumeration of that empty closure
is not positive referenced-blob fault evidence. Keep the existing separate
`positive_blob_after_commit_total_owner_death_preserves_complete_publication`
and referenced-blob ENOSPC controls, with their nonempty literal body/oracles;
this slice neither removes nor substitutes for those controls.

## Scope and acceptance

This is real **local process writer failover after total connection loss**. It
uses the selected Native+SQLite single-host profile and no provider, VM image,
mount, raw device, new dependency, unsafe Rust, schema or protocol change.

It is not a power interruption, lost device-cache flush, torn write, actual
fsync/media error, cross-host takeover, malicious-root isolation, distributed HA
or whole M3 completion. These selected-profile technical fault requirements remain
open in M3; D07 real-topology rehearsal does not replace them. TLS trust rotation
and its fresh-business result retain their own existing control/evidence.

Before qualification, compile and run the new selector, the original retained-
handle selector and the original stopped-trust-rotation selector through the
actual owning executable/host/CLI bindings; run strict owning Clippy/formatting,
the unchanged required repository gate and applicable final-source CI. Report
actual execution separately from the accepted design.
