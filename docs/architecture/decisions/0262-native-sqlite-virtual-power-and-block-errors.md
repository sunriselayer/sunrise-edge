# DR-0262: Native SQLite virtual power and typed block errors

Date: 2026-10-17 (Asia/Singapore)

Status: Accepted for the additional bounded Linux/QEMU/ext4 fault fixture.
Execution results and completion status belong in TODO.md and its evidence.

## Context

DR-0234's positive-body control loses every fixture process after a successful
COMMIT; DR-0260 adds a real replacement local TLS writer. Neither removes a
guest kernel/cache or proves actual storage write/flush errno propagation.
The original M3 selected-profile fault criteria retain those boundaries.

A separate mechanism probe established that the installed kernel boots from a
minimal initramfs and that QEMU's live block graph can be changed to return real
guest write and flush EIO. Mechanism evidence alone says nothing about the
product's COMMIT, acknowledgment, complete write set or recovery semantics.

## Decision

Use the additional [virtual fault profile](../native-sqlite-virtual-fault-profile.md)
for four separately attributed product cases: acknowledged COMMIT guest loss,
successful COMMIT before caller ACK guest loss, real COMMIT write EIO and real
COMMIT flush EIO. Preserve the original process-loss tests unchanged.

Reuse the positive-body fixture's independent literals and complete twelve/two
table and four-collection/body oracles. Retain the random source ID outside the
guest before the fault. A cold guest must reconcile none-or-all by receipt
before retry, preserve both acknowledged immutable bodies, fence stale work,
replay exactly once and accept a genuine new state/receipt/outbox transaction.

Keep all rendezvous and actual extended SQLite COMMIT error observation behind
`cfg(test)`. No production hook, new dependency, unsafe code, schema or protocol
byte change is introduced. A successful graph command is insufficient. Require
the actual block error and the real COMMIT extended code; exact fsync credit
requires `SQLITE_IOERR_FSYNC`.

Use a task-owned, resource-capped owner with no host mount, host block device,
network, download, privileged operation or global VM/host setting. Retain exact
failed attempts, wait/EOF/reap and resource/cleanup observations. Source review
and an attributable bounded execution gate precede qualification.

## Consequences

This adds selected virtual-machine kernel/cache-loss and typed storage-error
coverage without claiming physical hardware or bare-host fault qualification.
An interrupted suspended WAL fsync is optional and would require its own exact
I/O attribution. Existing M3 hardware/media/topology and whole-release claims
are not inferred from this fixture or moved into a public-launch checklist.
