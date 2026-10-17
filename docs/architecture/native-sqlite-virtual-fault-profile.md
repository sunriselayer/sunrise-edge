# Native SQLite virtual power and block-error profile

This additional selected Native+SQLite fault profile runs the actual compiled
`runtime-sqlite` test binary inside one disposable Linux guest. Its fault owner
runs outside that guest. The owner kills the QEMU process to remove the guest
kernel, all guest SQLite owners and guest caches together, or inserts a typed
QEMU block error under the live guest's real source COMMIT. It never substitutes
a mocked `SqlBackend` result for a device error.

The profile is Linux 7.2.9, ext4 on a virtio block device and QEMU 10.2.2, with
SQLite's existing WAL/FULL settings unchanged. The backing file uses direct I/O
and honors flushes. A network-free guest has one CPU and 512 MiB memory. It has
no host filesystem mount, host block-device passthrough or provider access.
The initramfs consists of existing pinned Bash/mount, the compiled test ELF and
their inspected dynamic libraries. No guest OS image or package is downloaded.

## Four boundaries

| Case | Actual boundary | Required observation before loss |
| --- | --- | --- |
| `ack` | Guest virtual power loss after successful caller COMMIT acknowledgment | `Committed`, complete SQL/public image, then nonce-bearing acknowledged frame while owners remain live |
| `preack` | Guest virtual power loss after SQLite COMMIT succeeds and before the caller receives the result | Existing `AfterCommit` hook emits its nonce-bearing frame and blocks without checkpointing or closing owners |
| `write` | Source COMMIT encounters an actual virtual-block write EIO | Existing `BeforeDispatch` hook blocks after source mutations; owner verifies the write-only armed graph and releases it; actual SQLite extended COMMIT error must be `SQLITE_IOERR_WRITE` (778) or `SQLITE_IOERR_FSYNC` (1034), recorded verbatim |
| `flush` | Source COMMIT encounters an actual virtual-block flush EIO | Same boundary with a flush-only rule; actual SQLite extended COMMIT error must be `SQLITE_IOERR_FSYNC` (1034) |

For each error case the owner first observes `data -> disk-file`, adds one new
`blkdebug` node with a persistent EIO rule for exactly `write` or `flush`, and
replaces the raw node's file child. It then observes the actual
`data -> fault-debug -> disk-file` graph. A successful QMP command alone provides
no fault evidence. An actual `BLOCK_IO_ERROR` for the selected data node and the
actual extended error from SQLite's real `transaction.commit()` are both required.
The backend's extra observation field and driver are `cfg(test)` only. Production
commit decisions, error mapping, persisted schema and protocol bytes are unchanged.

The virtual device operation and SQLite error stage are separate observations.
Ext4 can buffer a failed block write until SQLite's WAL fsync reports EIO, giving
code 1034 under the write-only device rule. This remains the block-write case;
it does not replace the separate flush-only rule/graph/error case. Unknown SQLite
codes fail qualification rather than being accepted as generic I/O failures.

`SQLITE_IOERR_FSYNC` is the exact fsync error gate. An unexpected extended code
fails this case and preserves the attempt; it cannot be renamed as fsync success.
An interruption during a suspended flush is a distinct optional experiment. It
would need to identify SQLite's actual WAL fsync, rather than an unrelated ext4
journal flush, and is not an extra prerequisite of these four cases.

## Independent cold recovery oracle

The fixture reuses DR-0234's independently fixed target and unrelated object,
nonce, state, receipt and outbox literals. Both nonempty 70 KiB object bodies are
successfully published before the source fault. The owner retains the initial
random 16-byte source identity before the fault. A fresh guest receives that pin
through its kernel command line and reconstructs the complete expected image
from fixed literals and codecs, never from recovered table fields.

Recovery queries the target receipt before choosing any retry. It then requires
exactly the complete initial or complete committed write set over all twelve
structured tables and both blob tables, including currently empty tables. Closed
table and column inventories, ordered rows, nineteen structured rows, three blob
rows, a 96 KiB cell bound and a combined 1 MiB image bound limit observation.
Both previously acknowledged bodies must survive even if the source write set
is absent. Such an immutable orphan is allowed; a partial source write set is
not. Acknowledged and successful-before-ACK cases require the committed outcome.

The four portable collections are enumerated page by page, with exact keys,
descriptors, payloads, namespace/source/fence/sequence token and both complete
bodies checked against independent material. Body checks include two bounded
chunks, canonical object decoding/reencoding and the existing Object-domain hash.

Only after receipt-first reconciliation does the fresh guest advance fence one
to two. A stale fence must refuse. The exact saved target invocation either
refuses as already committed or commits once if the full write set was absent.
Its next replay must leave all SQL/blob rows and public images unchanged. A new
real invocation then updates the existing state at revision one, adds its own
receipt/outbox at fence two, and replays without another mutation. Independent
full images require sequence three, the exact revised state and all original
objects/nonces/receipts/bodies intact. This proves a current writer can perform
new work after cold recovery, beyond a fence-counter update.

## Ownership and attributable evidence

The ignored driver is inert unless its explicit environment profile, exact
kernel command-line case/mode/nonce/source fields, pinned kernel release,
nonce-bound virtio serial and writable `/dev/vda1` ext4 mount all match. It writes
only beneath its private `/data/sunrise-native-ownership-<nonce>` root. Ordinary
test runs neither create a VM nor enter this path.

An external bounded owner retains exact input hashes, QMP replies/events, each
guest's separate raw serial stream, per-case source pin and recovery outcome,
actual child wait statuses, stdout EOF, process/socket absence, cgroup limits,
peak memory and I/O accounting. Every guest, including a failed one, must be
killed, waited, drained and reaped under its existing deadline. Failed attempts
remain immutable; recovery uses an exact independently rehashed copy of each
write/flush fault image, retaining the original image. There is no automatic
cache-flag, filesystem-repair or retry fallback.

The bounded owner uses at most six 128 MiB private images, one copied 19 MiB
kernel, one compressed initramfs capped at 164 MiB, 32 MiB combined raw/serial
logs and 4 MiB terminal metadata. This is below a 1 GiB retained-artifact cap.
Eight sequential boots have at most 150 seconds each including cleanup and
1,200 aggregate guest seconds. The outer owner has 1 GiB memory, no swap,
one CPU, 128 tasks, a 4 GiB gross logical-I/O cap and 5 GiB free-space headroom.
The source/build and actual execution owners retain their own exact approvals,
limits and terminal results; architecture is not an execution receipt.

## Limits

This profile exercises a real guest kernel/cache loss and real virtual block
EIO propagation through ext4 and SQLite. It does not qualify bare-host power,
physical hardware/firmware caches, torn physical sectors, arbitrary media loss,
cross-host distributed failover, production load or provider certification.
Those claims retain separate evidence requirements in M3. Existing SIGKILL,
ENOSPC and actual TLS/business controls keep their separate selectors and
assertions. Passing this profile cannot silently close every M3 requirement.

See [DR-0262](decisions/0262-native-sqlite-virtual-power-and-block-errors.md).
