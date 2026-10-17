# DR-0266: Independent-anchor virtual fault profile

Date: 2026-10-17 (Asia/Singapore)

Status: Accepted for a separately named local virtual fault profile.

## Decision

Keep DR-0262's ordinary four cases and their literal full-state/body oracles.
Add an ignored Linux child driver for `native-sqlite-qemu-anchored-v1` using the
same source implementation and two independent task-owned virtio/ext4 devices.
Source and immutable-body files reside under `/data`; configured authority and
its separate lease reside under `/authority`, outside the source tree. Both
nonce-bound device serials, exact kernel, mounts and closed kernel command line
must match before any writable test path. A normal invocation is inert.

The product order remains authority Pending COMMIT, source COMMIT, independently
verified authority finalization COMMIT, then caller value release. Add only
instance-owned `cfg(test)` one-shot rendezvous and actual SQLite extended-error
observations immediately around authority prepare/finalize `tx.commit()`. Hooks
produce bounded nonce-bearing frames and await release; they return no synthetic
error or result. Existing source BeforeDispatch/AfterCommit hooks and actual
source COMMIT error observation remain unchanged. No new dependency, unsafe,
production fault option, protocol format, storage policy or repair is introduced.

## Nine actual owning boundaries

| Case | Exact cut | Required cold behavior |
| --- | --- | --- |
| Acknowledged | Caller returned Committed after finalization | Exact new source and acknowledged authority, no Pending; fresh fence/replay/new work |
| Prepared | Existing BeforeDispatch, after durable Pending and before source COMMIT | Exact old source and candidate Pending; repeated real anchored-factory refusal, no clearing/fence/value |
| Source committed | Existing AfterCommit, before authority finalization | Exact new source and candidate Pending; actual anchored open verifies bodies and finalizes that candidate |
| Source write / flush | Real source SQLite COMMIT device EIO after durable Pending | Complete source none/all; old plus Pending stops, exact new reconciles |
| Prepare write / flush | Real authority prepare SQLite COMMIT device EIO | Source remains old without dispatch; coherent old authority permits continuation, candidate Pending requires stop |
| Finalize write / flush | Real authority finalize SQLite COMMIT device EIO after source success | Source remains new; coherent Pending or acknowledged new resumes through the existing reconciliation |

Every EIO case requires the actual observed COMMIT phase and extended code,
selected-device BLOCK_IO_ERROR, installed block graph and typed rule. Write-only
block errors accept actual SQLITE_IOERR_WRITE or SQLITE_IOERR_FSYNC because ext4
writeback can surface at fsync. Flush-only credit requires SQLITE_IOERR_FSYNC.
Unknown codes, requested flags, successful QMP configuration, generic statement
failure or a returned Committed do not qualify.

## Independent complete oracle

Before the fault, retain the random source identity and actual authority/lease
device/inode coordinates outside the guest. Reuse the original independent
literal objects, complete twelve structured and two blob table images, four
portable collections, positive two70KiB bodies, receipt/nonce/revision/history
and outbox facts. Compute expected authority roots independently from those
complete literal typed row images and known body length/content-hash inventory;
never derive expected roots from recovered output or call the production root
implementation to create expectations. Match the independent baseline root to
actual stopped enrollment before arming a fault.

Cold recovery reads the receipt first through an explicitly forensic historical
read-only owner, without granting independent freshness or write authority.
Compare every source/body cell and both authority tables including closed column
inventory, acknowledged/Pending roots, sequence and all body-manifest rows.
Pending with old source deliberately fails three real anchored factory opens
without any row/fence/identity change. No operator repair, Pending clear, metadata
rewrite, new enrollment or blanket automatic retry is permitted. Exact new source
plus Pending must use the actual normal anchored open/check/finalize path before
claiming the next fence. A coherent continuable case then proves stale fencing,
exact target receipt reconciliation/replay, genuine fresh state/receipt/outbox
commit and replay with exact independent acknowledgement sequence/root changes.

Keep the SAME original authority image as the actual cold device. An immutable
byte copy may be retained only in a private forensic directory as untrusted,
never-attached evidence; it is not backup authority or a recovery candidate.
The controller rejects any forensic path in launch argv or actual block nodes
and proves the active original authority host identity is unchanged. No guest
is live during image copying. Failed attempts retain raw streams, exact roles,
paths, hashes, graph/errors and owned wait/EOF/reap observations.

## Containment and scope

One512MiB/oneCPU guest at a time, no network, host mounts, passed-through host
devices, downloads, global VM settings or cache/fsck/retry fallback. Nine source
64MiB and authority32MiB disk pairs plus six cold source copies and nine immutable
forensic authority copies total33 images/1536MiB. With a164MiB initramfs ceiling,
32MiB kernel,16MiB raw logs and4MiB terminal metadata, a2GiB new-root cap is finite.
The execution owner separately checks the exact prior retained roots and3.5GiB
aggregate ceiling. Gross logical I/O is capped at8GiB, free headroom5GiB. The
outer owner has1GiB memory, swap0, oneCPU and128 tasks; eighteen sequential boots
retain150 seconds each including cleanup, a shared1200 guest-second cap and
1320-second outer cap. These are invocation bounds, not physical guarantees;
execution approval and results remain separate from architecture.

This names guest kernel/cache loss and virtual block failures with the actual
selected authority. It does not reuse ordinary-profile evidence as anchored
coverage, prove bare-host/firmware power loss, demonstrate torn persistent WAL
writes, repair arbitrary media loss, supply quorum authority, qualify all M3,
replace independent security review or move technical criteria into public D07.
Actual qualification status belongs only in TODO.
