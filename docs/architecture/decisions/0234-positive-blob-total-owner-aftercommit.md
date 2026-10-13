# DR-0234: Positive blob closure after total fixture-owner death

- Date: 2026-10-13
- Status: Source and scoped Docker execution independently reviewed; integrated gates pending
- Scope: Linux local SQLite, successful COMMIT before confirmation, disposable test fixtures only

## Decision

Add one private Linux control alongside, not instead of, DR-0210's original
Inline before/after-COMMIT controls and the five separate Docker ENOSPC controls.
The new `blob_crash` module exercises two independently fixed canonical objects
larger than 64 KiB, positive `BlobReference` rows, state/nonce, receipts and
nonempty outbox. Only existing public storage/codecs and the existing private
`AfterCommit` test hook are used; no production hook, API, schema or dependency.

Parent setup publishes the unrelated body and one complete unrelated invocation,
checks the literal public results, captures preservation images and completes
fresh-only synchronization. The setup scope drops **all** parent database/blob,
statement/transaction/engine and physical attachment holders. Only plain paths,
scalar main identities, known canonical bytes and images/tokens survive.

One exact current-test-executable child reopens the original named pair using
existing-only constructors, confirms target absence, publishes its known target
body once and verifies it through the public blob API. Both owners remain live.
The existing backend invokes `AfterCommit` only after successful SQLite COMMIT
and before its final attachment check/return. That callback atomically exposes
a bounded exact phase/PID marker and parks without database queries or closes.
The parent opens only that marker while the child lives, rendezvouses within
15 seconds, kills only the retained `Child`, and explicitly requires signal 9,
no exit code and completed wait/reap before opening either database. Guard Drop
is failure cleanup, never the successful fault oracle.

## Complete bounded reconciliation

The reopened pair must preserve the original main inode identities. Normal WAL
recovery is allowed; no raw WAL/SHM byte equality, sidecar deletion, repair,
auto-bootstrap/reset or copied database is used. An additional existing-only
read-only blob owner opens only after reap. Both public owners verify each full
body, exact descriptor and two contiguous range chunks, purpose-bound digest and
public object decode/re-encode against independently fixed literals.

The private SQL reader steps rusqlite rows and checks each `ValueRef` length
**before** Rust allocation/copy, rather than using `SqlSession::exec`'s unbounded
collector. Fixed queries cover every current column/null in the twelve structured
tables and the two blob tables, with separate exact table-name inventories.
The populated-row caps are **16 structured plus 3 blob rows**, 19 combined;
table inventory rows are separate. One shared 1 MiB payload budget and a 96 KiB
per-cell/body cap precede copies. Unknown table/row/REAL/oversized value fails;
there is no truncation or posthoc-only collector bound.

Public snapshots enumerate exactly nine keys in all four collections with
one-key pages, a 16-page global bound, exact descriptors and bounded contiguous
payload chunks under one unchanged token. Positive version descriptors contain
the two expected blob references, never Inline fallback. Direct public state,
nonce, heads, versions, receipts and Ordinary/Unsealed/Inactive metadata agree.
Expected material SQL fields use independent literals/public codecs, including
NULL inline payloads, exact digest references and zero/NULL delivery fields.
The random 16-byte source-instance and complete preexisting raw rows are captured
**before** the fault for preservation, not invented as independent initial bytes.
This is not a blanket independent proof of every internal bootstrap encoding.

Sequence 1 becomes 2 exactly once. Receipt-first replay refuses without a second
structured write-set publication, revision, receipt/outbox or blob addition.
Fence 1 to 2 has a **separate** expected image: only its metadata field/token
changes, sequence remains 2. Existing-only reopen proves persisted fence 2.
Fresh valid-deadline stale-fence context refuses `WriterFenced` before receipt;
fresh fence-2 context refuses `RequestAlreadyCommitted`. Complete raw/public
images and tokens must remain unchanged after each refusal. These checks do not
count paid/business evaluator invocations or qualify a real failover controller.

## Limits and qualification

The helper child is inert without its dedicated closed-phase fixture environment;
only the outer control supplies the fault assertions. The 15-second rendezvous
bounds polling/eligibility, not preemptive disk I/O, scheduling or kill/wait
syscalls. The trusted local private-directory assumptions remain; no hostile
privileged-host isolation or power-loss flush guarantee is claimed.

This boundary is successful blob publication plus successful structured COMMIT,
unconfirmed return, then total paired **fixture**-owner process death. It is not
failed/interrupted COMMIT, cross-file atomicity, fsync/power/host/disk/media fault,
authenticated business execution, custody, TLS or public release qualification.
On 2026-10-13 the formatted four-path source received independent review, actual
test compilation and strict owning all-feature/all-target Clippy passed. The
fresh executable was then rebound and the exact nonignored outer control passed
inside the disposable Docker profile: actual UID 1000, 64 MiB noswap allocation,
512 MiB memory/no additional swap, 64 PIDs and one CPU. The case reported one
pass and zero failures; its container exited 0 without OOM. The bounded parent
completed in 3.78 seconds with both pipe EOFs, no stop and its owned cgroup absent.
Complete terminal output and source/executable bindings were independently
reviewed; exact owned container/volume/image and private staging were removed.

The record is `validation-0fed3d1a6460413294be623cb89e7fb1.json` with its complete
raw streams. The earlier execution refused the runner's three-library equality
before resource creation; it remains a failure. The corrected equality matches
the four already pinned libraries, including the executable's direct loader
dependency; it does not acquire or admit any additional library.

This qualifies only the described AfterCommit total fixture-owner death case.
The isolated candidate is not part of the earlier c69 required run. Integrated
complete gates remain required; no whole M3/TODO checkbox or release result
follows from this scoped execution.
