# DR-0210: Native SQLite durability and lock-safe file identity

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted corrected design after fresh read-only Codex fallback review.
The review checked the actual SQLite locking and operator/read boundaries; this
is design approval, not implementation approval, an independent security audit
or production qualification. Local selected-profile work follows DR-0208.

## Context

`SqlDurableEngine` owns logical state/object, receipt/outbox, namespace,
fencing and atomic decisions; `NativeSqlBackend` owns the connection mutex and
SQLite BEGIN/COMMIT. Fresh/import paths explicitly selected FULL synchronization,
but ordinary/historical reopen lacked a common configuration/verification
owner. Defaults may already be FULL: this was a contract gap, not proven damage.

Fresh/import file and ancestor handles already protect opening and final sync;
reopened structured handles lacked lifetime attachment checks. Native
qualification must check that a pathname still denotes the same file.

## Decision

One private writable-connection owner sets/verifies `foreign_keys=ON`,
`trusted_schema=OFF` and `synchronous=FULL`, retaining bounded busy timeout and
checkpoint policy. Only explicit fresh/development initialization may select
WAL; live/historical/import opens require supported WAL/application/schema
identity without bootstrap or repair. Store-specific identities stay with
their owners. Reuse settings for matching structured/import/blob consumers,
not for different read-only blob behavior.

Observe identity without extra open main/WAL/SHM descriptors. Capture regular
file device/inode via `symlink_metadata` before/after SQLite open and retain
ancestor directory handles, which do not share the locked inode. Under the
existing mutex, recheck main/sidecars before BEGIN, after SQLite lock acquisition,
before COMMIT dispatch and after COMMIT. Observe existing regular sidecars
before use and attach legitimate SQLite-created ones to the same owner. Reject
symlinks, aliases and replacement, but permit mutable WAL size/bytes and valid
checkpoint/close lifecycle. Linux/POSIX is the first qualified identity profile;
length/timestamps do not establish equivalent evidence elsewhere.

Reads use `TransactionDecision::Rollback`, not COMMIT, and refuse definitely if
the mutex-scoped return check finds identity drift. Blob point/descriptor/chunk
reads and native snapshot/maintenance need equivalent before/after checks;
private `NativeSqlBackend::lock` is no production bypass.

Closing an independent descriptor for a POSIX locked inode can release all
process locks on it. SQLite handles its own closes, not `std::fs::File` guard
drops; constructors and Drop must add no main/SHM descriptor. Do not substitute
fd leaks, a global registry, unsafe VFS/raw handles or singleton assumptions.

Amend DR-0195's fresh/import leaf reservation: create exclusively, capture
identity, synchronize and close before SQLite opens; retain identity and
ancestor handles, not the leaf descriptor. Final fresh-file sync uses SQLite's
connection/VFS checkpoint/flush with every busy/completeness field checked,
then held parent-directory sync and attachment checks. Drop active statements/
transactions first; never reopen merely for `sync_all`. Preserve initial
identity and fresh-only/no-repair semantics; incomplete sync fails. Busy timeout
bounds lock waits, not disk I/O, so host blocking admission remains required.
This adds neither a background worker nor cross-file transaction.

Memory-only development connections remain explicit and cannot qualify as
guarded files or Native release; auto-bootstrap remains separate from production
reopen. No public maintenance bypass, file-copy repair or namespace promotion.

Failure before COMMIT dispatch stays definite with no confirmed result;
during/after COMMIT, including identity failure, is indeterminate. Existing
receipt ownership reconciles requests. `run_operator_step` must expose a
distinct operator indeterminate error, not map
`SqlBackendError::CommitIndeterminate` to definite
`SqliteDurableStoreError::Unavailable`.

Bootstrap/fence/lifecycle have no request receipt; namespace metadata,
lifecycle/barrier and exact writer-generation readers own inspection. On
indeterminate reply, refuse serving/success, preserve files and inspect those
values under physical writer exclusion, without reset, repair or blind retry.
A matching generation cannot identify which competing operator claimed it;
metadata alone grants no live ownership. Add no duplicate evaluator or receipt
protocol for these operations.

Attachment checks cannot stop privileged path swaps between checks or revoke a
writer on another disk. Preserve trusted local-directory/single-writer
assumptions, fencing and physical exclusion; claim no malicious-root isolation,
distributed HA or cross-file atomicity. Add no unsafe raw SQLite handle/VFS.

## Local acceptance

Retain real-file atomicity, ABA, contention/deadline, schema/lifecycle,
writer-generation, import, Seal/activation, receipt and replay controls. Add
FULL-on-reopen/settings refusal and real-file main/ancestor/sidecar replacement,
symlink and alias controls. With A holding a transaction, open/drop B's identity
owner and exercise B constructor failure; an external process must remain
write-locked until A releases. This tests POSIX locks, not merely a mutex.
Check definite versus post-dispatch indeterminate results through request and
operator APIs with exact persisted metadata/fence after lost confirmation.

Use a disposable Rust subprocess and private test-only commit-boundary sync.
Kill after SQL mutations/before COMMIT and reopen to find none of the object/
state/nonce/receipt/outbox write set. Kill after COMMIT/before reply and reopen
to find the complete set and receipt. Verify stale fencing and no duplicate
revision/nonce/outbox through the owning API; backend checks do not prove node
authentication or a new replay path. Keep the genuine core/host owners.

Retain immutable blob publication/reference ordering: interrupted pre-reference
publication may leave an orphan body, never an accepted dangling reference.
Add no fake cross-file transaction or garbage collector. Focused real-store,
complete required and independent exact-head review/CI remain necessary.
Process-failure proof is not power/fsync, ENOSPC, off-host restore, failover or
mainnet qualification; those gates stay in TODO.

## Owning implementation boundaries

The private [`NativeConnection`](../../../crates/runtime-sqlite/src/native_connection.rs)
owns native settings, scoped attachment inspection and fresh synchronization.
[`native_files`](../../../crates/runtime-sqlite/src/native_files.rs) owns only
metadata observations and retained directory handles. A live observed sidecar
must not disappear or change identity; a real checkpoint may change its length.
Closing the last SQLite connection releases its owner, and a later constructor
captures its own optional sidecars. Read-only blob inspection retains its
non-WAL read contract rather than inheriting writable initialization authority.

[`NativeSqlBackend`](../../../crates/runtime-sqlite/src/rusqlite_backend.rs)
owns BEGIN/COMMIT and the existing mutex; structured/import adapters retain
store identity and lifecycle checks. Blob operations guard their separate
connection and never make state/blob publication a cross-file transaction.
The existing shared SQL engine retains every logical commit, receipt, outbox,
namespace and writer-generation rule. Private `cfg(test)` commit hooks are
absent from released builds and do not add a public maintenance capability.
Implementation, integration and qualification status remain only in TODO.

## 2026-10-10: compiled serving-host SIGKILL source control

The [TLS process target](../../../apps/operator/tests/local_tls_startup.rs) adds
nonignored Linux control
`actual_direct_tls_hosts_replay_once_after_owned_sigkill_and_fresh_fence`;
its [private child owner](../../../apps/operator/tests/support/compiled_source_host_process.rs)
adds test-only `ChildGuard::kill_abruptly_and_reap`.

After an authenticated acknowledged paid CLI transfer, all four live children
must show actual signal-9/no-exit-code and confirmed reap under one polling end.
Restart reuses four database/blob paths, namespaces, keys, certificates,
configuration and nonzero endpoints, advancing fence 2→3. Pre-held stale read
and valid nonempty CAS/Put refuse `WriterFenced`. Logical snapshots compare
State, Receipts, ObjectHeads, ObjectVersions, referenced blob bytes and mutation
sequence as continuity, not independent cut authority. Saved canonical
artifacts, paid receipt/result, public object/nonce bytes and all 19 inputs
stay equal. Saved CLI replay returns all four original results without another
business mutation/receipt commit; read-only SQL COMMIT is not excluded.
Ordinary tail stop follows and is not the fault oracle.

Parent SQLite handles stay open. The outbox oracle is guarded empty; physical
pages and unreferenced blobs are not compared. The shared end bounds polling/
success eligibility, not kill/wait syscalls, scheduling, Drop cleanup, readers
or process-group release. This covers post-acknowledged host failure, not loss
of all connections, WAL, interrupted COMMIT, power/fsync, disk, ENOSPC or
failover; before-COMMIT and after-COMMIT-before-confirmation gates remain.

At authorship: UNFORMATTED, UNCOMPILED, UNEXECUTED, runtime/resource fit UNKNOWN.
This control qualified no M3/TODO, PostgreSQL, custody, dependency/floor/private-
input/ROOT ONE, runtime or release authority.

## 2026-10-11 (Asia/Tokyo): request-scoped outbox reply-loss source controls

Local `3e0f066e` adds three controls in the existing
[Native HTTP tests](../../../crates/native-http/src/tests.rs):

- `sqlite_request_outbox_reconciles_landed_claim_and_ack_reply_loss`
- `sqlite_request_outbox_unresolved_landed_claim_preserves_first_ambiguity_without_send`
- `sqlite_request_outbox_unresolved_landed_ack_preserves_first_ambiguity_after_one_send`

The fresh real-file fixture submits a valid signature through the typed
`ReadOnly` Native consumer. A forwarding wrapper requires a real successful
claim/acknowledgement, then masks only its reply as `ConnectionLost`.
Reconciliation reuses original request/context; refusal controls return a
different second rejection without delegation, preserving first ambiguity.
No production hook or API is added.

Independent literal state/payload/nonce frames and public receipt/result/outbound
codecs define expected bytes, not captured writes/post-state. One-key pages
and seven-byte chunks compare every descriptor/body in four portable collections
under one local token, retaining unrelated rows. Referenced blobs use a
separate interface outside that token; empty object/reference collections prove
no positive blob coverage or content-hash authentication. The handoff-empty-
outbox guard is not invoked.

Clock-bounded probes require the complete same-lease claim and foreign
`NoDueWork` before expiry; after ACK, same-ACK `Acknowledged`, original-claim
`LeaseIdReuse` and fresh foreign `NoDueWork`. After setup each case requires
one application transition and `commit_invocation`, with +3/+2/+3 sequence
deltas. Claim ambiguity allows no send/ACK; success and ACK ambiguity require
one exact canonical send. Reconciliation/probes add no mutations. These counts
neither cover every SQL COMMIT nor prove a new business replay path.

Different exact-slice source review passed. At authorship the three controls
were UNFORMATTED, UNCOMPILED, UNEXECUTED and outside the original 41 selectors.
Synthetic trait reply loss after confirmed operation is not failed SQLite
COMMIT, physical I/O, ENOSPC, crash/power durability, custody or M3/TODO20;
original commit-boundary and release gates remain.

## 2026-10-12 (Asia/Tokyo): bounded Docker ENOSPC source controls

The private Linux [ENOSPC module](../../../crates/runtime-sqlite/src/structured/ownership_tests/enospc.rs)
adds two ignored controls:

- `docker_noswap_enospc_before_commit_publishes_no_partial_write_set`
- `docker_noswap_enospc_during_literal_commit_remains_indeterminate`

Before any fill, both require the literal `/fault` mount to be an effective
64MiB tmpfs with noswap, a read-only root, nonroot/capability restrictions,
512MiB container memory with zero swap, one CPU, 64 PIDs and loopback-only
interfaces. Bounded positive writes must reach actual errno28; only the held,
identity-matched filler is closed and removed before recovery. Deadline checks
do not preempt blocking syscalls or establish all-path cleanup.

The early case requires an independent SQLITE_FULL probe, definite
`UnavailableBeforeCommit` and zero Before-hook hits. The late case requires a
successful TRUNCATE checkpoint and zero WAL length/allocated blocks. Its Before
callback installs the After marker, fills the mount and returns Ok. Before1/
After0, stable attachment and `Indeterminate(ConnectionLost)` target the literal
COMMIT-error path, not an injected callback error; the main raw SQLite code is
discarded and is not asserted.

Independent literal oracles enumerate every column in all twelve SQL tables
and all pages, descriptors and payload chunks in the four portable collections
under one unchanged token. Positive inline objects and unrelated/protected rows
are covered; referenced-blob closure is explicitly empty. After filler removal,
the original owner and same-file/namespace reopen must both equal baseline before
one explicit successful retry. Sequence2 becomes3 once, and receipt-first replay
must leave the complete raw and portable state unchanged.

Different exact-two-path source review passed. UNFORMATTED, UNCOMPILED and
UNEXECUTED; both names are outside the original 41 selectors. The separate
[Docker ENV probes](0230-bounded-docker-fault-environments.md) do not execute
these Rust controls. Actual resource/timing fit and fault outcomes remain open;
no physical-disk, power, nonempty referenced-blob, custody, full-profile,
M3/TODO20 or release qualification follows from this source slice.

## 2026-10-13 bounded ENOSPC execution update

The prior unexecuted captions remain historical authorship records. Actual run
`validation-9f49f698c13548bfbff2d0162b15635b` passed both original `Inline`
and both new positive `Referenced` controls, with exit zero, both output streams
at EOF and its owning cgroup absent. Referenced setup publishes exactly two
fixed canonical objects with 65,537 data bytes each; the original blob writer
and warmed read-only owner stay live, with no blob writes after setup.
Both complete public blob bodies, purpose-bound digests and codec round trips
are checked while full, before filler removal. Afterwards, full twelve-table
and four-portable-collection reconciliation checks exact metadata/payloads and
NULL-inline/digest reference rows on the original owner and same-file reopen,
before one authorized retry and unchanged receipt-first replay. Pre-COMMIT
rejection remains distinct from literal-COMMIT `Indeterminate`; retaining the
prepublished unreachable target blob is expected residue, not logical commit.
These executions do not prove cross-file atomicity, physical power-loss,
custody, full M3 completion or a passed full required rerun.

## 2026-10-16 overlapping host-generation control

The owning Native TLS fixture adds an adversarial overlapping startup: four
generation-two hosts stay alive while four replacement processes open the same
state/blob files and claim generation three. This deliberately supplies the
offline-fence confirmation while the old hosts remain live; it tests containment
under that misuse, not permission for a supported live operational handoff.

Retained old read/CAS capabilities must report the specific new writer fence.
Old HTTP query and authenticated certified-apply routes must refuse with their
existing redacted unavailability responses; those bodies alone do not identify
the internal failure cause. Replacements must retain the complete acknowledged
business view and reproduce the original certified receipt without mutation.
A fresh transfer uses the first settlement's sender-owned refund coin and the
remaining distinct Write fee source, with a new request and nonce. It verifies
ordinary signatures, both quorums, exact input/recipient/value, replica query
agreement and unchanged complete business snapshots after receipt-first replay.

Both generations retain separate TLS files and real owned PIDs through the
observation; all children are subsequently stopped and reaped through the
existing owner. No lock, fence, original test or startup permission is weakened.
The control adds no cross-host restore activation, physical power/media/fsync
qualification or independent rollback anchor. Results belong only in TODO.md.
