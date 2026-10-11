# DR-0210: Native SQLite durability and lock-safe file identity

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted corrected design after fresh read-only Codex fallback review.
The review checked the actual SQLite locking and operator/read boundaries; this
is design approval, not implementation approval, an independent security audit
or production qualification. Local selected-profile work follows DR-0208.

## Context

The shared `SqlDurableEngine` owns state, object, receipt/outbox, namespace,
fencing and atomic decision rules. Native `NativeSqlBackend` owns the connection
mutex and actual SQLite BEGIN/COMMIT. Before this decision, fresh and import paths
explicitly selected FULL synchronization; ordinary/historical reopen did not use
one common configuration/verification owner. SQLite defaults may already be FULL. This is
an explicit contract gap, not evidence of corruption or a proven vulnerability.

Native file/ancestor handles already protect fresh/import opening and final
synchronization. Reopened structured handles do not retain that attachment
evidence through their operation lifetime. Selected Native qualification should
not rely on a pathname continuing to identify the same file without checking it.

## Decision

Keep one private native writable-connection settings owner. Set and verify
`foreign_keys=ON`, `trusted_schema=OFF` and `synchronous=FULL`; retain bounded
busy-timeout and checkpoint policy. Only explicit fresh/development initialization
may select WAL; existing live/historical/import opens require the already
supported WAL/application/schema identity and never bootstrap or repair it.
Store-specific application/schema identities remain with their existing owners.
Reuse the settings owner for the actual structured/import/blob consumers where
their contracts match; do not force different read-only blob behavior into it.

Use lock-safe identity observations, not extra open main/WAL/SHM descriptors.
Capture regular-file device/inode identity with `symlink_metadata` before and
after SQLite opening; retain ancestor directory handles, which do not share a
SQLite locked inode. Recheck main/sidecar identity around transactions under
the backend's existing mutex: before BEGIN, after acquiring SQLite's lock,
before COMMIT dispatch and after COMMIT. Existing regular sidecars are observed
before use; legitimate SQLite-created sidecars attach to the same identity
owner. Reject symlinks, aliasing and replacement. Do not freeze mutable WAL
bytes/length, remove sidecars, or reject valid checkpoint/close lifecycle.
The first attributable identity qualification is Linux/POSIX; other platforms
cannot claim equivalent identity evidence from file length or timestamps.

Reads complete through `TransactionDecision::Rollback`, not COMMIT. Recheck
identity before returning their result under the same mutex, with definite read
refusal on a changed observation. Separate blob point/descriptor/chunk reads
and native snapshot/maintenance access need equivalent scoped before/after
checks; the private raw `NativeSqlBackend::lock` is not a production bypass.

Closing any independent descriptor for a POSIX locked inode can release every
lock held by that process on it. SQLite accounts for its own descriptor closes,
not `std::fs::File` guard drops. Constructor failures and Drop therefore must
never introduce extra main/SHM descriptors. No fd leaks, process-global registry,
unsafe VFS/raw handle, or assumed singleton connection is a solution.

Amend the fresh/import leaf-handle mechanism in DR-0195 at this physical boundary:
reserve the new file exclusively, capture its identity, synchronize and close
that reservation before SQLite opens it. Retain identity and ancestor handles,
not the leaf descriptor. Final fresh-file synchronization uses the SQLite-owned
connection/VFS checkpoint/flush with an explicitly checked non-busy complete
result, followed by held parent-directory synchronization and attachment checks.
Never reopen the leaf merely to `sync_all` it. Keep the exact initial identity
and fresh-only/no-repair semantics; no success follows incomplete synchronization.
Drop active statements/transactions before the checkpoint and verify every busy
and completeness result field. The existing busy-timeout bounds lock waiting,
not synchronous disk-I/O duration; bounded host blocking admission remains
required. This is neither a background worker nor a cross-file transaction.

Any internal memory-only development connection must be explicit and must not
masquerade as a guarded file or qualify the native release profile. Existing
auto-bootstrap development APIs remain distinct from production reopen.
No new public maintenance bypass, file-copy repair or namespace promotion follows.

Failure before commit dispatch produces no confirmed result and retains the
original definite-failure classification. Failure during/after COMMIT, including
postcommit identity failure, remains indeterminate. Request reconciliation stays
with the existing receipt owner. Add a distinguishable operator indeterminate
error instead of mapping `SqlBackendError::CommitIndeterminate` to definite
`SqliteDurableStoreError::Unavailable` in `run_operator_step`.

Bootstrap/fence/lifecycle operations have no request receipt: their existing
namespace metadata, lifecycle/barrier and exact writer-generation readers own
inspection. On an indeterminate reply, refuse serving/success and preserve the
files; inspect those exact values under confirmed physical writer exclusion,
without reset, repair or blind retry. A matching generation does not prove which
of two competing operators claimed it, so metadata observation alone never
grants live writer ownership. No new receipt protocol or duplicate evaluator
is introduced merely to reconcile these operator operations.

Safe API attachment checks cannot prevent a privileged filesystem actor from
swapping paths between checks or revoke a writer on another disk. Preserve the
trusted local-directory/single-writer operational assumptions, explicit fencing
and physical exclusion; do not present these checks as malicious-root isolation,
distributed HA or cross-file atomicity. No unsafe raw SQLite handle/VFS is added.

## Local acceptance

Retain existing real-file atomicity, ABA, deadline/contention, schema/lifecycle,
writer-generation, import, Seal/activation, original receipt and replay controls.
Add FULL-on-reopen and settings refusal checks across real constructors, plus
main/ancestor/sidecar replacement and symlink/alias controls with real files.
Hold a transaction on connection A, open/drop connection B's identity owner and
exercise its constructor-failure path, then prove a real external process still
cannot acquire the write lock until A releases it. This tests actual lock
ownership, not only that a second same-process mutex exists. Exercise definite
versus post-dispatch indeterminate classification through both request and
operator APIs, retaining the exact persisted metadata/fence on lost confirmation.

Use a disposable subprocess of a Rust test executable with private `cfg(test)`
commit-boundary synchronization, absent from releases. Kill after real SQL
mutations but before COMMIT: reopen and find none of the object/state/nonce,
receipt or outbox write set. Kill after SQLite COMMIT but before returning output:
reopen and find the exact complete write set and receipt. Verify stale fencing
and no duplicate revision/nonce/outbox application on a repeated request using
the relevant owning API; backend assertions are not proof of node authentication
or a newly claimed protocol replay path. Retain those genuine core/host owners.

Retain existing immutable blob publication/reference ordering. An interrupted
pre-reference publication may leave an orphan body, never an accepted dangling
reference; do not add a fake cross-file transaction or a new garbage collector.
Focused real-store checks, complete required acceptance and independent exact-head
review/CI are required. This proves process-failure behavior on local storage,
not power-loss flush correctness, ENOSPC, off-host restore, failover or mainnet.
Those remaining release requirements stay open in TODO.

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

The existing [TLS process target](../../../apps/operator/tests/local_tls_startup.rs)
adds the nonignored Linux control
`actual_direct_tls_hosts_replay_once_after_owned_sigkill_and_fresh_fence`.
Its [private child owner](../../../apps/operator/tests/support/compiled_source_host_process.rs)
adds `ChildGuard::kill_abruptly_and_reap`, not a production signal or storage API.

The fixture authenticates an acknowledged paid CLI transfer before the fault.
All four live owned children must return actual signal-9/no-exit-code status
and confirmed reap receipts under one original eligibility/polling end. Restart
retains the same four database/blob paths, namespaces, keys, certificates,
configuration and nonzero endpoints, advancing the writer fence from 2 to 3.
Pre-held stale read and valid nonempty CAS/Put capabilities must refuse as
`WriterFenced`. Complete logical snapshots compare State, Receipts, ObjectHeads,
ObjectVersions, referenced blob bytes and mutation sequence; they are continuity
observations, not independently reconstructed cut authority. Canonical saved
artifacts, paid receipt/result, public object/nonce query bytes and all 19 input
files remain equal. Saved CLI replay must return all four original results
without a second business mutation/receipt commit. Read-only SQL COMMIT is not
excluded. Ordinary tail stop follows those assertions and is not the fault oracle.

Parent-side SQLite handles remain open across host reaps/restart. The outbox
oracle is guarded empty, not nonempty-outbox delivery; physical pages and
unreferenced blobs are not compared. The shared end bounds polling and success
eligibility, not kill/wait syscalls, scheduling, legacy Drop cleanup, readers or
process-group release. This is post-acknowledged serving-host failure, not loss
of every connection, WAL loss, interrupted COMMIT, power/fsync, disk failure,
ENOSPC or failover qualification. Existing before-COMMIT and after-COMMIT-before-
confirmation requirements above remain unchanged.

UNFORMATTED, UNCOMPILED, UNEXECUTED; runtime/resource fit is UNKNOWN. This source
control does not complete M3/TODO, qualify PostgreSQL or custody, or grant runtime,
dependency/floor/private-input/ROOT ONE or release authority.

## 2026-10-11 (Asia/Tokyo): request-scoped outbox reply-loss source controls

Local `3e0f066e` adds three controls in the existing
[Native HTTP tests](../../../crates/native-http/src/tests.rs):

- `sqlite_request_outbox_reconciles_landed_claim_and_ack_reply_loss`
- `sqlite_request_outbox_unresolved_landed_claim_preserves_first_ambiguity_without_send`
- `sqlite_request_outbox_unresolved_landed_ack_preserves_first_ambiguity_after_one_send`

The fixture creates a fresh real-file SQLite store and uses the existing valid
signed submission through the actual typed `ReadOnly` Native consumer. Its
forwarding wrapper first requires a real successful claim or acknowledgement,
then masks only that reply as `ConnectionLost`. Native reconciliation must reuse
the original request and operation context. The refused-reconciliation controls
return a different second rejection without another delegation, requiring the
original ambiguity to survive. No production fault hook or new API is introduced.

Independent literal state/payload/nonce frames and public receipt/result/outbound
codecs define expected bytes, not captured invocation writes or stored post-state.
One-key pages and seven-byte chunks compare every descriptor and body in all four
portable collections under the same local token, retaining unrelated rows.
Immutable referenced blobs use their separate interface outside that token;
this fixture has empty object/reference collections and proves no positive
object/blob coverage or content-hash authentication. No handoff-empty-outbox
guard is invoked.

Before original lease expiry, probes require the complete same-lease claim tuple
and foreign `NoDueWork`; after ACK, they require same-ACK `Acknowledged`, original
claim `LeaseIdReuse` and fresh foreign `NoDueWork`. Explicit clock checks surround
those probes. After setup, the source requires one application transition and
one `commit_invocation`, with sequence deltas +3/+2/+3 across the three cases.
Claim ambiguity permits no send or ACK; success and ACK ambiguity require one
exact canonical send. Reconciliation/probe snapshots must not add mutations.
These counters do not count all SQL COMMITs or prove a new business replay path.

Different exact-slice source review passed. UNFORMATTED, UNCOMPILED, UNEXECUTED;
all three names are outside the original 41 selectors. Synthetic trait reply
loss after a confirmed operation is not failed SQLite COMMIT, physical I/O,
ENOSPC, crash/power-loss durability, custody or M3/TODO20 completion. All original
before-COMMIT/after-COMMIT-before-confirmation and release requirements remain.

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
