# Independent local checkpoint anchor

This opt-in native storage profile supplements the verified saved-business
closure and ordered-history floor. It does not change genesis, certificates,
readiness, Seal, canonical business frames, signatures, cryptographic primitives
or the protocol's serverless execution model. The baseline v6 SQL profile is
unchanged. Current execution evidence and remaining gates belong in TODO.

The trusted local OS retains one anchor SQLite database and its separate lease
file outside both state and body backup directory trees. Its integrity and
retention are independent assumptions: restoring a disk snapshot containing the
anchor as well as the source is outside this profile. A copied anchor is not a
replacement authority, and missing authority is never reconstructed from a
backup. The anchor's own device/inode and its lease inode are pinned in its head.
Only directory metadata observations are used on SQLite-owned inodes; the OS
lease uses a separate `.lease` file and never an independent SQLite descriptor.
No global daemon, account, service, privileged setting or external trust root is
introduced. Unix file identity support is required for enrollment.

## Roots and immutable bodies

The local state root commits all typed columns of the 12 durable SQL tables in
fixed table and natural-primary-key order. It includes tombstones, revisions,
local consensus/signing safety, namespace lifecycle, import progress, barriers,
readiness, successor activation, receipts and outbox payload/delivery/attempts.
It excludes SQLite pages, WAL/SHM bytes, file timestamps, indices and query plans.
One closed local v1 SHA-256 framing fixes null/integer/text/blob tags, lengths,
row/column counts and table boundaries. This root deliberately retains local
metadata, so it is not the cross-replica business cut root or a protocol state
commitment. Existing verified cut/package/plan roots keep their own meaning.

The independently retained manifest lists immutable body algorithm/key, length
and raw SHA-256 content digest in canonical key order. All acknowledged bodies
must remain present and exact. An additional staged body does not by itself
change business state or invalidate a read; the next state commit captures the
complete actual body inventory, including retained staging orphans. The blob
owner continues to enforce insert-if-absent and exact idempotency. This owner
provides retention/integrity evidence, not protocol validation or semantic
reconstruction of opaque state bytes. Existing business verification still owns
proof and referenced-body completeness checks.

An invocation shares a limit of 65,536 observations, including row/column/body
work, and 128 MiB charged input across all root/manifest inspections. One body is
at most 16 MiB. Borrowed SQLite values are charged before hashing; fixed-width
persisted anchor values are length-checked before copying. State roots are
streamed; no complete state image is allocated. Request root work consumes the
original storage deadline. As with the native file owner, these cooperative
checks cannot preempt blocked filesystem I/O. This is a bounded local profile,
not a throughput claim or a replacement for M3 durability qualification.

## Ownership and crash order

One owner holds the separate OS lease for its lifetime. A second owner, including
a byte-identical current source clone, refuses while that lease is held. After
the old owner closes, an exact current clone can recover under the same anchor;
a stale original then refuses. The protocol's existing fences still advance
normally, but the independent root detects same-epoch in-place rollback and
stale clones that copied the original namespace identity.

Every `NativeSqlBackend::transaction` obtains the independent anchor mutex
before the source connection mutex and SQL transaction. It checks the full
current state root and acknowledged bodies before any SQL callback. The body
inspection connection is read-only; blob insertion never acquires the anchor
or source mutex, so there is no reverse lock path. A callback which changes logical state follows:

1. Inspect the candidate typed state inside the source transaction and capture
   its complete body manifest.
2. Durably commit Pending with the next checked acknowledgement sequence and
   candidate root/manifest in the independent anchor.
3. Dispatch the ordinary source SQLite COMMIT with existing identity guards.
4. Reinspect actual committed rows and exact pending bodies; only an exact match
   permits durable anchor finalization and release of the callback's value.

A logical no-op COMMIT creates no Pending and advances no acknowledgement;
its unchanged state still receives full before/after checks.

A crash or unavailable anchor before step 3 leaves Pending with old source state
and refuses subsequent work. It is never automatically cleared or retried as an
old state. A crash after actual step 3 permits reconciliation only when the
source has the exact new rows and bodies; then it finalizes that same Pending.
Any other state stops. Lost post-COMMIT acknowledgement remains the existing
Indeterminate outcome. There is no claimed cross-database atomic transaction,
automatic rollback, unsafe reset or fallback to an unanchored writer.

## Enrollment, compatibility and commands

Initial enrollment is a deliberate stopped-writer transition. The operator must
stop every pre-profile writer and signer; this code cannot revoke signatures
already created or establish historical freshness retroactively. Independently
inspect the intended initial state and body roots, retain both pins, and require
those exact roots during enrollment before creating the anchor or changing the
source profile. Only an ordinary namespace or completed import may enroll.
Partial imports are not eligible. The anchor and lease must be fresh.

The source schema identity changes explicitly to
`sunrise-edge/sqlite/structured/schema/v6/independent-anchor/v1`; row layouts and
protocol bytes do not change. Baseline engines check identity on every operation,
so even a pre-existing opened baseline handle refuses its next read/write. The
new anchored factory alone opts into the profile. There is no downgrade or
opening-time migration. Baseline PG and Durable Object sessions retain exactly
their old default identity, SQL statements and framing. Historical native readers
can decode the new identity without an anchor, but their writes are refused and
their observations make no latest-state claim.

The existing `sqlite_source_host` executable exposes three separate offline
modes without adding a release executable:

- `anchor-inspect`: common namespace/state/body flags, producing untrusted initial
  input observations. No anchor is created or currentness asserted.
- `anchor-enroll`: those flags plus `--independent-anchor-db ABSOLUTE_PATH`,
  `--expected-initial-state-root`, `--expected-initial-body-manifest-root` and
  `--confirm-writers-and-signers-stopped`. Both expected roots are mandatory.
- `anchor-checkpoint`: common flags plus the existing independent anchor. This
  rechecks the current acknowledgement and prints sequence, local state root
  and body manifest root. A live owner's lease makes another invocation refuse.

`--independent-anchor-db` selects the same guarded factory in the original and
successor native hosts, conditional-readiness voting, successor activation,
import resumption, Seal preparation and business-cut export. Creation/import
still starts inactive and unanchored; enrollment occurs only after independent
completion verification. Missing anchor on these ordinary writer paths cannot
open enrolled state. Read-only historical material retains historical decoding
and does not grant activation/signing permission. Existing command pins and
lifecycle checks remain in their original owners.

`anchor-inspect` opens the source read-only and validates its native WAL header,
shared historical namespace and complete state root in one deferred read
snapshot. It reserves no writer lock and opens no anchor lease. Its body
inspection is also read-only, on a separate database snapshot; these two
observations grant no cross-database atomicity or currentness. Enrollment still
rechecks the retained pins under its stopped-writer requirement. Existing
historical store handles and ordinary writable transactions keep their own
opening and lock behavior.

This local acknowledgement is not a new quorum publication. The separate
[local v2 encrypted continuation](local-checkpoint-backup.md) captures complete
selected-store snapshots and verifies exact current authority without resetting
it. Published protocol checkpoint authority, off-host retention, activated
migration/upgrade qualification, recovery-key custody and actual power/storage
fault qualification retain their separate owners and requirements. Exact-current
local recovery and refusal controls must be executed before claiming this slice;
full required validation and final-source hosted CI remain required as usual.
