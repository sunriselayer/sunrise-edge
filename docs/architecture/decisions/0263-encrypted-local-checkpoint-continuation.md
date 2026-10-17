# DR-0263: Encrypted local checkpoint continuation

Date: 2026-10-17 (Asia/Singapore)

Status: Selected local implementation contract; execution belongs in TODO.

## Decision and authority

Add `pack-checkpoint` and `open-checkpoint` to the existing `business_recovery`
owner. Preserve every v1 saved-business role, byte, vector and proof-verification
path. Reuse its maintained age X25519 transport, zeroized identity loading,
same-cursor header/total/physical EOF limits, SDK attachment budgets, private
stage and no-clobber ciphertext publication. Introduce no key service, protocol
identifier, crypto primitive, unsafe code or dependency version.

The local v2 envelope carries exactly two complete SQLite snapshots: all twelve
structured tables, including signing/safety/history/receipts/delivery state,
and the complete immutable-body database. This is physical local continuation,
not inactive business reconstruction, a portable protocol state root or quorum
checkpoint authority. The independent configured DR-0259 anchor and separate
lease remain outside the archive. Recovery never creates or repairs authority,
rewinds acknowledgement, clears Pending, copies signer/TLS/recovery keys or
activates a host. Existing host genesis/successor checks and next-fence claims
remain mandatory after restored files are qualified.

Capture holds anchor then source ownership, pins a source read transaction and
an immutable-body read transaction, and uses rusqlite0.40.2's safe incremental
Backup API into fresh private SQLite-owned outputs. Enable only its existing
`backup` feature. Bound pages, copied database sizes, steps and the original
cooperative invocation deadline; never copy live main/WAL/SHM through ordinary
file descriptors. Close snapshot SQLite owners before hashing/encrypting files.
Only closed private snapshot files use SQLite's read-only `immutable=1` URI
mode during verification. Require effective-UID ownership,0600/0400 permission,
single link, attached ancestors and exact full file stamps, with absent sidecars
before and after. Percent-encode every path byte that could alter URI parsing.
Never use this mode on a live source or mutable blob store: it skips SQLite
locking/change detection. Keeping snapshot WAL headers unchanged preserves raw
archive hashes and ordinary serving factories; read-only WAL verification must
not create residual WAL/SHM, and recovery adds no promotion format.

Recheck full logical rows, namespace/source identity and body inventory before
publishing its local checkpoint. Any newly retained staged bodies enter the
independent acknowledged manifest atomically; no source transaction is repaired.
A failure retains unqualified private residue without cross-file atomicity or
rollback claims.

Open first acquires the configured independent authority without requiring lost
original source paths. Pending or unavailable authority refuses. Fully authenticate
and close the encrypted input before trusting any restored file. Require the
exact current acknowledgement sequence/state root/body-manifest root; verify
namespace and source-instance identity against the actual complete rows. Require
exact known SQLite schema objects, SQL definitions, application/schema versions
and immutable body inventory, refusing surplus tables, views, triggers or index
substitutions. Encryption to a public recipient is not sender authentication;
logical roots alone do not authenticate executable SQLite schema. Publish the
private completion marker only after these checks and attachment rechecks.

## Local envelope v2

All unsigned integers are big-endian. Reuse magic `SE-RECOVERY\0`, followed by
u16 version2. A Manifest record is tag1, u32 payload length and a closed payload:
u16 chain byte length, UTF-8 chain (1..128 bytes), validator32, domain32,
source-instance16, acknowledgement u64, state-root32, body-root32, then exactly
two file descriptors, each u64 length plus raw SHA-25632. Filenames are implicit
`state.sqlite` then `blobs.sqlite`; there is no caller path, role selector,
algorithm negotiation or optional field. Payload length is exactly234+chain
length and at most362 bytes.

Exactly two File records follow, each tag2, index u8 (0 then1), length u64 and
exact body bytes. Footer is tag3, total plaintext length u64 and raw manifest
payload SHA-25632. Total plaintext is exactly80+manifest length+both body lengths.
Require authenticated plaintext EOF and later physical EOF on the same original
ciphertext cursor. V1 rejects v2 and v2 rejects v1; neither decoder downgrades.

Keep existing per-file32MiB, plaintext256MiB, ciphertext272MiB, header64KiB,
control4MiB, transfer64KiB and cooperative300-second maxima, with downward-only
configuration and one shared original archive budget. Native root/page work has
its own checked finite observations and consumes that same invocation deadline.
No nominal individual ceiling promises every simultaneous combination fits the
shared work budget. Private outputs remain0600 under a0700 stage, fresh-only,
with original held directory/leaf identities and at least1GiB free headroom.

## Scope and acceptance

Preserve all actual stored history, receipts, local safety and blob bytes and
old-format readability. An exact-current restored store can continue only under
the same independent lease and the existing next writer fence. Missing/stale
anchor, Pending, wrong namespace/source, changed/missing/surplus bodies, schema
substitution, truncation/concatenation, wrong recovery key, quota refusal and
existing output must refuse without a qualified completion marker. Test real
age round trips and actual post-restore writes/replay; retain v1 vectors and
refusal controls. Compilation is not execution.

External public genesis/successor proof archives remain in their existing v1
owner and serving configuration; this store envelope does not silently replace
them. Same-layout local continuation is not a protocol upgrade policy, off-host
retention qualification, power/media/fsync evidence, independent security audit
or all-M4 completion. All original M4 gates remain binding.

## Compiled selected-host restoration contract

Keep all fourteen existing local-TLS selectors and their original assertions.
A separate fifteenth Linux selector inserts the actual compiled
`business_recovery pack-checkpoint`/`open-checkpoint` flow into the existing
four-host anchored paid-business, complete-owner-loss, fresh-fence owner. Only
after all four sole hosts are SIGKILLed and reaped, create disposable age
identities and private sibling capture/cipher/restored trees outside source and
authority trees. Use one original300-second group deadline, downward per-child
remaining deadlines, the existing strict child EOF/reap/output owner and finite
32MiB file/68MiB plaintext/72MiB ciphertext/control/header caps. No signing-key
or recovery-identity contents enter argv or the archive.

Publish all four snapshots, retain any intentional body-only acknowledgement
advance while requiring unchanged complete state roots, then move all original
state/body files and sidecars into private forensic directories. All eight old
main paths remain unavailable through decrypt, new serving and tail stop.
Original forensic12+2 table images remain fixed. Independently configured
anchors and leases stay in their original sibling directories. Each compiled
open must preserve their post-publication acknowledged rows and its completed
candidate must pass the actual compiled current-checkpoint inspection.

Fresh restored pairs then enter the original actual host argv, with unchanged
TLS/namespace/genesis/signing pins, exact endpoints and writer fence2→3.
Preserve complete raw12+2 table equality before restart, the existing exact
fence-only image delta, all four portable collections/referenced blobs, old
receipt replay, fresh paid CLI/quorum business and fresh receipt replay, and
ordinary tail-stop equality. Add only actual CLI mode-irrelevant input,
wrong-namespace, missing-authority and existing-output refusals; a failure never
becomes qualified completion. This integration is ordinary same-protocol local
continuation. It does not activate a protocol migration, qualify off-host
retention or mark all M4 complete. Execution status belongs in TODO.
