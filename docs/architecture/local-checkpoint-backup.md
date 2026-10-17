# Encrypted local checkpoint continuation

[DR-0263](decisions/0263-encrypted-local-checkpoint-continuation.md) defines the
same-layout local v2 store envelope. Execution status belongs in
[TODO](../../TODO.md). This selected Native SQLite flow keeps its independent
[local anchor](local-checkpoint-anchor.md) outside the archive and reuses the
existing maintained age X25519 transport and private file guards. The v1
[saved-business closure](encrypted-recovery-closure.md) and its complete public
proof roles retain their original bytes and verification owners.

`business_recovery pack-checkpoint` requires these exact inputs:

- `--chain-id`, `--validator-id` and `--domain`: the configured namespace.
- `--independent-anchor-db`: the absolute existing independent authority path.
- `--recipient`: one public age X25519 recovery recipient, separate from signers.
- `--state-db` and `--blob-db`: the complete enrolled selected store.
- `--capture-root` and `--ciphertext-out`: separate absent local outputs.

Capture holds anchor then state ownership. The safe SQLite Backup API copies
read snapshots of all twelve structured tables and the complete immutable blob
database into fresh private files. It checks current logical rows, namespace,
source-instance identity, complete body inventory and the exact known SQLite
schema. New staged bodies enter the acknowledged manifest in one independent
commit. Closing the output SQLite owners precedes ordinary leaf hashing and
encryption. The encrypted envelope binds both file lengths/hashes and the local
sequence/state-root/body-root. Local completion records remain diagnostics;
current authority remains the independently held anchor.

`business_recovery open-checkpoint` requires the same configured namespace,
anchor and recipient, plus `--ciphertext-file`, private `--identity-file` and
absent `--out-dir`. It acquires the existing authority lease without requiring
surviving old state/blob paths. A running owner, missing authority or Pending
refuses. It authenticates the whole age stream and its physical EOF before
opening candidate SQLite files, then requires exact current authority, complete
known schema, namespace/source identity and both full logical inventories.
Closed snapshot verification uses SQLite read-only immutable URI mode only for
private, effective-UID-owned single-link files with unchanged full stamps and
no sidecars. Paths are percent-encoded; mutable live source/blob owners retain
their original locking mode. Snapshot WAL header bytes remain unchanged, and
no WAL/SHM residue or separate serving promotion is accepted.
Matching raw file hashes cannot substitute for these checks: any public
recipient can encrypt a substituted SQLite schema. Completion is written only
after semantic verification and original attachment rechecks.

The restored filenames are `state.sqlite` and `blobs.sqlite`, private0600 under
an owned0700 directory. The anchor and its lease are never copied. Starting a
host remains a separate existing operation, with the same configured independent
anchor, original genesis/successor trust and signer protection, and the next
writer fence. No serving permission is supplied by a marker. After continuation
advances authority, an older snapshot or source copy refuses. Recovery never
re-enrolls, repairs Pending, resets currentness or deletes failed residue.

All existing downward recovery limits apply. Two database files each have a
32MiB ceiling, plaintext256MiB, ciphertext272MiB, header64KiB, control4MiB and a
cooperative300-second invocation deadline. Database page counts and64-page
backup steps are finite; Busy/Locked refuse without retry. Native typed scans
retain finite per-phase observation/byte caps and consult the original deadline;
each backup step also charges the same original archive budget. Shared budgets
can refuse combinations below individual maxima. Existing parent ownership,
no-follow identities, no-clobber ciphertext publication and1GiB free headroom
remain required. Fresh private partial output is unqualified residue, with no
cross-file atomicity, power-loss or automatic rollback promise.

Preserved history/receipt/blob bytes and same-layout continuation do not activate
a protocol upgrade. Current immutable execution refuses cross-version execution
until an explicit migration exists; historical records and exact receipts retain
their established readers. Activated migration/upgrade qualification remains an
original M4 technical gap. Real off-host retention, recovery-key custody and
operator deployment approval stay with D04/D06/D07/D08. A quorum checkpoint is
not introduced as a prerequisite for this selected local authority.
