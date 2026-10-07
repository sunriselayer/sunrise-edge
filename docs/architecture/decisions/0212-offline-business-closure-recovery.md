# DR-0212: Offline Native SQLite business-closure recovery rehearsal

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted after fresh independent Codex fallback DESIGN APPROVE on
2026-10-07, including the logical-generation/writer-fence distinction. This is
not source approval or executed recovery evidence. No serving or release authority
is granted. The selected first profile is Native plus SQLite under DR-0208;
general checkpoint, backup and disaster-recovery qualification remains M4.

## Context and existing owners

The operator already exposes `business_cut export-sqlite`,
`business_cut verify-saved`, `business_import create-sqlite` and
`business_import resume-sqlite`. These are callable production compositions,
not merely a library interface. Existing tests independently cover export,
archive substitution/refusal and fresh inactive installation/reopen.

`derive_source_business_cut` captures a token-covered drained source and
independently reconstructs and compares its complete business closure. Saved
verification authenticates original proofs against pinned signed genesis and
the fixed ordered-history target. `verify_saved_business_import` produces the
opaque verified installation plan; `VerifiedImportPlan::advance` installs
required bodies, rechecks installed prefixes and compares complete inventory
before `CompleteInactive`.

The local portable snapshot token is continuity, not a state root, cross-replica
identity, freshness proof or import/serving credential. File manifests and
completion markers likewise cannot replace independent proof reconstruction.
The raw import projection preserves validated business history/receipts and
retention closure, but deliberately excludes source-local signing identities,
ACKs, reservations, cursors and consensus safety rows. Destination physical
revisions are new and the runtime version checkpoint is rebased to zero.
This is not an ordinary crash-state restoration codec.

## Decision

Reuse the existing commands and authority owners. Add no recovery runtime API,
wrapper executor, schema, normalized certificate codec, unchecked repair flag,
promotion capability or new quorum checkpoint merely to join these steps.

The bounded local outcome is one genuine original-genesis business closure:

1. Export to an immutable local archive using independently configured pins and
   an eligible drained source with empty portable outbox and terminal three-chain.
2. Close all source SQLite owners and make both original state and blob database
   paths unavailable. Re-run saved verification using only the original pins,
   fixed history archive and complete saved cut.
3. Create two fresh distinct destination files outside the input archive trees.
   Install bounded batches, reopen/resume to `CompleteInactive`, then resume
   again proving stable cut/package/plan identities and `new_batches=0`.
4. Keep both source paths unavailable throughout verification and installation.
   Reattach them only after that sequence to independently compare their original
   complete business inventory. No source writer-fence generation or source-
   instance identity is copied into the destination, and the original source
   is not refenced. Authenticated logical generations and their generation
   floor remain preserved.

Extend the existing compiled import acceptance instead of duplicating its
expensive signed fixture. Preserve every existing corruption, wrong placement,
namespace, resume and ordinary-serving refusal. Pin the sequence to actual
executables, not a replacement interpreter or manufactured verifying capability.
Also exercise a genuine second-file creation failure: a fresh state database
can have initialized import origin before body-database creation fails. Preserve
the inactive residue, refuse ordinary open and missing-body resumption, and
verify source/archive inputs unchanged. No cross-file atomic creation guarantee
or automatic cleanup/repair is claimed. Use task-owned files only, with no public
fault hook or host-permission-dependent skipped positive test.

Update the existing export/import guides with this combined local rehearsal and
the exact successor boundary; avoid a parallel command/runbook implementation.
All actual execution/CI/source-review status remains in `TODO.md`.

## Refusal and authority boundaries

Wrong local pins, domain, context, history target, incomplete Freeze/DrainSet or
selected outcomes, nonempty outbox/tip, changed source token/fence, corrupt,
missing, foreign or surplus archive material refuse. Existing destination paths,
unsupported/replaced/symlinked SQLite attachments, wrong import binding/origin,
conflicting rows, missing bodies and corrupt progress refuse. Keep failed files
for explicit inspection; never reset metadata or force resumption.

Later-epoch cuts cannot be selected by changing `--epoch`: their full verified
predecessor chain supplies current policies. Successor source export additionally
requires an issuer-bound live warrant over installed Serving state, current
namespace/member/key and actual chain evidence. Saved successor verification and
import reauthenticate that chain without a signer key or live capability. This
first rehearsal does not replace the existing successor acceptance owner.

Destination-local fencing affects only its database. Advancing a copied inode
does not revoke the original writer or protocol signer, and SQLite locks do not
cross those copies. This rehearsal ends inactive and does not attempt that
transition. Any future live restoration needs actual physical old-writer/signing
exclusion plus the applicable owning genesis/successor authority checks; neither
matching metadata nor a file hash can substitute.

## Acceptance and remaining M4 contracts

Require independent complete final-source review, compiled owning test execution,
strict Clippy, unchanged independent refusal controls, full required acceptance
and CI before merge. Do not infer execution from compilation or a library call.
The stored identities and command observations are evidence, not credentials.

This locally controlled rehearsal does not establish published checkpoint/state-
root authority, arbitrary same-epoch crash continuation, live restore freshness,
ABA/retention policy, encrypted off-host backup or recovery-key custody, a chosen
backup destination, real old-writer exclusion, power/storage/ENOSPC faults,
migration/upgrade/rollback, off-host restore or HA. Those M4/M3/M2 contracts stay
open; no production values, cloud resources or public-network admission follow.

## Defining references

- [Portable repository and local token](../../../crates/runtime/src/portable.rs)
- [Cut derivation](../../../crates/node-core/src/business_reconstruction/cut.rs)
  and [saved proof verification](../../../crates/node-core/src/business_reconstruction/cut/proof.rs)
- [Verified inactive import](../../../crates/node-core/src/business_reconstruction/inactive_import.rs)
  and [raw projection](../../../crates/node-core/src/business_reconstruction/projection.rs)
- [Export/saved command](../../../apps/operator/src/business_cut/command.rs)
  and [import command](../../../apps/operator/src/business_import.rs)
- [Compiled export tests](../../../apps/operator/tests/business_cut_sqlite.rs)
  and [compiled import tests](../../../apps/operator/tests/business_import_sqlite.rs)
