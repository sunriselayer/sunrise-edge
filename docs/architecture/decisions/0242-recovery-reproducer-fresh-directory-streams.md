# DR-0242: Recovery reproducer fresh root-directory streams

Date: 2026-10-14 (JST)

Status: Accepted test-support correctness fix. Grants no implementation,
execution, deployment, or R4/M7 completion claim.

## Context

[`apps/operator/tests/support/recovery_reproducer.rs`](../../../apps/operator/tests/support/recovery_reproducer.rs)'s
private `Guard` ([DR-0232](0232-bounded-recovery-failure-reproduction.md))
anchors enumeration and verification to one held root `File` opened once in
`Guard::new`. `Guard::descend` returned that same held root whenever the
relative path was empty by duplicating its descriptor
(`self.directory.try_clone()`). A duplicate shares its original open
instance with the file it was cloned from. On Btrfs
([`fs/btrfs/inode.c`](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/btrfs/inode.c),
lines 5478-5497 and 5581), a directory read keyed to that original open
instance can omit entries created in the directory after the instance was
opened, even on a fresh read of the duplicate. `apps/operator`'s parent
diagnostic reproduced this: the same unmodified driver exits 101
(`Refusal::Verification`) on Btrfs and exits 0 on tmpfs, with all thirteen
actual child paths overlaid onto `/usr/bin/false` and no native child ever
executed; the retained receipt is private, outside this worktree, at
`sunrise-edge-validation-1013/r4-directory-controls-receipt.json`.

## Decision

`Guard::descend`'s empty-relative-path branch now opens a fresh descriptor
with `openat(&self.directory, ".", directory_flags(), Mode::empty())` instead
of duplicating `self.directory`. A fresh `openat` starts a new open instance,
so a Btrfs directory read through it observes entries created after
`Guard::new`'s original root open. The returned descriptor's
`DirectoryStamp` is checked against the existing root entry
(`self.prefixes.get(&PathBuf::new())`) and against `DirectoryStamp::named`
for `"."` under the held root, then passed through the existing `recheck`
call, mirroring the identity/recheck pattern each named-descendant branch of
the same loop already applies. No other branch of `descend`, and no other
directory/file/hash/mode/owner/bounds or refusal logic in `Guard` or its
callers, changes. The fix stays `#![forbid(unsafe_code)]` and adds no
dependency.

A new focused regression,
`descend_empty_path_reopens_root_and_observes_entries_created_after_guard_open`,
reads the empty-relative root listing twice before any entry exists, creates
a directory entry after `Guard::new`'s original root open, and asserts a
fresh root listing observes it and keeps observing it on a repeated read.
This supplements, and does not weaken or replace, the existing shared-root
assertions in
`failed_pack_reproducer_copies_only_closed_roles_and_refuses_unsafe_or_oversized_plan`
and
`failed_pack_reproducer_refuses_replaced_prefix_special_mode_and_fifo_without_outside_writes`.

## Acceptance boundaries

This is a test-support correctness fix only: it changes one private helper
used exclusively by `apps/operator`'s failure-reproduction test support and
adds one regression test. It makes no runtime, protocol, dependency, or
production-behavior change, and no M1/D02 security/audit or release-readiness
claim. Confirming the fix against an actual Btrfs mount, and re-running the
parent's full required validation gate, remain the parent's responsibility
and are tracked only in [`TODO.md`](../../../TODO.md).
