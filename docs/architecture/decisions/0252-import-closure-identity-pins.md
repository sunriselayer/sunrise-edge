# DR-0252: Independent closure-identity pins for inactive import

Date: 2026-10-16 (Asia/Singapore)

Status: Accepted narrow design. This does not satisfy M4's published
checkpoint/state-root requirement, and it does not redefine or close that
requirement. Current qualification belongs in [TODO](../../../TODO.md).

## Problem and decision

A genuine saved cut, package and privately derived plan can still differ from
the exact closure an operator independently retained from an earlier run or
verification. `verify_saved_business_import`/`verify_saved_business_import_chain`
already authenticate the saved material and already report `cut_digest`,
`package_digest` and `plan_digest` in `ImportBinding`; `business_import` had
no way to require that the freshly reverified closure match a previously
retained identity before touching a destination. Add an optional refusal
guard, modeled on [DR-0248](0248-import-ordered-history-freshness-floor.md)'s
ordered-history floor, to the existing `business_import create-sqlite` and
`resume-sqlite` consumers.

The operator supplies all three explicit pins or none: `--expected-cut-digest`,
`--expected-package-digest`, `--expected-plan-digest`, each using the existing
32-byte hexadecimal parser. A strict subset or malformed hex refuses before any
file access, including before the existing read-only cut/history archive opens.
The pins must be retained from an earlier independent run or verification, kept
outside the cut, ordered-history archive or successor artifacts being restored;
CLI argv is trusted local operator input, not protection from a compromised OS
or an operator who substitutes their own pins.

Compare all three fields of `verified.binding()` against the supplied pins
immediately after `verify_saved_business_import`/`verify_saved_business_import_chain`
produces `VerifiedImportPlan`, and before the namespace is opened, before any
`require_output_outside` recheck and before `SqliteImportTarget::create` or
`open_existing` runs. A mismatch in any one of the three fields refuses with one
fixed message. Success grants no new authority: it only permits the original
independent proof reconstruction, the existing full-`ImportBinding` equality
check inside `SqliteImportTarget::open_existing`, and the unchanged
`CompleteInactive` completion path to continue exactly as before. No pins
preserves the original behavior; output format and canonical bytes are
unchanged, and no new frame, protocol identifier, cryptographic primitive,
dependency or persisted schema is introduced.

## Limits and compatibility

This pins one saved package's closure identity, not a state root, a quorum
publication for the current cut, latest-state or owned fast-path freshness, or
whole-store rollback detection. It is not old-writer exclusion, activation, or a
claim of cross-file atomicity between the two destination files. The ordered
-history floor (DR-0248) and this closure-identity pin stay separate checks;
neither stands in for the other, and neither stands in for a quorum-signed
checkpoint.

`plan_digest` is derived locally from the saved package during private
reconstruction. A pin mismatch after a legitimately different retained proof
subset (for example a different valid certificate carrier set for the same
cut) is therefore an expected, correct refusal, not a fault to work around.

Encrypted `business_recovery` already requires independently supplied exact
cut and package digest pins at its own, separate trust boundary; it is
unmodified here and gains no `plan_digest` argument.

## Verification contract

Compiled `business_import` controls use a genuine authenticated saved
cut/history fixture. A strict subset of the three flags and a single flipped
final byte in each digest, in turn, refuse before any fresh destination file
is created, leaving the pinned cut and ordered-history archives unchanged.
Exact pins taken from an earlier independent, unpinned run against a different
destination reach `CompleteInactive` with the same reported `cut`/`package`/
`plan` identities. A wrong plan pin on resume refuses and leaves the existing
destination bytes, the reopened `CompleteInactive` binding and portable
snapshot token unchanged; resume with the exact pins reaches `new_batches=0`
and leaves the existing inner full-`ImportBinding` resume check in force. The
original unpinned import suite, encrypted-recovery suite and complete required
repository gate remain.
