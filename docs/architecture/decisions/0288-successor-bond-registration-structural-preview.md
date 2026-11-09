# DR-0288: Verified-successor bond-registration structural preview

Date: 2026-11-08 (Asia/Singapore)

Status: Implemented structural preview. It grants no protected signing,
trusted approval or release qualification.

Later scope note (2026-11-09): [DR-0289](0289-bond-outer-key-custody-and-split-approval.md)
selects the outer-key boundary and separate approvers only. The structural
preview remains nonauthorizing; protected signing and semantic approval are
still unimplemented.

## Context

[DR-0287](0287-bond-registration-structural-preview.md) introduced a seed-free
original registration preview and deliberately refused successor pins. The
existing successor development signing route already prepares a registration
against a verified chain and current e+1 context, retaining the original
resource authority. Its genuine recurring owner constructs and submits the
registration, but a seed-free inspection path was absent.

## Decision

Allow the same `economics bond-registration-preview` command with a complete,
verified successor archive selection. The CLI uses the existing successor
pin loader and prepared registration owner. Partial pins, a declared context
other than the verified current e+1 context, wrong authorization key, invalid
leg/row and signing/output flags fail before a preview is returned. The
retained successor owner and original resource authority are not replaced.

Original and successor previews share one canonical signed-leg, predicted-row,
row-digest, outer-intent and signing-frame recomputation. The output identifies
`scope=successor` and remains `approved=false`, `signed=false`,
`executed=false`, and `leg_semantics=unreviewed`. It writes no artifact and
makes no signing call. The existing development signing path and protocol bytes
are unchanged.

## Verification and remaining boundary

The original CLI test owner retains argument and refusal checks. The existing
genuine recurring successor owner compares preview bytes with its prepared
registration, refuses an old context or changed row, and invokes the CLI
preview before its signed registration. This adds no second successor fixture
or shortened epoch path. Exact test and full-gate results belong in TODO.

The preview cannot recognize whether a coherent replacement of untrusted
inputs was previously approved. Bond authority, recognized leg semantics,
attended review, protected custody, recovery and revocation remain M2-N3/N4
work. This decision closes no M2 or release checkbox.
