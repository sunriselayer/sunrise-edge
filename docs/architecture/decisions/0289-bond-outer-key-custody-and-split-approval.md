# DR-0289: Bond outer-key custody and separate content approvals

Date: 2026-11-09 (Asia/Singapore)

Status: Selected boundary; implementation and qualification pending.

## Context

[DR-0287](0287-bond-registration-structural-preview.md) and
[DR-0288](0288-successor-bond-registration-structural-preview.md) provide
seed-free original and verified-successor previews. Both remain
`approved=false`, `signed=false`, `executed=false`, and
`leg_semantics=unreviewed`. The source owner signs the collateral-transfer
leg; the new validator signs the outer registration. A coherent prepared
frame or a protocol-admitted code revision is not human approval of its
generic-contract effects.

## Decision

For the **outer new-validator registration key** in original and verified
successor scope, trust the local OS and isolate the key in a separate process
and UID from the CLI and registration owner. Trusted local configuration must
pin the role, expected public key, permitted registration domain and scope.
The prepared owner recomputes the exact frame for each operation, and that
frame is bound to the operation-specific approval.
Reuse the existing prepared registration owner and independent returned-
signature verification. This selection grants no general raw-frame signing
endpoint or authority beyond the approved operation.

The content approver for the source-owner collateral movement and the content
approver for the outer validator registration must be distinct principals.
The inner approval binds the exact unsigned collateral leg, intended validator,
resource and context before inner signing. The outer approval binds the
resulting exact signed leg, predicted row, root or successor scope and outer
prepared frame before outer signing. Verify that these two stages are linked
and that the approvers are distinct. Refusal, expiry, revocation,
wrong key, changed content or unknown semantics must fail closed before a
protected signature is returned.

## Limits and next evidence

This decision does **not** select custody for the inner source-owner key, an
approved generic code revision/dependency closure/entrypoint or its understood
collateral effects, real people/UIDs/keys, enrollment, recovery, revocation
procedure or release qualification. Independent semantic approval of the inner
leg is required before actual protected bond signing. Real enrollment, recovery
and release qualification remain production gates; disposable fixture keys can
exercise the bounded implementation before those gates. Existing protocol
framing, resource authority, membership admission and development signing
behavior remain unchanged.

Implementation must reuse the original and successor prepared owners and the
existing genuine test owners. Verify exact reviewed bytes, two distinct
approvals, wrong-key/content/role refusal, restart and revocation, and actual
registration effects without reducing the seven-epoch/e8 successor selector.
Record exact-source required and CI results in TODO. This selection closes no
M2 or release checkbox.
