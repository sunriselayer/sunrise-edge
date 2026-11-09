# DR-0291: Original bond inner Standard Asset profile

Date: 2026-11-09 (Asia/Singapore)

Status: Selected initial boundary; protected implementation and qualification pending.

## Context

[DR-0287](0287-bond-registration-structural-preview.md) and
[DR-0288](0288-successor-bond-registration-structural-preview.md) expose
non-authorizing registration previews. [DR-0289](0289-bond-outer-key-custody-and-split-approval.md)
selects outer validator-key isolation and two distinct content approvers, but
leaves the inner source-owner key and the executable transfer meaning open.
The prepared registration owner verifies an authenticated signed local leg and
the ordered handler independently checks its actual effects. Neither check
constitutes the source owner's attended content approval.

## Decision

The first inner collateral operation is limited to an **original-genesis**
`LocalExecutionIntent` Call of the signed genesis manifest's Standard Asset
Coin revision 1 `transfer` entrypoint. It transfers the entire one source
Coin, with no split or fee source, to the deterministically derived
`BondCollateral` deposit owner token for the intended new validator and
resource. The token is deliberately not an Ed25519 recipient address.
The locally verified manifest, reconstructed in-tree code artifact, empty
dependency closure, exact code digest, instance, type, schema, entrypoint and
execution policy must agree before any review or signature. The unsigned leg,
source Coin and predicted owner-only mutation are reviewed as one operation.

Trust the local OS. Isolate the source-owner key in a separate process and UID
from the CLI and the outer validator worker. The source-owner collateral
movement approver and the outer validator-registration approver are distinct
principals. Inner approval binds the exact unsigned leg, source object,
intended validator, resource, context and frame. Outer approval binds the
resulting exact signed leg, predicted row, original root and outer frame.
Neither worker provides a raw-frame or generic code-signing endpoint.

The existing paid Standard Asset transfer profile remains unchanged: its
canonical Ed25519 recipient and publisher-owned sender checks are correct for
that separate operation and must not be relaxed for bond deposits. The
existing local-execution and bond-registration frame formats remain unchanged.

## Limits and evidence required

Successor/live-epoch bond deposits are outside this initial slice and must be
refused by this adapter. The existing successor registration and seven-epoch/e8
qualification are not weakened. No actual real key, host user, security
policy or deployment is selected here.

The present custody approval records contain a key, expiry and frame but no
authenticated human approver identity. Terminal confirmation and the worker's
peer-UID check do not establish that the inner and outer content approvers are
different people. Protected signing must remain unavailable until an
attributable, independently enforceable two-principal approval contract is
implemented and verified. The role binding must survive expiry, revocation
and restart and refuse a changed frame, key, UID, role or code meaning.

Use the existing original bond CLI test owner for byte equality and actual
ordered registration effects, with separate inner and outer fixture identities.
Refusal tests cover unknown code/revision/dependencies/entrypoint, malformed
source and predicted effects, wrong identity/role/context, expired or revoked
approval, and changed content. Full required and exact-source CI evidence are
separate. This decision closes no M2 or release checkbox.
