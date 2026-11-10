# DR-0291: Original bond inner Standard Asset profile

Date: 2026-11-09 (Asia/Singapore)

Status: Selected initial boundary; development implementation committed, qualification pending.

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

## Later implementation note (2026-11-10)

The nonauthorizing `bond-inner-preview` can optionally query an endpoint for
the declared source object. It first compares the endpoint's reported protocol
context to the local pin, then requires a current inline result whose
recomputed digest, creating chain/protocol, version, canonical bytes and exact
access reference match the reviewed local Coin. Absent, tombstoned, blob-only,
historical, changed and malformed responses refuse before any review output.

This is a check against an **endpoint-reported** current snapshot. A matching
response and body digest do not prove that the endpoint's claimed head is the
current chain state. The review therefore retains
`source_snapshot_unverified=true` and explicitly says the query is not a
chain-state proof. The command remains unable to approve, sign, register or
execute. The two-principal approval broker, separately isolated keys, actual
registration and release qualification remain pending.

The original `bond-registration-preview` can also require the complete
source Coin/key pair and rebuild the manifest-pinned inner request from the
already signed leg. It compares the exact unsigned intent with that leg, and
the predicted custody reference and amount with the outer row. The row's
authority remains a separate caller prediction for the ordered handler. Only
then does it label the leg's bounded Standard Asset meaning as
recognized. The supplied Coin is still a caller snapshot, so this joined
preview explicitly retains the unverified-source warning. Successor scope
cannot select this check. It does not create an approval or signature.

## Later protected-fixture note (2026-11-10)

The original-genesis fixture now reconstructs the pinned whole-Coin transfer
inside a separate source-owner key worker. A broker checks the inner and outer
approval records, distinct approver UIDs, expiry and tombstones before
releasing either verified signature. The worker accepts only a typed operation,
not an arbitrary frame. The fixture uses disposable UIDs and keys; it neither
proves the source snapshot current nor establishes actual human approver
identity, executes the ordered transfer/registration, or qualifies release.
Full required and exact-source CI remain open.
