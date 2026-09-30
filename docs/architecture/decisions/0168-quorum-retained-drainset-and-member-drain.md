# DR-0168: Quorum-retained DrainSet and certified member drain

## Decision

Accepted implementation boundary, 2026-09-30. Extend
[DR-0167](0167-frozen-frontier-extraction-boundary.md) with one usable capability:
independently reconstruct a quorum-selected frozen frontier union, durably
retain its complete proof material before voting for an ordered DrainSet, and
apply an explicitly selected certified member through native HTTP, Rust SDK
and CLI. Work status and validation belong only in `TODO.md`.

This extracts part of [DR-0154](0154-complete-epoch-handoff.md), not the whole
aggregate handoff implementation. Authenticated cut/import, conditional
readiness, Seal and next-epoch activation are separate prerequisites for live
rollover. The existing refusal of fresh Logical activation remains in force.

## Authority and possession

Only the currently serving outgoing committee, the actual committed Freeze
and the fresh signed-v3 genesis/profile authorize this capability. A request,
local configuration, timeout, descriptor digest or coordinator assertion
cannot upgrade an old profile or reopen admission. Preserve historical bytes,
existing publication/artifact/ACK addresses and original user replay.

Authenticate a strictly greater-than-two-thirds weighted selection of unique
frontier signers under the locally pinned outgoing context. Each selected
descriptor must bind the same chain, protocol, epoch, atomicity domain and
committed Freeze request/height. Independently verify every consecutive page
through its signed terminal count/accumulator. A valid partial page or vote
does not establish completeness. Deduplicate only identical operation
identities; contradictory identities for the same request fail closed.

Every voter reconstructs the deterministic union and durably verifies and
retains every member's full FastCertificate, original signed intent, witness
and actual replay artifact closure before exposing a DrainSet vote. Retention
does not execute contracts or install receipts, nonces, fees or availability
ACKs. Local readiness and its exact dependency revisions join vote/commit
fences; a transient download, earlier holder's ACK or readiness digest alone
is insufficient. Use bounded resumable steps and the existing store's
aggregate transaction limits. Never expose a signature on an ambiguous commit.

DrainSet uses the existing shared HotStuff operation chain, leader/view/lock
rules and ordinary three-chain commitment. An uncommitted candidate is not
drain authority. Preserve inherited high/locked QCs and the existing
same-event Freeze admission checks. No second epoch-control chain, force
flag or later business-free Seal barrier is imported merely to make this
capability compile.

## Proof relay is separate from descriptor authority

A selected descriptor's signature fixes membership, not the only permitted
artifact supplier. Source endpoints are untrusted locators. Fetching from a
different current-committee replica cannot change the selected descriptor or
relax any certificate, intent, witness, manifest, digest, context or exact
artifact verification.

Permit independently re-verified imported drain material to be relayed after
its confirmed retention. Original pre-Freeze publication material remains
available under its unchanged address and verification rules. An imported
proof need not manufacture a pre-Freeze ACK or frontier membership. This
separation is necessary when the sole original full-proof holder fails after
the DrainSet commitment: the honest intersection of its voting quorum must
still be able to supply the retained obligation. Keep source and selected
signer mappings distinct and bound every retry by explicit work/deadline caps.

## Narrow member application

An actual committed DrainSet authorizes only its independently verified full
certificate members in the still-current frozen epoch, even when no aggregate
availability certificate was retained. A partial prepare is not a member.
Re-derive the original signed operation and deterministic commitment through
the ordinary generic paid execution engine; Standard Asset receives no
special node-core path. Original effects, charged-trap semantics, fee settlement,
receipt, nonce and logical provenance must agree with that certificate.

Missing code, instance, object-version or nonce prerequisites stop progress.
Request-ID union ordering is not causal execution ordering or proof that all
members have drained. This capability exposes explicit member application
and exact recovery, not an automatic complete-drain/cut assertion. No
indeterminate or missing prerequisite becomes a deterministic no-effect
original-user receipt.

A verifying member may resolve only the exact observed local conflicting
partial reservations necessary for its application. Verify the full
certificate, committed membership and actual conflict first. Fence those
rows and retain a local resolution audit in the same atomic commit as the
original application. Preserve unrelated reservations, newer heads, original
receipts and nonces. No global abort, arbitrary unlock, rollback, second fee
charge or synthetic receipt is authorized. Completed exact replay remains
read-only and returns the original bytes before fresh execution.

## Acceptance

Exercise genuine PostgreSQL-backed validator processes through a separately
compiled CLI. Include ordinary paid Publish/Instantiate/Call, Standard Asset
operations and a charged trap. Certify an unapplied operation with A/B/C,
retain its full proof initially only on A without aggregated ACKs, and keep a
conflicting partial preparation on D. Commit real Freeze, import the complete
selected frontier union/material, and normally order DrainSet only after
each voter has its complete durable closure.

After commitment, stop A and retrieve its obligation from an imported-proof
relay. Restart a recipient during retained progress and after application.
Explicitly drain the missing certified member, preserve every other existing
reservation row and the original partial prepare, and compare exact original replay, object/history, receipt,
nonce and fee state without reapplication. Compare complete same-replica
rows/revisions for read-only and refusal claims.

Add stable independent public-frame vectors and adversarial tests for weak or
forged quorums, mixed Freeze/context selections, missing/duplicate/reordered
pages, changed/corrupt/oversized artifacts, incomplete possession, premature
votes, membership substitution, stale writers, CAS races, missing causal
prerequisites and indeterminate commits. Full repository validation, required
CI and fresh explicit exact-head independent approval remain merge gates.

This does not establish cut completeness, a new ready validator set,
activation, Delivery 3 completion, public deployment, real custody, independent
operational control, load/HA/provider certification or production readiness.
