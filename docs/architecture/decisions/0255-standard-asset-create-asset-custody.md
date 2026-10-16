# DR-0255: Standard Asset create-asset custody

Date: 2026-10-16

Status: Accepted design. Qualification is tracked in TODO.md.

## Decision

Extend the trusted-local-OS custody boundary (DR-0238, DR-0246, DR-0249,
DR-0253) to the ordinary paid `create-asset` operation: a paid
`PaidApplication::Instantiate` of the published, pinned genesis Standard
Asset package's own initializer, under a fresh application instance. This
is the next bounded family, and the only one that does not target the
pinned genesis instance at all: `transfer`/`split`/`merge`/`mint`/`burn`
all operate on the one genesis Standard Asset instance and its existing
`Coin`/`TreasuryCap` objects; `create-asset` creates a brand-new instance
and has no pre-existing application input to validate.

The genesis/code/policy pin is not reverified or reimplemented: this
family wraps the same private `PinnedAssetTrust` (DR-0246/DR-0249/DR-0253)
every other Standard Asset custody family shares. A new private
`AssetCreateTrust` wraps `PinnedAssetTrust` and adds only `create-asset`'s
own logic: independently deriving the exact new
[`InstanceTarget`](../../../crates/execution/src/call.rs) this intent signs
for from the caller-supplied seed and the trust's own pinned
sender/context/code (never from a caller-supplied target, code reference,
or digest), and rendering its own review. No new shared field is added to
`PinnedAssetTrust` itself; `create-asset` needs no `cap_tag`/
`validate_owned_cap`-equivalent addition, since it has no owned application
input beyond the fee source.

The published WASM initializer remains the sole execution oracle: custody
adds no new protocol math. Unlike `mint`/`burn`'s independently rebuilt
supply arithmetic, `create-asset` has no before/after amount to recompute —
the initializer always creates a fresh `Definition` and `TreasuryCap` owned
by the sender, with initial supply zero, for every caller. What custody
adds is an independent pre-approval review of the exact
sender/seed/context/pinned-code-derived `InstanceTarget` the signed intent
commits to, computed under custody's own pinned trust, never from a
caller-claimed target or any live query. Because the created `Definition`
and `TreasuryCap` object identifiers are derived at execution time (see
`derive_local_created_object_id`), this review explicitly states that they
are `unknown-until-execution`; it never claims a precomputed ID for them.

`create-asset` takes no owned application input beyond a fee source that is
owned and distinct from every other input, with a positive maximum fee
strictly below the fee source's balance and the refund returned to the
sender, matching every other family. The `CallIntent` itself carries no
application access entries, type arguments, or arguments — `Instantiate`
forbids application inputs at the protocol level
(`PaidApplicationScopes::Instantiate` carries no inputs) — matching the
existing ordinary paid `create-asset` CLI path exactly.

A new adapter-local message kind 5 carries this operation under the same
`CUSTODY_WIRE_VERSION`. Kind 1 (publication), kind 2 (transfer), kind 3
(split/merge) and kind 4 (mint/burn) keep their existing decoders and
`serve`/`serve-transfer`/`serve-split-merge`/`serve-mint-burn` policies
unchanged; a kind-5 frame is refused by all four, and kind 1–4 frames are
refused by the new `serve-create`. `custody prepare-create`/`approve-create`/
`sign-create` mirror the existing offline per-family commands, with their
own distinct `APPROVE-CREATE` typed confirmation line (never any other
family's confirmation string).

The ordinary paid `standard_asset create-asset` CLI now accepts the same
three custody signer flags every other family already does; custody's own
fee pin checks apply identically. The caller-supplied seed and the fee
source's canonical preimage are sent to custody, which never trusts the
caller's claimed target: it independently rederives the exact
`InstanceTarget` from the seed and its own pinned sender/context/code
before rendering the review it requires a human to approve.
`transfer`/`split`/`merge`/`mint`/`burn` stay on their own existing kinds
and are unaffected.

No genesis change is required to exercise this family: the existing
one-owner Docker fixture's single development owner is both the sole
genesis owner and `mint_authority` (DR-0196/`apps/devnet`), distinct from
the separate genesis authority (`DEVNET_PAID_GENESIS_SEED`) that actually
created the genesis Standard Asset instance, and from the separate fee
recipient. The custody publisher is this one development owner, exactly as
for `mint`/`burn`.

## Compatibility and lifecycle

No protocol encodings, cryptographic domains, execution effects, fee quote
ordering or historical vectors change. The kind-5 message is outside the
protocol namespace, by the same reasoning as kind 1–4. Approval and expiry
reuse the existing whole-frame store exactly; revocation is tested directly
for this family (tamper, expire, revoke, and refuse-to-restore-a-revoked-
record cases in `asset_create_tests.rs`). Key recovery and rotation are
architecturally shared code paths with every other family and are not
expected to differ, but — unlike revocation — neither is exercised by a
create-asset-specific test; this decision record does not itself
constitute acceptance evidence for recovery/rotation under this family.

A derived new `InstanceTarget` that happens to equal the pinned genesis fee
instance is refused as an actual collision. Reusing the same seed bytes as
some other creator (including the pinned genesis instance's own creator,
the separate genesis authority) is not, by itself, a collision: `creator`
is part of the hashed `InstanceRecord`, so a different creator legitimately
derives a different target from the identical seed bytes. Custody never
treats equal seed bytes alone as proof of a collision, and it never
independently proves the caller's seed is "fresh" against live chain state
before preparation — a reused seed can still fail, and charge the reviewed
fee ceiling, at actual execution.

## Limits

Same trusted OS/root, separate-UID model and limits as DR-0238/DR-0246/
DR-0249/DR-0253. Other packages, other epochs, and automatic protocol
signing stay outside this profile. New assets created through this family
remain unsupported by every other genesis-only custody family
(`transfer`/`split`/`merge`/`mint`/`burn` all stay pinned to the one
genesis instance); this decision does not widen them to any newly created
asset. No real keys, host users, public services, network activation,
asset owner/key migration, or security audit are claimed. No new
cryptographic primitive, canonical encoding, or protocol arithmetic is
introduced.
