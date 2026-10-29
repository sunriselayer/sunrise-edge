# DR-0249: Genesis Standard Asset split/merge custody

Date: 2026-10-16

Status: Accepted design. Qualification is tracked in TODO.md.

## Decision

Extend the trusted-local-OS custody boundary (DR-0238, DR-0246) to the
genesis Standard Asset coin-owner operations `split` and `merge`. These are
the next bounded family because, like `transfer`, their only authority
precondition is coin ownership; `mint`/`burn` instead require the
`TreasuryCap` and remain unsupported in this profile.

The genesis/code/instance/fee-policy pin is not reverified or re-implemented:
a new private `asset_trust` module factors the existing verification into
`PinnedAssetTrust`, and both the transfer family (`asset_transfer`) and this
split/merge family (`asset_split_merge`) wrap it. Only the entrypoint,
argument shape and amount/overflow checks differ per family.

`split` takes one owned `Coin` Write, a strictly-partial positive amount
(`0 < amount < held`), and a recipient. Unlike `transfer`, the recipient may
legitimately equal the pinned publisher: splitting one's own coin is not a
transfer and is never refused for that reason. The recipient may just as
legitimately be a genuinely foreign address: `split` can move part of a
coin's value to anyone, so this family is not self-only housekeeping, and an
operator enabling `serve-split-merge` is authorizing real value transfers,
not merely coin bookkeeping. `merge` takes a destination
`Coin` Write and a distinct owned source `Coin` Consume, requires a positive
source amount, and refuses a checked-sum overflow before any network or
signing step. Both require a fee source that is owned and distinct from
every application input, with a positive maximum fee strictly below the fee
source's balance and the refund returned to the sender, matching `transfer`.

A new adapter-local message kind 3 carries both operations (a closed `split`/
`merge` operation tag selects the trailing fixed-field shape), under the same
`CUSTODY_WIRE_VERSION`. Kind 1 (publication) and kind 2 (transfer) keep their
existing decoders and `serve`/`serve-transfer` policies unchanged; a kind-3
frame is refused by both, and kind 1/2 frames are refused by the new
`serve-split-merge`. `custody prepare-split`/`approve-split`/`sign-split` and
the `-merge` equivalents mirror the existing offline transfer commands.

The ordinary paid `standard_asset split`/`merge` CLI accepts the same three
custody signer flags `transfer` already does; custody's own fee/asset/refund
pin checks apply identically. Every application input's canonical preimage
is captured in `operation.inputs` order and carried to custody, which never
trusts that order or any caller-claimed amount: it decodes, validates
ownership/schema/nominal type and recomputes every reference and amount
itself before rendering the review it requires a human to approve.

## Compatibility and lifecycle

No protocol encodings, cryptographic domains, execution effects, fee quote
ordering or historical vectors change. The kind-3 message is outside the
protocol namespace, by the same reasoning as kind 1/2. Approval, expiry and
revocation reuse the existing whole-frame store and lifecycle exactly;
nothing about recovery, rotation or revocation changes for this family.

## Limits

Same trusted OS/root, separate-UID model and limits as DR-0238/DR-0246.
`create-asset`, `mint`, `burn`, other packages/instances/epochs and automatic
protocol signing stay outside this profile. No real keys, host users, public
services or network activation are selected.
