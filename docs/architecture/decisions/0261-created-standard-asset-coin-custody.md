# DR-0261: Locally pinned application Coin custody

Date: 2026-10-17 (Asia/Singapore)

Status: Source contract. Qualification is tracked in TODO.md.

## Context

DR-0258 lets the protected mint/burn family target one Standard Asset created
by the pinned publisher. The transfer and split/merge families still always
validate application Coins against the genesis asset and target its instance.
Consequently an own-created asset can be minted and burned through custody,
but its owner cannot yet use custody to transfer, split or merge its Coins.

## Decision

Extend kind-2 transfer and kind-3 split/merge with DR-0258's exact optional
local `--asset`/`--instance-ref` pair. Preparation, approval, offline signing
and the bounded serving process each load their own independently trusted
pin. The ordinary Standard Asset CLI also accepts the pair with its custody
signer. The pair is never added to a wire request, and the client cannot
choose or replace the protected process's target.

All families reuse `ApplicationAssetPin::new`: one bounded exact-canonical
InstanceRecord under the pinned context and exact genesis-verified in-tree
code, revision one, the known initializer and the pinned publisher as creator.
The derived instance and supplied asset must not alias the genesis fee
instance or asset. This first extension accepts only assets created by that
publisher. The local record and object preimages do not prove existence or
currentness; execution remains authoritative.

Each operation's trust retains its fixed `PinnedAssetTrust` for fees and an
optional application pin for its own Call. The effective instance and asset
supply CallIntent.instance/type_arguments; application Coins validate against
that asset's own nominal Coin type. The fee source always validates against
the fixed genesis Coin type and fee policy. Neither an application Coin nor
its balance becomes fee authority. Existing ownership, schema, exact-preimage,
distinctness, recipient, amount, overflow, gas and maximum-fee rules remain.
Transfer still moves a whole Coin, split still requires a strictly positive
amount below the held value, and merge still consumes its distinct source.

The existing genesis identity lines keep their original meaning. A bound pin
adds six `application_*` lines showing the effective asset and complete
instance target alongside the genesis fee identity and full signing frame.
No pin emits no additional review bytes. Existing whole-frame approvals bind
the selected instance and type arguments: the same nominal Coin preimages
accepted under a different local instance cannot reuse an earlier approval.
Preparation and signing never grant an unapproved frame-signing interface.

The unchanged bounded private-file parser is shared with mint/burn so every
role enforces the same all-or-none flags, mode-0600 file, owned mode-0700
parent and 2,048-byte bound. A partial public CLI pair now refuses before
endpoint access. A complete pair follows the existing application query and
preimage path. create-asset defines no such flags and remains separate.

## Compatibility

No protocol version, canonical encoding, message kind, signature domain,
confirmation string, request schema, approval/revocation format, server
lifetime/resource bound or genesis fee meaning changes. Omitting the pair
selects the original genesis target/type and preserves review and frame
bytes. Existing genesis preparation/execution/replay and approval lifecycle
controls remain. Historical DR-0258 described mint/burn-only scope; this
record is the explicit subsequent extension, not a reinterpretation of it.

The optional application pin is immutable for a serving invocation. Switching
local pins requires a separately configured invocation and approvals for its
actual frames. A key change still changes the owner address and does not
migrate old Coins or approvals. No automatic or consensus signing is added.

## Verification

`asset_application_coin_tests.rs` declares pure controls for all three
operations: positive pinned preparation and both identity reviews, no-pin
genesis target, refusal of genesis/other-asset application Coins at every
position, unconditional genesis fee typing, constructor pin validation,
same-asset/different-instance approval refusal and genesis-approval refusal.
The positive approval controls call the existing in-process signing decision
and do not create a server. Synthetic application preimages are labeled as
such; these tests do not prove executed application effects or live state.

Offline command tests exercise their actual role specs and the shared bounded
pin reader. Existing mint/burn parser controls remain attached to that shared
reader. Public CLI tests cover all five Call verbs accepting a pair, partial
pair refusal before endpoint access, and the existing sender-refund rule.

Formatting/source inspection, owning compilation/tests, actual bounded CLI
and distinct-UID execution, complete required/hosted gates and release
qualification are distinct. No source-only check is an execution pass.

## Limits

The existing trusted-local-OS/root and separate-process/UID model remains.
This change adds no key provisioning, real keys/users/services, privileges,
dependencies, public listener, deployment or security audit. Foreign-creator
assets, key/ownership migration, all-family lifecycle evidence and automatic
protocol signing remain outside this slice; M2 is not complete from this
extension alone.
