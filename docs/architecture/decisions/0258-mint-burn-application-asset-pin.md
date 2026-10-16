# DR-0258: Optional mint/burn application asset pin

Date: 2026-10-16

Status: Accepted design. Qualification is tracked in TODO.md.

## Decision

Extend the existing genesis Standard Asset mint/burn custody family
(DR-0253) with one bounded capability: an operator may optionally bind
`custody prepare-mint`/`approve-mint`/`sign-mint`/`serve-mint-burn` (and
their `-burn` equivalents) to one independently, *locally* pinned
non-genesis Standard Asset application — a `Definition`/`TreasuryCap` pair
created earlier by the separate `create-asset` family (DR-0255) — instead of
the pinned genesis fee instance. Before this change, mint/burn's `cap_tag`/
`coin_tag` and `CallIntent.instance` always resolved to the one genesis
Standard Asset instance; an asset created through `create-asset` could never
be minted or burned through custody. This removes exactly that functional
limitation, without touching genesis fee authority, without widening
`transfer`/`split`/`merge`/`create-asset`, and without introducing a new
wire kind, protocol version, or canonical byte format.

The new local pin is two flags, matching the public Standard Asset CLI's own
names: `--asset` (a 32-byte object id) and `--instance-ref` (a bounded
canonical `InstanceRecord` private file), all-or-none. Both are read
directly from local operator input — exactly like `--genesis-manifest-file`
and `--genesis-digest` already are — never from the peer wire request. The
existing kind-4 `AssetMintRequest`/`AssetBurnRequest` wire shape is
unchanged; no new field, kind, or protocol version is added. Omitting both
flags is byte-identical to the original genesis-only behavior: the new
`asset_application_pin` module is never constructed, `AssetMintBurnTrust`'s
effective asset/instance/`coin_tag`/`cap_tag` fall back to the existing
genesis fields exactly as before, and the rendered review emits no
`application_*` line at all.

A new, small, dependency-light module (`asset_application_pin`) isolates
this pin's own verification, kept entirely separate from the shared
`PinnedAssetTrust` genesis pin so no other family's meaning changes:
`PinnedAssetTrust` itself, and every other family built on it
(`asset_transfer`, `asset_split_merge`, `asset_create`), are untouched.
Given the trust's own pinned context, exact verified in-tree Standard Asset
code, and publisher, `ApplicationAssetPin::new` independently:

- decodes the supplied `InstanceRecord` bytes, requiring the exact canonical
  re-encoding (`decode_instance_record` already enforces this) under a
  bounded size (`MAX_APPLICATION_INSTANCE_RECORD_BYTES = 2048`, matching the
  public CLI's own `MAX_INSTANCE_RECORD_BYTES`);
- requires the record's `context` and `code` to equal the trust's own
  pinned, genesis-verified context and code reference exactly — the
  application always runs under the identical verified in-tree Standard
  Asset package, never a different one;
- requires `revision == 1` and `initializer == public_standard_asset::INITIALIZER`;
- requires `creator` to equal the pinned custody publisher's own address —
  this first own-created-asset slice only supports an asset the custody
  publisher itself created;
- derives the exact `InstanceTarget` from the verified record and rejects it
  if it aliases the pinned genesis fee instance, and separately rejects the
  supplied asset id if it aliases the pinned genesis fee asset;
- derives this asset's own `Coin`/`TreasuryCap` nominal types
  (`coin_type_tag`/`treasury_cap_type_tag`) from the shared genesis code
  origin and the pinned asset id.

`AssetMintBurnTrust` holds this pin as `Option<ApplicationAssetPin>` and
exposes small effective accessors (`asset`/`instance`/`coin_tag`/`cap_tag`)
used to build `CallIntent.instance`/`type_arguments` and to validate the
application `TreasuryCap`/`Coin` inputs. The fee source is unaffected by any
application pin: `FeeSourceConsent` and the fee object's own validation
always use the pinned *genesis* `Coin` nominal type
(`PinnedAssetTrust::validate_owned_coin`), never the pinned application's —
fee authority and application authority are deliberately kept separate, and
a pinned application's own `Coin`/`TreasuryCap` preimage is refused as a fee
source by the unconditional genesis-type check. Checked mint/burn supply
arithmetic, input distinctness/access-mode checks, and fee ceiling/refund
checks are otherwise exactly as DR-0253 describes.

The rendered review always keeps the original genesis identity lines
(`asset=`, `instance_creator=`, `instance_seed=`, `instance_revision=`,
`instance_record_digest=`) with their original, unchanged meaning and
values. When an application pin is bound, six further lines
(`application_pinned=true`, `application_asset=`,
`application_instance_creator=`, `application_instance_seed=`,
`application_instance_revision=`, `application_instance_record_digest=`)
are appended, so a human approver always sees both identities — the genesis
fee identity the `FeeSourceConsent` still authenticates against, and the
application identity the `CallIntent` actually targets — plus the complete
signed frame, never only one. `freshness=enforced-at-execution-not-preparation`
is unchanged: a local pin is not a fetched or quorum-certified live-state
proof that the pinned asset or instance actually exist or are current;
exactly like every other family, that remains execution-only.

`PinnedAssetTrust` gains one small, purely mechanical refactor in support of
this: `validate_owned_object`, a generic owner/schema/nominal-type check
parameterized by an explicit `ScopedTypeTag`, which `validate_owned_coin`/
`validate_owned_cap` now delegate to with their own fixed genesis tags. This
changes no behavior or error message for any existing caller; it exists so
the mint/burn family's own `validate_application_cap`/`validate_application_coin`
can reuse the identical check against the *effective* (genesis-or-pinned)
tag instead, which is the one new piece of generic authority this decision
introduces, and it is confined to `AssetMintBurnTrust`.

## Compatibility and lifecycle

No protocol encodings, cryptographic domains, execution effects, fee quote
ordering, or historical vectors change. The kind-4 wire shape, canonical
`AssetMintRequest`/`AssetBurnRequest` encodings, and every existing stable
test vector are unchanged. `transfer`/`split`/`merge`/`create-asset` do not
gain this capability: their own CLI gates (`commands/standard_asset.rs`)
continue to refuse a custody signer combined with `--asset`/`--instance-ref`
with the exact same `"custody signing requires the genesis asset"` message
as before this change; only `mint`/`burn` now accept the pair. Approval and
expiry continue to reuse the existing whole-frame store exactly: the
approved frame comparison in `sign_mint_burn_request` is unaffected,
because the application pin changes the exact frame `prepare_mint`/
`prepare_burn` compute (via the effective instance/type arguments), not the
approval mechanism comparing it.

## Tests

Pure, owning unit tests were added in this slice. These have been **written,
not run**: no `cargo check`/`test`/`clippy`/`fmt` was executed while adding
them, and nothing here is compiler-verified.

`asset_mint_burn_commands.rs` (`application_pin_selection_tests`) covers
all-or-none flag parsing, exact asset-id/record-byte round-tripping, and the
oversized-file bound. `asset_mint_burn_tests.rs` covers: byte-identical
no-pin review/target; successful pin-targeted mint preparation with both
identities shown in the review; a positive pinned `burn` through
`validate_application_coin`; fee/application validation separation using an
actual application-typed `Coin` (not merely a `TreasuryCap`) as the rejected
fee preimage; genesis-cap and genesis-coin type-confusion refusals under a
pin; wrong-context/code/initializer/creator refusal (asserted against the
one typed `CliError`/exact shared message the check actually returns, not
only `is_err()`); a non-one revision's encode-time rejection;
genesis-fee-asset aliasing refusal; a record that honestly satisfies the
creator check yet actually derives the genesis fee instance, reaching the
alias guard through a constructor-only `CustodyConfig` whose publisher is
the genesis instance's own verified creator (no real signer/key change); a
non-canonical (trailing-byte) record rejection; a stale cross-application
approval under the identical pinned asset but a different valid
own-creator instance, refused only by the full frame comparison even though
both instances' cap/coin type checks pass identically; and a genesis (no
pin) approval that cannot authorize a pinned-application request. The last
two call `server::sign_mint_burn_request` directly as a pure in-process
function (no Unix socket, no live `serve` process). No live CLI, Docker
fixture, or full required/CI gate run is part of this slice. Qualification
status and any Docker fixture extension belong in
[TODO.md](../../../TODO.md), not here.

## Limits

Same trusted OS/root, separate-UID model and limits as DR-0238/DR-0246/
DR-0249/DR-0253/DR-0255. This decision adds no key generation, key storage,
or fixture change, and claims no real keys, host users, public services,
network activation, or security audit. It does not widen `transfer`/
`split`/`merge`/`create-asset`, does not change genesis fee authority or the
meaning of the shared `PinnedAssetTrust` genesis pin for any family, and
does not introduce a new wire kind, protocol version, or canonical encoding.
A locally pinned application is never independently fetched, queried, or
otherwise proven current by this capability; that remains execution-only,
exactly like every other family.
