# Standard Asset create-asset custody

[DR-0255](decisions/0255-standard-asset-create-asset-custody.md) adds the
`create-asset`-only family to the trusted-local-OS boundary. This guide
describes the implemented contract; qualification status belongs in
[TODO.md](../../TODO.md).

## Trust and operation

Custody's genesis/code/policy pin is the exact same verification as
[genesis Standard Asset transfer custody](standard-asset-transfer-custody.md),
[split/merge custody](standard-asset-split-merge-custody.md) and
[mint/burn custody](standard-asset-mint-burn-custody.md), factored into the
shared private `PinnedAssetTrust` so this family never reimplements or
re-derives it. A new private `AssetCreateTrust` wraps that one trust and
adds only `create-asset`'s own new-instance derivation and review; no new
field is added to `PinnedAssetTrust` itself, since this family has no
pre-existing owned `Coin`/`TreasuryCap` input to validate.

Unlike every other family, `create-asset` does not target the pinned
genesis Standard Asset instance: it targets a *fresh* one. Custody
independently derives the exact
[`InstanceTarget`](../../crates/execution/src/call.rs) the signed intent
commits to from the caller-supplied seed and this trust's own pinned
sender (the custody publisher), context, and code — the same
`InstanceRecord`/`instance_target` production SDK derivation the ordinary
paid `create-asset` CLI path already uses
(`commands/standard_asset.rs::run`'s own instantiate branch) — never from a
caller-supplied target, code reference, or digest. A derived target that
*actually equals* the pinned genesis fee instance is refused as a real
collision; reusing the same seed bytes some other creator already used
(including the genesis instance's own creator, the separate genesis
authority) is not itself a collision, since `creator` is part of the
hashed instance record and a different creator legitimately derives a
different target from identical seed bytes. Custody never independently
proves a seed is "fresh" against live chain state before preparation: a
reused seed, or one that now collides with an instance created since this
review was rendered, is refused only by execution itself, after this exact
reviewed fee ceiling may already have been charged up to `max_fee` — see
the review's own `freshness=enforced-at-execution-not-preparation` and
`seed_reuse_or_existing_instance=refused-only-at-execution-may-still-charge-up-to-max-fee`
lines.

The published WASM initializer remains the sole execution oracle. There is
no pre-existing application `Coin`/`TreasuryCap` and no before/after
arithmetic for custody to recompute: the initializer always creates a
fresh `Definition` and `TreasuryCap` owned by the sender, with initial
supply zero, exactly as it does for every other caller
(`commands/standard_asset.rs::validate_created_asset`). Because the
created `Definition`/`TreasuryCap` object identifiers are derived at
execution time, never from inputs known before execution, the review
explicitly states `created_definition=unknown-until-execution` and
`created_treasury_cap=unknown-until-execution` rather than ever guessing or
precomputing one.

`create-asset` takes no owned application input beyond a fee source that
is owned by the custody publisher and distinct from every other input,
with a positive maximum fee strictly below the fee source balance, and the
refund returned to the sender — the same fee shape as every other family.
The signed `CallIntent` itself carries empty access entries, type
arguments and arguments, matching `Instantiate`'s own protocol-level
prohibition on application inputs.

The complete bounded review displays the pinned genesis code/policy
fields, the pinned genesis fee instance (for comparison), the newly
derived instance's own creator/seed/revision/record digest, the
initializer name, explicit `type_arguments=none`/`access=none`/
`arguments=none` lines (not only the opaque signed frame hex), the
`unknown-until-execution`/`initial_supply=0` created-object notes, the fee
balance/ceiling/refund/full policy, context/nonce/request fields, the
execution-only seed-freshness disclosure above, and the complete signed
frame.

## Independent preparation, approval and serving

```bash
sunrise-edge-cli custody prepare-create \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --seed <64-hex-seed> --fee-source-file /private/fee.bin \
  --nonce 0 --request-id <64-hex-request> \
  --max-fee 1000000 --gas-limit 200000 --out /private/create-request.bin

sunrise-edge-cli custody approve-create \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --request-file /private/create-request.bin --approvals-dir /private/approvals \
  --expires-in-seconds 3600

sunrise-edge-cli custody serve-create \
  --config /private/config --key-file /private/custody.seed \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --socket /custody-run/create.sock --approvals-dir /private/approvals \
  --max-connections 8 --max-requests 8 --total-deadline-secs 300
```

Approval requires a real terminal, renders the full review and requires
the exact typed `APPROVE-CREATE` confirmation line (never any other
family's confirmation string). `custody sign-create` is the offline
alternative, exporting the ordinary signed paid intent after independent
finalization.

## Actual CLI consumer

The existing `standard_asset create-asset` CLI now accepts the same three
custody signer flags every other family already does, with its ordinary
endpoint/context, instance-seed/instance-ref-out, fee, nonce, request and
gas flags. It captures the fee source's exact canonical preimage and sends
it to custody alongside the caller-supplied seed; the protected side
independently rederives the new instance target and renders its own
review before signing. `transfer`/`split`/`merge`/`mint`/`burn` are
unaffected and stay on their own kinds.

No genesis change is required to exercise this family against the
existing one-owner Docker fixture: its single development owner is both
the sole genesis owner and `mint_authority`, so it already owns a fee
`Coin` — distinct from the separate genesis authority (which created the
genesis instance and owns no `Coin`/`TreasuryCap`), and from the separate
fee recipient.

## Lifecycle and limits

`custody revoke` reuses the existing durable store exactly as DR-0246/
DR-0249/DR-0253 describe, and this family's own revocation, expiry, and
tampered-or-restored-record refusals are directly tested
(`asset_create_tests.rs`). The contained fixture adds a create-specific
same-key recovery consumer described below. Full key rotation and ownership
migration remain separate from this consumer. New assets
created through this family remain unsupported by every other
genesis-only custody family; this does not widen `transfer`/`split`/
`merge`/`mint`/`burn` to any newly created asset. Actual source and
execution qualification, including any Docker fixture extension, belong in
[TODO.md](../../TODO.md).

### Same-key recovery consumer

The initial live consumer uses the earlier preparation described below.
This later historical consumer retains its own independent copy sequence.

After the original create-asset, its revoked restart and all own-created
mint/burn/E67/Coin follow-ons have stopped, the fixture prepares a fresh `9d`
request using the original public instance seed, canonical fee preimage and
nonce. This is offline signing only. That seed's instance already exists and
the fee/nonce preimages are historical: no second `Instantiate` is submitted
and no live freshness or execution success is claimed.

The request receives its own full attended `APPROVE-CREATE` review. An
original-key `serve-create` signs this exact fresh frame, then exits and loses
its socket before the existing custody-UID backup/restore helper runs. A
recovered-key `serve-create` must produce identical complete signed bytes
through the real `sign-create` CLI and its independent finalization. The old
`95` revocation remains effective; cancelling `9d` refuses it in the same
process, and a recovered-key restart refuses both IDs again. The exact
reference/recovery/restart counts are 1/1/1/0, 3/3/1/2 and 2/2/0/2.

Original config/genesis/fee/request and approval/revocation attachments, the
fresh reviewed request and the same-frame reference must remain unchanged.
Eight generated files stay private at mode 0600, and four refused output paths
must stay absent. The added source control has nine direct CLI children, one
PTY, three bounded signers and two custody-UID private-copy children, with
16 KiB generated-file, 32 KiB captured-output and 2 KiB summary suballocations
inside the unchanged fixture totals. All original/T/G cases and counters
remain. Source coverage and actual execution qualification are distinct;
[TODO.md](../../TODO.md) owns the latter.

### Initial live recovered-key consumer (2026-10-30)

[DR-0282](decisions/0282-initial-recovered-application-key.md) prepares the
same disposable identity before the first create-asset operation in each
application recovery profile. A separate empty-signer-registry check precedes
the existing custody-UID backup/restore helper. Its two waited copy children
create `/work/custody-keys/custody.seed.backup` and
`/work/custody-keys/custody.seed.restored`; these paths were previously unused
in these fresh application allocations. All three files must be distinct
regular, single-link, custody-owned mode-0600 files. The pair adds two files,
130 logical bytes for the existing 65-byte key format, under the helper's
unchanged maximum of 512 bytes for two copies.

The initial `serve-create` and its revoked restart select that restored path.
The same early path serves the initial own-created mint/burn and its restart.
Each actual child-argv selection is recorded and checked independently in
Python and Node. The new `initial_application_recovery` evidence is separate
from historical recovery allocations and the original 47 setup predicates;
it records the exact two paths, generated bytes, two waited private-copy
children and zero extra CLI, PTY or signer children. Per-profile total private
recovery-copy children increase from six to eight, while every historical
phase keeps its original two.

The first paid create still uses its original seed, nonce, request, fee and
review. Its live counters remain 3/3/2/1, with 1/1/0/1 after revocation and
restart. Full frame/signature byte comparisons, independent created-object
and receipt/replay checks, original-seed isolation probes and all resource,
capture, PTY and deadline limits remain. The later `9d` reference still signs
with the original key, stops, and then creates its own backup/restored pair;
its historical request is never submitted. Actual qualification belongs in
TODO.md and does not follow from source changes alone.
