# Genesis Standard Asset mint/burn custody

[DR-0253](decisions/0253-genesis-standard-asset-mint-burn-custody.md) adds
the `TreasuryCap`-owner-only family to the trusted-local-OS boundary. This
guide describes the implemented contract; qualification status belongs in
[TODO.md](../../TODO.md).

## Trust and operation

Custody's genesis/code/instance/policy pin is the exact same verification as
[genesis Standard Asset transfer custody](standard-asset-transfer-custody.md)
and [split/merge custody](standard-asset-split-merge-custody.md), factored
into the shared private `PinnedAssetTrust` so this family never reimplements
or re-derives it; only the entrypoint and supply-arithmetic checks differ.
The one addition to shared trust is the genesis `TreasuryCap` nominal type
(`cap_tag`) and `validate_owned_cap`, checked identically to `validate_owned_coin`.

The published WASM remains the sole execution oracle. Custody never computes
new protocol math and never changes what the contract itself enforces
on-chain; it independently decodes the exact same inputs the contract would
read and performs the exact same checked arithmetic as an *advance, local*
review, so the human approver sees the outcome for the referenced cap/coin
preimage versions before ever typing the confirmation line — not merely the
caller's claimed amount. This is computed from caller-supplied, hash-bound
preimages, not independently fetched live chain state; currentness is still
enforced only at execution (the review's own
`freshness=enforced-at-execution-not-preparation` line), not at this
preparation step.

`mint` owns one `TreasuryCap` (Write) and a distinct owned fee source.
Custody decodes the cap's current supply from its own verified preimage,
rejects a zero amount, and rejects a checked-addition overflow before any
approval or signing step. `burn` owns one `TreasuryCap` (Write) and consumes
a distinct owned whole `Coin` (Consume) — never a partial amount — plus a
distinct owned fee source. Custody decodes the cap's current supply and the
coin's exact amount from their own verified preimages, rejects a zero-amount
coin, and rejects a checked-subtraction underflow before any approval or
signing step. Both require a positive maximum fee strictly below the fee
source balance, with the refund returned to the sender — the same fee shape
as every other family. `create-asset` is its own separate kind-5 custody
family (see [Standard Asset create-asset
custody](standard-asset-create-asset-custody.md), DR-0255), not an
extension of this one. Other packages/instances/epochs and automatic
protocol signing stay out of scope.

The complete bounded review displays the operation, sender and (for `mint`)
recipient, the `TreasuryCap` reference and its Write access mode, (for
`burn`) the whole `Coin` reference and its Consume access mode plus the
exact burned amount, the independently rebuilt supply before and after, the
fee balance/ceiling/refund/full policy, every one of the four pinned
instance fields, context/nonce/request fields and the complete signed
frame. Currentness is enforced by execution. A supplied object body alone is
not current-state proof.

## Independent preparation, approval and serving

```bash
sunrise-edge-cli custody prepare-mint \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --cap-file /private/cap.bin --fee-source-file /private/fee.bin \
  --amount <positive> --recipient <64-hex-address> \
  --nonce 0 --request-id <64-hex-request> \
  --max-fee 1000000 --gas-limit 200000 --out /private/mint-request.bin

sunrise-edge-cli custody approve-mint \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --request-file /private/mint-request.bin --approvals-dir /private/approvals \
  --expires-in-seconds 3600

sunrise-edge-cli custody serve-mint-burn \
  --config /private/config --key-file /private/custody.seed \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --socket /custody-run/mint-burn.sock --approvals-dir /private/approvals \
  --max-connections 8 --max-requests 8 --total-deadline-secs 300
```

`prepare-burn`/`approve-burn` take `--cap-file`/`--coin-file` in place of
`--amount`/`--recipient`; one `serve-mint-burn` invocation accepts both
operations under the one closed kind-4 decoder, exactly as `serve-split-merge`
is the sole kind-3 consumer. Approval requires a real terminal, renders the
full review and requires the exact typed `APPROVE-MINT`/`APPROVE-BURN`
confirmation line (never split/merge's or transfer's confirmation strings).
`custody sign-mint` and `sign-burn` are the offline alternatives, exporting
the ordinary signed paid intent after independent finalization.

## Actual CLI consumer

The existing `standard_asset mint`/`burn` CLI accepts the same three custody
signer flags `transfer`/`split`/`merge` already do, with its ordinary
endpoint/context, treasury-cap, amount/recipient or coin, fee, nonce,
request and gas flags. It captures every owned application input's exact
canonical preimage (the `TreasuryCap`, then the `Coin` for `burn`) and sends
them to custody alongside the fee source preimage; the protected side
independently decodes, validates ownership/schema/nominal type, and
recomputes every reference, amount and the exact before/after supply before
rendering its own review. `create-asset` is now supported under its own
separate kind-5 family (DR-0255), not an extension of this one;
`transfer`/`split`/`merge` are unaffected and stay on kind 2/3.

No genesis change is required to exercise this family against the existing
one-owner Docker fixture: its single development owner is both the sole
genesis owner and the fixed `mint_authority`, so it already owns the
installed `TreasuryCap<A>` — distinct from the separate genesis authority,
which owns no `Coin` or `TreasuryCap`.

## Optional application asset pin (DR-0258)

[DR-0258](decisions/0258-mint-burn-application-asset-pin.md) adds one
optional, independently local pin to this family: `--asset` (a 32-byte
object id) and `--instance-ref` (a bounded canonical `InstanceRecord`
private file), all-or-none, accepted by `prepare-mint`/`approve-mint`/
`sign-mint`/`serve-mint-burn` and their `-burn` equivalents, matching the
public Standard Asset CLI's own flag names. Neither value ever comes from
the peer wire request. Omitting both flags is byte-identical to the
genesis-only behavior described above. When bound, the new
`asset_application_pin` module independently verifies the record's context,
exact genesis-verified code, revision one, known initializer and the pinned
custody publisher as creator, rejects a derived instance or asset that
aliases the pinned genesis fee instance/asset, and derives this asset's own
`Coin`/`TreasuryCap` nominal types — never from a peer-supplied target. The
fee source keeps validating against the genesis `Coin` type regardless; only
the application `TreasuryCap`/`Coin` inputs and the `CallIntent` target use
the pinned asset. The review shows both the genesis and (when bound) the
pinned application identity. This lets mint/burn target an asset created by
the separate `create-asset` family (DR-0255), which no prior family could
do. [DR-0261](decisions/0261-created-standard-asset-coin-custody.md) subsequently
extends the same local pin to transfer/split/merge; create-asset remains its
separate profile. See DR-0258 for this family's original verification and
compatibility details, and TODO.md for qualification status.

Each role must own its instance pin file at mode `0600` in an owned `0700`
directory. Public `create-asset --instance-ref-out` output follows the
operator's file-creation mask, so its owner must make it private or install
an owned private copy before passing it to a custody command. The custody
process receives its own independently trusted protected copy; the peer
request never supplies that path or changes the server's application pin.
The local fixture keeps its existing capabilities and uses each process's
own UID for error cleanup signals.

## Lifecycle and limits

`custody revoke` reuses the existing durable store exactly as DR-0246/
DR-0249 describe, and this family's own revocation, expiry, and tampered-
or restored-record refusals are directly tested
(`asset_mint_burn_tests.rs`). The contained fixture also has the genesis
same-key recovery consumer described below. Its ordinary live mint/burn
operations and revoked restart also use the already stopped, distinct recovered
genesis key path, following [DR-0280](decisions/0280-live-recovered-genesis-mint-burn.md).
The earlier E67 consumer covers the separate own-created application profile;
neither consumer proves full key rotation or ownership migration. Actual source
and execution qualification belong in [TODO.md](../../TODO.md).

### 2026-10-17 genesis same-key recovery consumer

After the original genesis mint/burn native host, signer and revoked restart
have been waited, with their PIDs and socket absent, the fixture prepares two
fresh historical signing-only requests. Mint `9e` uses the original genesis
TreasuryCap and fee preimages, amount 5,000,000, the same recipient and nonce 0.
Burn `9f` uses the retained `burn-inputs` cap, Coin and fee exported after the
ORIGINAL `93` mint, with nonce 1. No `9e` execution creates those burn inputs:
the original `94` burn has already tombstoned that Coin and advanced the
ledger to nonce 2. The new signatures are never submitted or claimed current.

Each fresh request receives its own full `APPROVE-MINT` or `APPROVE-BURN` PTY
review, while pipe approval refuses. An original-key reference signer signs
both exact new frames and is actually waited, with PID and socket absent,
before the existing two custody-UID private backup/restore children run.
Recovered-key `sign-mint` and `sign-burn` must independently finalize and
export identical complete signed bytes for each SAME reference frame. Old
revoked `93`/`94` refuse; cancelling `9e`/`9f` refuses them in the same recovered
process; a recovered-key restart refuses all four IDs again. Each of the
eight refusal paths must remain absent. Reference/recovery/restart counts
are exactly 2/2/2/0, 6/6/2/4 and 4/4/0/4.

Seventeen original trust, preimage, request, approval and revocation
attachments, six fresh reviewed request/approval attachments and both
reference attachments remain unchanged. Direct bounded readers inspect only
nonsecret evidence; key bytes stay inside the existing custody-UID copies.
The normal addition is 18 CLI children, two PTYs, three signers and two
private-copy children (25 total), with fourteen private mode-0600 files and
32 KiB generated-file, 48 KiB captured-output and 4 KiB summary suballocations.
All global limits and original/C/T/G controls and business assertions remain.
This describes source coverage; actual qualification remains separate in
[TODO.md](../../TODO.md).
