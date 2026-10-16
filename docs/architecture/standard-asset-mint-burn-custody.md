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
review, so the human approver sees the true outcome before ever typing the
confirmation line — not merely the caller's claimed amount.

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
as every other family. `create-asset`, other packages/instances/epochs and
automatic protocol signing stay out of scope.

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
rendering its own review. `create-asset` keeps its existing custody
refusal; `transfer`/`split`/`merge` are unaffected and stay on kind 2/3.

No genesis change is required to exercise this family against the existing
one-owner Docker fixture: its single development owner is both the sole
genesis owner and the fixed `mint_authority`, so it already owns the
installed `TreasuryCap<A>` — distinct from the separate genesis authority,
which owns no `Coin` or `TreasuryCap`.

## Lifecycle and limits

`custody revoke`, recovery and rotation reuse the existing durable store and
lifecycle exactly as DR-0246/DR-0249 describe; nothing about expiry,
revocation or key recovery changes for this family. Actual source and
execution qualification, including any Docker fixture extension, belong in
[TODO.md](../../TODO.md).
