# Genesis Standard Asset transfer custody

[DR-0246](decisions/0246-genesis-standard-asset-transfer-custody.md) extends
the trusted-local-OS, separate-process/UID boundary to one known whole-coin
transfer. This guide describes the implemented contract; qualification status
belongs in [TODO.md](../../TODO.md).

## Trust and operation

Custody independently pins its context, sender public key, permitted operator
UID and signed genesis digest. The existing private config format is reused:
`publisher_public_key` names the sender for this profile. The genesis manifest
is custody-owned mode 0600 under a 0700 directory. Custody authenticates both
the outer root and nested publication/initializer, checks the exact in-tree
Standard Asset code, fee roles, instance and base policy, and refuses other
epochs or packages.

Custody decodes two bounded canonical object preimages, checks sender ownership,
schema and nominal Coin type, reads the amount from each body and recomputes
their signed references under its pinned context. The coin and fee source must
differ. Transfer moves the entire coin unchanged. The refund returns to the
sender, and maximum fee must be positive and below the fee-source balance.
There are no additional authorizations or caller-selected code/entrypoints.

The complete bounded review displays sender, whole-coin amount, recipient,
exact object references, fee balance/ceiling/refund, policy prices/caps, context,
genesis/code/instance pins, replay fields and full signed frame. Currentness is
enforced by execution. A supplied object body alone is not current-state proof.

## Independent preparation and approval

The administrator obtains the genesis and object preimages independently of
the live operator request. Use only disposable development keys until the
separate real-key and operational qualification is complete.

```bash
sunrise-edge-cli custody prepare-transfer \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --coin-file /private/coin.bin --fee-source-file /private/fee.bin \
  --recipient <64-hex-address> --nonce 0 --request-id <64-hex-request> \
  --max-fee 1000000 --gas-limit 200000 --out /private/request.bin

sunrise-edge-cli custody approve-transfer \
  --config /private/config \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --request-file /private/request.bin --approvals-dir /private/approvals \
  --expires-in-seconds 3600
```

Preparation creates no approval. Approval requires terminal stdin/stdout,
renders the full review and requires the exact `APPROVE-TRANSFER` line. The
record binds the whole signed frame and expiry. Private exports never overwrite.

## Separate serving and actual CLI consumer

```bash
sunrise-edge-cli custody serve-transfer \
  --config /private/config --key-file /private/custody.seed \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --socket /custody-run/transfer.sock --approvals-dir /private/approvals \
  --max-connections 8 --max-requests 8 --total-deadline-secs 300
```

Socket directory/peer credentials and lifetime limits follow the
[local custody guide](local-publication-custody.md). Publication `serve` only
accepts message kind 1; `serve-transfer` only accepts kind 2. Neither accepts an
arbitrary caller-built signing frame. Each invocation checks key/config identity
before binding and checks exact approval, expiry and durable revocation before
signing. A signature is independently finalized on each side.

The existing `transfer` CLI accepts the three custody signer flags in place of
`--seed-file`, with its ordinary endpoint/context, coin, fee, recipient, nonce,
request and gas flags. It obtains canonical object bodies and sends them to
custody; the protected side verifies its own references and semantics. The
ordinary paid execution, receipt validation, exact replay and output paths stay
the same. Other Standard Asset operations retain their custody refusal.

`custody sign-transfer` is an offline alternative: it requires operator-owned
private config/genesis/request copies, the same explicit root pin and three
custody signer flags, plus fresh `--out`. It exports the ordinary signed paid
intent after independent finalization; it has no endpoint or development seed.

## Lifecycle and limits

`custody revoke` uses the same durable request cancellation store. Revocation
does not erase issued signatures; stop and drain the signer before requiring
that stronger fence. Retain revocations with approvals during key recovery.
Restart reuses explicit trust pins, rather than trusting a peer's new policy.
Changing the key changes the address: it does not silently transfer ownership
of old coins or authorize an old approval.

The contained Docker fixture retains the original publication/lifecycle controls
and adds actual distinct-UID transfer approval and signing, an ordinary CLI
transfer through real SQLite and WASM, identical offline/CLI signed bytes,
receipt-first replay, nonce and ownership/value checks, and revocation refusal.
It creates no host users or services and uses the original resource limits.
During its SQLite phase only, the disposable volume root permits listing its
fixed names because the native adapter pins readable ancestor descriptors.
All key/approval/operator/database directories remain private, and the actual
operator key-read/approval-edit refusals are repeated under that parent mode.
Native SQLite deployment paths similarly require readable ancestor directories;
this does not require exposing the contents of private key or database directories.
The fixture is not a real key ceremony, public operation or all-family M2 proof.
