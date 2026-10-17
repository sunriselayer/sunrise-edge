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

## Optional own-created application pin

[DR-0261](decisions/0261-created-standard-asset-coin-custody.md) additionally
accepts a local `--asset`/`--instance-ref` pair for every prepare, approve,
sign and serve role and the ordinary Standard Asset CLI. Application Coins
and the Call target use that publisher-created asset's verified local pin;
fees always use the genesis Coin and policy. Both identities appear in the
review. Omitting both flags preserves the genesis behavior below. See the
[application Coin guide](standard-asset-application-coin-custody.md) for the
pin, compatibility and qualification boundary.

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
the same. Split/merge, mint/burn and create-asset use their own closed custody profiles.

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

### Recovered-key transfer consumer control

The 2026-10-17 fixture extension follows the existing
[stop-first recovery contract](publication-custody-lifecycle.md). After the
original transfer signer and its revoked restart have exited, it prepares and
independently approves a new signing-only request over retained object preimages.
The original key signs that exact request on a separate reference socket. Only
after actual wait and socket disappearance does the custody UID copy the same
disposable key to new private backup/restored paths.

The real `sign-transfer` consumer then produces identical signed bytes through
the recovered-key `serve-transfer`. The original revoked request remains refused;
revoking the fresh request also refuses signing in that process and after a
separate restart. The reference, recovered and restarted signers have exact
connection/handled/signed/refused counts of 1/1/1/0, 3/3/1/2 and 2/2/0/2. Each
socket must be absent after normal exit. The original transfer and publication
counters and business assertions remain unchanged.

This control adds 13 CLI children, two custody-owned copy children, one attended
PTY approval, six signing requests and eight retained files. Its own additional
captured child output and generated files must each fit 16 KiB within the
existing aggregate allowances. Container, UID, capability, memory, process,
network, volume, total deadline and full-output bounds are unchanged. The
retained preimages are deliberately never submitted again: the control checks
same-frame key recovery, not current ownership, a second business mutation or
positive new-identity rotation. Source implementation is not runtime acceptance;
actual qualification remains in TODO.


### Two-owner genesis Coin identity handoff control

The separate ignored `distinct_uid_genesis_coin_identity_handoff_probe` and
`phase_genesis_coin_identity_handoff` use one fresh two-owner genesis and one
live SQLite/WASM store. A is the existing disposable custody publisher; B is
its already provisioned independent `custody2.seed` identity. Both receive
separate genesis fee Coins. This explicit development funding does not move
A's fee balance, account or wallet to B.

Before any transfer, B's own `prepare-transfer` must refuse the A-owned target
Coin with no output. A independently prepares and approves fresh `b1`, signs
both offline and through the actual protected `transfer` consumer, and moves
the whole same Coin to B. The independent probe checks the actual version-2
Coin's ID, type, schema, unchanged value/body and owner B; A nonce becomes 1
while B remains 0. It authenticates the saved intent and canonical paid result,
recomputes reserve/settle pricing, checks current fee/effects/receipt state and
replays the same request without another mutation.

A's approval is cancelled and must refuse in that process and a restarted
A signer, with separate absent output paths. Both A processes are actually
waited with their PIDs and sockets absent before B's operation-specific
approval or serving authority is used. A's preparation against the actual
exported CURRENT B-owned version-2 preimage must now refuse ownership.
B's independently prepared/attended `b2` uses B's own config/key, separate
prefunded fee Coin and nonce 0 to transfer the SAME target back to A. The
same live store must expose version 3/owner A and per-owner nonces A=1/B=1.
Offline/CLI bytes agree for each exact frame. The independent probe verifies
both saved paid results, receipts and replays, preserving current object and
fee state. B's matching cancellation and restarted refusal are also required.

Each live signer handles exactly 3/3/2/1 connections/handled/signed/refused;
each restarted signer handles 1/1/0/1. The normal incremental workload is
16 CLI commands, three finite oracle invocations, two attended PTYs, four
signer servers and one live oracle host: 26 children, no key-copy children.
Thirty explicitly inventoried private evidence/preimage leaves have a 2 MiB
combined allowance; the owning SQLite files remain inside the original
64 MiB global generated-volume bound. Complete new child output has a
48 KiB suballocation and the final result summary 4 KiB. At most five
failure-only same-UID signal children can stop this phase's exact retained
owned processes under the existing SETUID/SETGID capabilities; no CAP_KILL
or new privilege is added. Every original family, lifecycle, counter and
selector remains unchanged, as do the global deadlines and output caps.

This is a fixture source contract, with actual execution qualification kept
in TODO. It proves no own-created application or TreasuryCap migration:
`ApplicationAssetPin` still requires the immutable instance creator to match
its custody publisher. It does not claim full account/key rotation, fee
balance migration, public ceremony, any additional asset operation or all M2.
