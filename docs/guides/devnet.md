# Local devnet and Rust CLI

This guide starts the loopback-only Sunrise Edge developer network and uses the
Rust CLI. It is a single-validator, non-production environment. Never expose it
to another network or use it to custody real assets.

The devnet installs Standard Asset as an ordinary published contract and routes
asset creation plus all five asset commands through the same signed, paid
instantiate/call paths available to user contracts. There is no native coin,
privileged balance table, preinstalled asset module, or asset-specific node-core
mutation path.

## Prerequisites

Build the workspace and create two development keys. Each seed file contains
exactly 32 random bytes encoded as 64 hexadecimal characters. The CLI rejects
symlinks and permissions other than `0600`.

```bash
cargo build --workspace

OWNER_SEED_FILE=/tmp/sunrise-edge-owner.seed
RECIPIENT_SEED_FILE=/tmp/sunrise-edge-recipient.seed
DEVNET_DATA_DIR=/tmp/sunrise-edge-devnet-v7
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$OWNER_SEED_FILE"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RECIPIENT_SEED_FILE"
chmod 600 "$OWNER_SEED_FILE" "$RECIPIENT_SEED_FILE"

OWNER="$(cargo run -q -p sunrise-edge-cli -- address --seed-file "$OWNER_SEED_FILE")"
OWNER="${OWNER#address=}"
RECIPIENT="$(cargo run -q -p sunrise-edge-cli -- address --seed-file "$RECIPIENT_SEED_FILE")"
RECIPIENT="${RECIPIENT#address=}"
```

## Start a fresh devnet

Protocol version 7 intentionally does not migrate databases from the removed
development-only Standard Asset fixture. Use a fresh data directory. The fee
recipient is an address, not a special treasury object, and may equal a
development owner.

```bash
cargo run -p sunrise-edge-devnet -- \
  --data-dir "$DEVNET_DATA_DIR" \
  --listen 127.0.0.1:7400 \
  --chain-id sunrise-local-devnet \
  --epoch 0 \
  --dev-owner "$OWNER" \
  --fee-recipient "$OWNER" \
  --max-concurrent 16
```

Startup prints the installed contract metadata and one line per owner:

```text
standard_asset_definition=<object id> standard_asset_treasury_cap=<object id>
standard_asset_instance=<digest> standard_asset_code=<digest>
owner=<address> fee_coin=<object id> spend_coin=<object id>
```

Copy the first owner's IDs into another terminal:

```bash
ENDPOINT=127.0.0.1:7400
FEE_COIN="PASTE_FEE_COIN"
SPEND_COIN="PASTE_SPEND_COIN"
TREASURY_CAP="PASTE_STANDARD_ASSET_TREASURY_CAP"

EXPECTED=(
  --endpoint "$ENDPOINT"
  --expected-chain-id sunrise-local-devnet
  --expected-protocol-version 7
  --expected-epoch 0
  --expected-hash-suite-id 1
  --expected-domain 4444444444444444444444444444444444444444444444444444444444444444
)
SIGNING=(--seed-file "$OWNER_SEED_FILE" --fee-source "$FEE_COIN" --max-fee 1000000 --gas-limit 500000)
```

The `EXPECTED` values are local operator configuration. They are deliberately
checked separately from TLS endpoint validation and from values returned by the
server. The fee code, fee instance, fee-asset type argument, schema, and fee
recipient are read from the installed policy and verified before signing. A
caller may select a separately created application asset only by providing its
exact canonical instance pin and Definition ObjectId together; that never
changes the policy-pinned asset used for fees.

## Read-only queries

```bash
cargo run -q -p sunrise-edge-cli -- context --endpoint "$ENDPOINT"
cargo run -q -p sunrise-edge-cli -- next-nonce --endpoint "$ENDPOINT" --sender "$OWNER"
cargo run -q -p sunrise-edge-cli -- object --endpoint "$ENDPOINT" --object-id "$SPEND_COIN"
```

## Standard Asset operations

Generate a new request ID for every new operation. `--nonce` is optional; when
omitted, the CLI queries the sender's next nonce immediately before signing.
Successful commands print fee settlement and every created, mutated, or deleted
object ID. Save created Coin IDs from `split` and `mint` for later commands.
For those two commands, the application-created Coin is the created
`effect[N].object` whose ID is neither the printed `fee_coin=` nor
`refund_coin=` value.
Run `split`, `merge`, `mint`, and `burn` before `transfer`: `transfer` changes
`SPEND_COIN`'s owner to `RECIPIENT`, so it must be the last operation that uses
`SPEND_COIN` as the signer's own coin.

### Create a separate asset

`create-asset` instantiates the already published Standard Asset code. It does
not publish another copy and does not make the new asset eligible for fees. The
initializer creates a zero-supply TreasuryCap owned by the creator. Preserve
the canonical instance reference and copy the printed `asset=` and
`treasury_cap=` values:

```bash
ASSET_INSTANCE_SEED="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ASSET_REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cargo run -q -p sunrise-edge-cli -- create-asset \
  "${EXPECTED[@]}" "${SIGNING[@]}" \
  --instance-seed "$ASSET_INSTANCE_SEED" \
  --instance-ref-out new-asset.instance \
  --submission-out create-asset.signed \
  --result-out create-asset.result \
  --request-id "$ASSET_REQUEST_ID"

NEW_ASSET="PASTE_ASSET"
NEW_TREASURY_CAP="PASTE_TREASURY_CAP"
NEW_ASSET_SELECTION=(--asset "$NEW_ASSET" --instance-ref new-asset.instance)
```

The three output paths are reserved with create-new semantics before the POST.
The signed submission and canonical instance reference are written and synced
before the POST; the result file is filled only after a validated response.
Capture the printed `request_id=` and `nonce=` lines. After an uncertain
response, keep all three files and query the receipt by `ASSET_REQUEST_ID`. A
present successful receipt means `new-asset.instance` is the usable instance
pin. There is currently no command that directly resubmits
`create-asset.signed`; do not rebuild under the same request ID after fee or
other signed inputs may have changed. For a clean new asset attempt, use a new
request ID, instance seed, and output paths.

Mint the first Coin from its capability, then transfer it through the same
ordinary call path. The fee source remains `FEE_COIN` from genesis:

```bash
cargo run -q -p sunrise-edge-cli -- mint \
  "${EXPECTED[@]}" "${SIGNING[@]}" "${NEW_ASSET_SELECTION[@]}" \
  --treasury-cap "$NEW_TREASURY_CAP" --amount 50 --recipient "$OWNER" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

NEW_ASSET_COIN="PASTE_CREATED_COIN"
cargo run -q -p sunrise-edge-cli -- transfer \
  "${EXPECTED[@]}" "${SIGNING[@]}" "${NEW_ASSET_SELECTION[@]}" \
  --coin "$NEW_ASSET_COIN" --recipient "$RECIPIENT" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

`--asset` without `--instance-ref`, or the reverse, is rejected before signing.
A Coin or TreasuryCap from the genesis asset cannot be substituted under
`NEW_ASSET_SELECTION` because its nominal type and exact instance authority
differ.

### Split and merge

The examples keep the created Coin under the signer so it can be merged back.
After `split`, replace `SPLIT_COIN` with the printed created object ID. The
source Coin ID remains the same at a newer version.

```bash
cargo run -q -p sunrise-edge-cli -- split \
  "${EXPECTED[@]}" "${SIGNING[@]}" \
  --coin "$SPEND_COIN" --amount 100 --recipient "$OWNER" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

SPLIT_COIN="PASTE_CREATED_COIN"
cargo run -q -p sunrise-edge-cli -- merge \
  "${EXPECTED[@]}" "${SIGNING[@]}" \
  --into "$SPEND_COIN" --from "$SPLIT_COIN" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

`merge` consumes `--from`; querying that ID afterward reports a tombstone.

### Mint and burn

Only the first configured development owner owns the genesis TreasuryCap. Mint
creates one Coin and increases recorded supply. Burn consumes an entire Coin
and decreases supply. Amount arithmetic remains inside the published WASM
contract.

```bash
cargo run -q -p sunrise-edge-cli -- mint \
  "${EXPECTED[@]}" "${SIGNING[@]}" \
  --treasury-cap "$TREASURY_CAP" --amount 25 --recipient "$OWNER" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

MINTED_COIN="PASTE_CREATED_COIN"
cargo run -q -p sunrise-edge-cli -- burn \
  "${EXPECTED[@]}" "${SIGNING[@]}" \
  --treasury-cap "$TREASURY_CAP" --coin "$MINTED_COIN" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

### Transfer a whole Coin

Run this last: it moves `SPEND_COIN` to `RECIPIENT`, so any earlier example
above that still needs `SPEND_COIN` under `OWNER` must already have run.

```bash
cargo run -q -p sunrise-edge-cli -- transfer \
  "${EXPECTED[@]}" "${SIGNING[@]}" \
  --coin "$SPEND_COIN" --recipient "$RECIPIENT" \
  --request-id "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

`transfer` changes ownership of the Coin object; it does not move a balance in
a node-native account table.

## Replay and restart checks

For recovery, add `--submission-out signed.bin --result-out result.bin` to any
asset command. Replaying the exact signed submission returns the committed
result without charging fees or applying object effects again. Reusing a
request ID with different signed bytes is rejected and must not change objects,
receipt, or nonce.

Stop the devnet with Ctrl-C and restart the same command with the same data
directory. Startup must report `paid_genesis_status=verified-existing`, a higher
writer generation, and exactly the same contract and genesis object IDs.
Queries for surviving and consumed objects must match the pre-restart state.

## Optional generic contract surfaces

`--enable-local-publication`, `--enable-local-execution`, and
`--enable-general-calls` expose the development-only zero-fee workflows used to
build and test arbitrary contracts. The public paid `contract paid-publish`,
`contract paid-instantiate`, and `contract paid-call` commands use the mandatory
paid path. These surfaces do not grant Standard Asset any native privilege.

Their exact security and execution model is documented in
[`docs/smartcontract/`](../smartcontract/) and
the remaining readiness work is tracked only in [`TODO.md`](../../TODO.md).

## Optional remote TLS transport

Plain HTTP accepts loopback endpoints only. For a remote development endpoint,
pass its resolved `SocketAddr` as `--endpoint` together with
`--tls-server-name` and `--tls-ca-cert-der-file`. The current CLI does not do
DNS resolution or client-certificate authentication. TLS authenticates the
server endpoint; it does not replace the independently configured
`--expected-*` protocol context.
