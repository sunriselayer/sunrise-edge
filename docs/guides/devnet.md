# Local devnet and Rust CLI

This guide starts the local, non-production Sunrise Edge devnet and drives it
with the Rust CLI. The devnet binds loopback only, is single-validator, and
must never be used to custody real assets or exposed beyond your own machine.

The devnet activates Standard Asset v1 whole-coin transfer, bounded
split/merge, supply-controlled mint, and whole-coin burn for its existing
derived asset (DR-0107/DR-0108/DR-0109/DR-0110): each
configured `--dev-owner` is seeded with one transferable
`StandardAssetCoinV1` and one distinct fee-payer coin, and the separate
`--fee-treasury-owner` is seeded with one ordinary treasury coin. `transfer`
moves a whole coin's ownership to a signed recipient address. `split` creates
one same-typed recipient coin from a checked partial amount, and `merge`
combines two sender-owned coins without creating a new coin.
The first configured development owner also receives a `TreasuryCap<A>` with
the exact genesis supply and a fixed devnet maximum. Mint checked-adds supply
and creates one coin; burn checked-subtracts supply and consumes one whole
coin. This is deliberately a local fixture, not a production monetary policy.

Optional immutable code publication is described in
[section 11](#11-opt-in-local-code-publication). It does not execute contracts.

The commands assume the workspace has already been built once:

```bash
cargo build --workspace
```

## 1. Create development keys

Choose explicit paths and create sender, recipient, and distinct fee-treasury
development seed files. These are private, non-keystore development secrets,
each containing exactly 64 hexadecimal characters. The CLI requires permission
`0600` and rejects symlinks. The recipient is never seeded with anything: it
only needs to be a canonical prime-order Ed25519 address that can receive the
transferred coin.

```bash
SENDER_SEED_FILE=/tmp/sunrise-edge-sender-seed
RECIPIENT_SEED_FILE=/tmp/sunrise-edge-recipient-seed
TREASURY_SEED_FILE=/tmp/sunrise-edge-treasury-seed
DEVNET_DATA_DIR=/tmp/sunrise-edge-devnet
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SENDER_SEED_FILE"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RECIPIENT_SEED_FILE"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TREASURY_SEED_FILE"
chmod 600 "$SENDER_SEED_FILE" "$RECIPIENT_SEED_FILE" "$TREASURY_SEED_FILE"
```

## 2. Derive addresses

Each command prints one `address=<64-hex-character address>` line. The values
depend on the random seeds, so this guide does not hard-code them.

```bash
SENDER_ADDRESS_LINE="$(cargo run -p sunrise-edge-cli -- address --seed-file "$SENDER_SEED_FILE")"
RECIPIENT_ADDRESS_LINE="$(cargo run -p sunrise-edge-cli -- address --seed-file "$RECIPIENT_SEED_FILE")"
TREASURY_ADDRESS_LINE="$(cargo run -p sunrise-edge-cli -- address --seed-file "$TREASURY_SEED_FILE")"
SENDER_OWNER="${SENDER_ADDRESS_LINE#address=}"
RECIPIENT_OWNER="${RECIPIENT_ADDRESS_LINE#address=}"
TREASURY_OWNER="${TREASURY_ADDRESS_LINE#address=}"
printf 'SENDER_OWNER=%s\nRECIPIENT_OWNER=%s\nTREASURY_OWNER=%s\n' \
  "$SENDER_OWNER" "$RECIPIENT_OWNER" "$TREASURY_OWNER"
```

## 3. Start the devnet

Run this in terminal A. Only `$SENDER_OWNER` is a `--dev-owner`; the recipient
is never passed to the devnet at all.

```bash
cargo run -p sunrise-edge-devnet -- \
  --data-dir "$DEVNET_DATA_DIR" \
  --listen 127.0.0.1:7400 \
  --chain-id sunrise-local-devnet \
  --epoch 0 \
  --dev-owner "$SENDER_OWNER" \
  --fee-treasury-owner "$TREASURY_OWNER" \
  --max-concurrent 16
```

Startup prints the asset authority pair, one line per seeded owner, and the
treasury:

```text
owner=<first dev owner> role=mint-authority seed_status=<created|verified-existing> asset_definition=<object id> treasury_cap=<object id>
owner=<owner> role=dev-owner seed_status=<created|verified-existing> transfer_coin=<object id> fee_coin=<object id>
owner=<owner> role=fee-treasury seed_status=<created|verified-existing> treasury_coin=<object id>
```

It also prints the derived asset id and preinstalled module identity:

```text
asset_id=<...> module_id=<...> module_version=<...> module_digest=<algorithm-label>:<hex digest>
```

Copy the sender's `treasury_cap`, `transfer_coin`, and `fee_coin`, the
treasury's `treasury_coin`, `asset_id`, `module_id`, `module_version`, and
`module_digest`. The digest currently prints as `sha2-256:<hex>`: pass `1` for
`--module-digest-algorithm` and only the hexadecimal portion after the colon
for `--module-digest`. The `asset_id` is *derived*, not fixed: it depends on
`--chain-id`, `--epoch`, and the committed protocol version, so a different
devnet configuration produces a different `asset_id` (see DR-0107).

## 4. Configure and query the CLI

In terminal B, set the exact values printed above. Replace the contents of the
quoted uppercase placeholders; do not copy shell angle brackets.

```bash
SENDER_SEED_FILE=/tmp/sunrise-edge-sender-seed
SENDER_OWNER="PASTE_SENDER_ADDRESS_PRINTED_IN_STEP_2"
RECIPIENT_OWNER="PASTE_RECIPIENT_ADDRESS_PRINTED_IN_STEP_2"
TREASURY_OWNER="PASTE_TREASURY_ADDRESS_PRINTED_IN_STEP_2"
SOURCE_COIN_ID="PASTE_SENDER_TRANSFER_COIN_ID_PRINTED_IN_STEP_3"
TREASURY_CAP_ID="PASTE_SENDER_TREASURY_CAP_ID_PRINTED_IN_STEP_3"
FEE_COIN_ID="PASTE_SENDER_FEE_COIN_ID_PRINTED_IN_STEP_3"
TREASURY_OBJECT_ID="PASTE_TREASURY_COIN_ID_PRINTED_IN_STEP_3"
FEE_ASSET_ID="PASTE_ASSET_ID_PRINTED_IN_STEP_3"
MODULE_ID="PASTE_MODULE_ID_PRINTED_IN_STEP_3"
MODULE_VERSION="PASTE_MODULE_VERSION_PRINTED_IN_STEP_3"
MODULE_DIGEST_HEX="PASTE_HEX_AFTER_THE_MODULE_DIGEST_COLON"
REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
```

The expected values below are the operator's own locally trusted expectation,
not values copied from the untrusted server response. They must equal the
devnet configuration used in step 3 and this profile's fixed protocol values.
See [DR-0085](../architecture/decisions/0081-0087-cli-first-roadmap.md) and
[`TODO.md`](../../TODO.md#cli-first-node-production-gate) S1.

```bash
EXPECTED_CHAIN_ID="sunrise-local-devnet"
EXPECTED_PROTOCOL_VERSION=6
EXPECTED_EPOCH=0
EXPECTED_HASH_SUITE_ID=1
EXPECTED_DOMAIN="4444444444444444444444444444444444444444444444444444444444444444"

cargo run -p sunrise-edge-cli -- context --endpoint 127.0.0.1:7400
cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
  --sender "$SENDER_OWNER"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$SOURCE_COIN_ID"
```

These queries do not change state.

## 5. Mint one sender-owned coin

The treasury cap is owned by the sender and passed as a `Write`; the fee coin
is a separate `Write`. The accepted response mutates the cap and contains one
`kind=created` effect whose object is a `StandardAssetCoinV1` owned by
`$SENDER_OWNER` with amount `1`. Sending this small coin back to the signer
lets step 6 burn it without requiring a seeded recipient fee coin.

```bash
MINT_REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cargo run -p sunrise-edge-cli -- mint \
  --endpoint 127.0.0.1:7400 \
  --seed-file "$SENDER_SEED_FILE" \
  --module-id "$MODULE_ID" \
  --module-version "$MODULE_VERSION" \
  --module-digest-algorithm 1 \
  --module-digest "$MODULE_DIGEST_HEX" \
  --treasury-cap "$TREASURY_CAP_ID" \
  --recipient "$SENDER_OWNER" \
  --amount 1 \
  --fee-coin "$FEE_COIN_ID" \
  --gas-limit 1000000 \
  --fee-asset-id "$FEE_ASSET_ID" \
  --max-fee 1000001 \
  --fee-treasury-object "$TREASURY_OBJECT_ID" \
  --request-id "$MINT_REQUEST_ID" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
  --expected-domain "$EXPECTED_DOMAIN" \
  --wait --wait-max-attempts 20 --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 --wait-max-elapsed-ms 5000
```

`mint` strictly decodes the treasury cap and fee coin, requires both to share
one asset id matching `--fee-asset-id`, checks sender ownership, and rejects an
amount that cannot fit beneath the cap's current maximum before signing. It
does not create new asset definitions; it issues only the existing derived
devnet asset. Record the created effect's object id:

```bash
MINTED_COIN_ID="PASTE_CREATED_OBJECT_ID_FROM_THE_MINT_RESPONSE"
```

## 6. Burn that whole minted coin

Burn takes empty module arguments and consumes the entire sender-owned coin;
partial burn is deliberately not part of v1. It mutates the same treasury cap
with a checked supply subtraction and charges the distinct fee coin in the
same atomic commit.

```bash
BURN_REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cargo run -p sunrise-edge-cli -- burn \
  --endpoint 127.0.0.1:7400 \
  --seed-file "$SENDER_SEED_FILE" \
  --module-id "$MODULE_ID" \
  --module-version "$MODULE_VERSION" \
  --module-digest-algorithm 1 \
  --module-digest "$MODULE_DIGEST_HEX" \
  --treasury-cap "$TREASURY_CAP_ID" \
  --coin "$MINTED_COIN_ID" \
  --fee-coin "$FEE_COIN_ID" \
  --gas-limit 1000000 \
  --fee-asset-id "$FEE_ASSET_ID" \
  --max-fee 1000001 \
  --fee-treasury-object "$TREASURY_OBJECT_ID" \
  --request-id "$BURN_REQUEST_ID" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
  --expected-domain "$EXPECTED_DOMAIN" \
  --wait --wait-max-attempts 20 --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 --wait-max-elapsed-ms 5000
```

After success, querying `$MINTED_COIN_ID` reports `status=tombstoned`; restart
must retain that tombstone and must not recreate the coin.

## 7. Submit a partial split, then merge it back

The split example sends the new coin back to `$SENDER_OWNER`, so both the
remainder and the newly created coin stay sender-owned. The seeded
`FEE_COIN_ID` remains a separate fee payer. Choose an amount known to be
strictly below the source amount (the seeded transfer coin is intentionally
large; query it in step 4 if needed). The CLI prints the created object id in
the accepted response whose `kind=created`; set `SPLIT_COIN_ID` to the
`object_id` printed on that same created-effect record before the merge.

```bash
SPLIT_REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cargo run -p sunrise-edge-cli -- split \
  --endpoint 127.0.0.1:7400 \
  --seed-file "$SENDER_SEED_FILE" \
  --module-id "$MODULE_ID" \
  --module-version "$MODULE_VERSION" \
  --module-digest-algorithm 1 \
  --module-digest "$MODULE_DIGEST_HEX" \
  --source-coin "$SOURCE_COIN_ID" \
  --recipient "$SENDER_OWNER" \
  --amount 1 \
  --fee-coin "$FEE_COIN_ID" \
  --gas-limit 1000000 \
  --fee-asset-id "$FEE_ASSET_ID" \
  --max-fee 1000001 \
  --fee-treasury-object "$TREASURY_OBJECT_ID" \
  --request-id "$SPLIT_REQUEST_ID" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
  --expected-domain "$EXPECTED_DOMAIN" \
  --wait --wait-max-attempts 20 --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 --wait-max-elapsed-ms 5000
```

After recording the printed `response[0].object_effect[*].object_id` on the
effect whose `kind=created` as `SPLIT_COIN_ID`, merge it with the remainder.
The primary coin is mutated, the split coin is consumed, and the seeded fee
coin remains distinct:

```bash
SPLIT_COIN_ID="PASTE_CREATED_OBJECT_ID_FROM_THE_SPLIT_RESPONSE"
MERGE_REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cargo run -p sunrise-edge-cli -- merge \
  --endpoint 127.0.0.1:7400 \
  --seed-file "$SENDER_SEED_FILE" \
  --module-id "$MODULE_ID" \
  --module-version "$MODULE_VERSION" \
  --module-digest-algorithm 1 \
  --module-digest "$MODULE_DIGEST_HEX" \
  --primary-coin "$SOURCE_COIN_ID" \
  --secondary-coin "$SPLIT_COIN_ID" \
  --fee-coin "$FEE_COIN_ID" \
  --gas-limit 1000000 \
  --fee-asset-id "$FEE_ASSET_ID" \
  --max-fee 1000001 \
  --fee-treasury-object "$TREASURY_OBJECT_ID" \
  --request-id "$MERGE_REQUEST_ID" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
  --expected-domain "$EXPECTED_DOMAIN" \
  --wait --wait-max-attempts 20 --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 --wait-max-elapsed-ms 5000
```

Both commands independently verify the sender owns every visible coin, that
the coins share the same asset id, and that the expected protocol context
matches before signing. Ledger signing for these new entrypoints remains
unsupported and fails closed.

## 8. Submit a whole-coin transfer

After the split coin has been merged back, the sender can transfer the
original source coin to the recipient address. The fee asset must equal the
transferred coin's asset. After this command, `SOURCE_COIN_ID` is owned by
`RECIPIENT_OWNER`; its body (asset id and amount) is unchanged.

```bash
cargo run -p sunrise-edge-cli -- transfer \
  --endpoint 127.0.0.1:7400 \
  --seed-file "$SENDER_SEED_FILE" \
  --module-id "$MODULE_ID" \
  --module-version "$MODULE_VERSION" \
  --module-digest-algorithm 1 \
  --module-digest "$MODULE_DIGEST_HEX" \
  --source-coin "$SOURCE_COIN_ID" \
  --recipient "$RECIPIENT_OWNER" \
  --fee-coin "$FEE_COIN_ID" \
  --gas-limit 1000000 \
  --fee-asset-id "$FEE_ASSET_ID" \
  --max-fee 1000001 \
  --fee-treasury-object "$TREASURY_OBJECT_ID" \
  --request-id "$REQUEST_ID" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
  --expected-domain "$EXPECTED_DOMAIN" \
  --wait --wait-max-attempts 20 --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 --wait-max-elapsed-ms 5000
```

`transfer` rejects malformed recipients, zero max fee, conflicting treasury
objects, or an invalid expected context before dispatch. It verifies both
coins are signer-owned, share one `AssetId`, and match `--fee-asset-id` before
signing. A rejected or execution-failed submission exits non-zero. If the fee
coin reaches exactly the settled fee, it becomes unusable because a
`StandardAssetCoinV1` amount cannot be zero.

## 9. Capture post-transfer state

Capture the transfer, mint, and burn receipts, treasury cap, burned coin
tombstone, the three
seeded current coins, and next nonce. These are the pre-restart observations
used in the next step.

```bash
OBSERVATION_PREFIX="/tmp/sunrise-edge-$REQUEST_ID"
cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
  --request-id "$REQUEST_ID" > "$OBSERVATION_PREFIX.receipt"
cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
  --request-id "$MINT_REQUEST_ID" > "$OBSERVATION_PREFIX.mint-receipt"
cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
  --request-id "$BURN_REQUEST_ID" > "$OBSERVATION_PREFIX.burn-receipt"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$TREASURY_CAP_ID" > "$OBSERVATION_PREFIX.treasury-cap"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$MINTED_COIN_ID" > "$OBSERVATION_PREFIX.minted-coin"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$SOURCE_COIN_ID" > "$OBSERVATION_PREFIX.source"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$FEE_COIN_ID" > "$OBSERVATION_PREFIX.fee"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$TREASURY_OBJECT_ID" > "$OBSERVATION_PREFIX.treasury"
cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
  --sender "$SENDER_OWNER" > "$OBSERVATION_PREFIX.nonce"
```

## 10. Restart and compare

Stop the devnet in terminal A with `Ctrl-C`. Rerun the exact command from step
3 with the same data directory, chain id, and owners. Wait until both owners
report `seed_status=verified-existing` — the transferred coin now reports its
current owner as `$RECIPIENT_OWNER`, not `$SENDER_OWNER`, and restart
verification accepts this (DR-0107 F9) — then run:

```bash
diff -u "$OBSERVATION_PREFIX.receipt" <(
  cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
    --request-id "$REQUEST_ID"
)
diff -u "$OBSERVATION_PREFIX.mint-receipt" <(
  cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
    --request-id "$MINT_REQUEST_ID"
)
diff -u "$OBSERVATION_PREFIX.burn-receipt" <(
  cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
    --request-id "$BURN_REQUEST_ID"
)
diff -u "$OBSERVATION_PREFIX.treasury-cap" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$TREASURY_CAP_ID"
)
diff -u "$OBSERVATION_PREFIX.minted-coin" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$MINTED_COIN_ID"
)
diff -u "$OBSERVATION_PREFIX.source" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$SOURCE_COIN_ID"
)
diff -u "$OBSERVATION_PREFIX.fee" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$FEE_COIN_ID"
)
diff -u "$OBSERVATION_PREFIX.treasury" <(
  cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
    --object-id "$TREASURY_OBJECT_ID"
)
diff -u "$OBSERVATION_PREFIX.nonce" <(
  cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
    --sender "$SENDER_OWNER"
)
```

Every `diff` must exit successfully with no output. This proves orderly
stop/reopen persistence for the observed state. It does not prove `kill -9`,
power-loss, torn-write, load, concurrency, or production SQLite suitability.

The automated E2Es additionally replay byte-identical signed whole-transfer,
split, merge, mint, and burn requests before and after restart. The CLI intentionally
exposes no raw replay command because these commands re-query the current nonce
and object references before signing.

A data directory created under a different committed protocol version fails
closed rather than silently seeding a disjoint object set. Protocol 3 predates
the marker and is rejected as `UnmarkedExistingObjectState` when its object
store is non-empty; a later marked version or epoch mismatch is rejected as
`ProtocolVersionMismatch` or `EpochMismatch`. Start a fresh `--data-dir`
rather than reusing one across an incompatible devnet upgrade or epoch change.

## 11. Opt-in local code publication

Restart terminal A with the same arguments from section 3 and the additional
`--enable-local-publication` flag. This explicitly enables fee-free immutable
code storage, not execution, instantiation or a public-network deploy service.
Leave the server on loopback. Without the flag, publication routes are absent,
including after restarting a database containing published code. Enabling it
seeds or verifies an exact fenced local publication policy; different policy
bytes or a tombstoned policy fail startup rather than silently replacing it.

Prepare your contract's WASM and canonical `abi::call_values::CallAbi` bytes
(produced by `encode_call_abi`, not JSON). The ABI must declare this publisher,
chain and origin seed, and its entrypoints must exactly match the manifest and
admitted WASM exports. The WASM admission rules in DR-0112 apply, including a
bounded memory maximum. A trusted preinstalled Standard Asset binary/ABI is
not a substitute for a public artifact. This guide does not introduce a toy
contract template. The full automated fixture flow is available with:

```bash
cargo test -p sunrise-edge-cli --test devnet_publication_e2e
```

In terminal B, use the locally trusted `EXPECTED_*` variables from section 4.
Set paths to your already-produced artifact files and the seed declared in
the ABI, then publish. Keep these files and the nonce unchanged for replay.

```bash
PUBLICATION_WASM=/absolute/path/to/contract.wasm
PUBLICATION_ABI=/absolute/path/to/contract.abi
PUBLICATION_ENTRYPOINTS=your_entrypoint
PUBLICATION_ORIGIN_SEED=YOUR_ABI_ORIGIN_SEED_AS_64_HEX_CHARACTERS
PUBLICATION_REQUEST_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PUBLICATION_CAPTURE_DIR="$(mktemp -d /tmp/sunrise-publication-comparison.XXXXXX)"

publication_cli() {
  cargo run -p sunrise-edge-cli -- contract "$@" \
    --endpoint 127.0.0.1:7400 \
    --origin-seed "$PUBLICATION_ORIGIN_SEED" \
    --expected-chain-id "$EXPECTED_CHAIN_ID" \
    --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
    --expected-epoch "$EXPECTED_EPOCH" \
    --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
    --expected-domain "$EXPECTED_DOMAIN"
}
publication_cli publish \
  --seed-file "$SENDER_SEED_FILE" \
  --wasm "$PUBLICATION_WASM" --abi "$PUBLICATION_ABI" \
  --entrypoints "$PUBLICATION_ENTRYPOINTS" \
  --request-id "$PUBLICATION_REQUEST_ID" \
  > "$PUBLICATION_CAPTURE_DIR/publish-before.txt"
cat "$PUBLICATION_CAPTURE_DIR/publish-before.txt"
PUBLICATION_NONCE="$(sed -n 's/^nonce=//p' "$PUBLICATION_CAPTURE_DIR/publish-before.txt")"
test -n "$PUBLICATION_NONCE"
publication_cli query --publisher "$SENDER_OWNER" \
  --dependency-ref-out "$PUBLICATION_CAPTURE_DIR/reference-before.bin" \
  > "$PUBLICATION_CAPTURE_DIR/query-before.txt"
```

For a dependent artifact, include `--dependencies path/to/reference.bin`
(comma-separated for multiple references) on its publish command. The signed
ABI must match the declared dependency origins; a copied ABI cannot claim
another package's types. Query's `--dependency-ref-out` creates a new file and
never overwrites an existing one.

Stop and restart terminal A using the same database, chain, epoch, owners and
`--enable-local-publication`. With no intervening transactions, repeat the
exact publication using its original nonce and compare both response text and
the canonical exact dependency reference:

```bash
publication_cli publish \
  --seed-file "$SENDER_SEED_FILE" \
  --wasm "$PUBLICATION_WASM" --abi "$PUBLICATION_ABI" \
  --entrypoints "$PUBLICATION_ENTRYPOINTS" \
  --request-id "$PUBLICATION_REQUEST_ID" --nonce "$PUBLICATION_NONCE" \
  > "$PUBLICATION_CAPTURE_DIR/publish-after.txt"
publication_cli query --publisher "$SENDER_OWNER" \
  --dependency-ref-out "$PUBLICATION_CAPTURE_DIR/reference-after.bin" \
  > "$PUBLICATION_CAPTURE_DIR/query-after.txt"
cmp "$PUBLICATION_CAPTURE_DIR/publish-before.txt" "$PUBLICATION_CAPTURE_DIR/publish-after.txt"
cmp "$PUBLICATION_CAPTURE_DIR/query-before.txt" "$PUBLICATION_CAPTURE_DIR/query-after.txt"
cmp "$PUBLICATION_CAPTURE_DIR/reference-before.bin" "$PUBLICATION_CAPTURE_DIR/reference-after.bin"
```

Exact replay does not consume the nonce again. Publication and asset operations
share the same sender nonce; never assume publication starts a second counter.
After an uncertain result, preserve the signed artifact, original nonce and
request ID and retry them, rather than selecting a new request ID. Reusing an
ID with different signed content is a conflict, not an update. Origin/revision
1 cannot be overwritten. Query verifies publisher signatures and commitments,
not a cryptographic inclusion or absence proof. The CLI uses the current
locally configured publication profile; historical protocol queries require
the Rust client's explicit original trusted context/resolver API.

## 12. Opt-in independent contract instances

Use `--enable-local-execution` in terminal A to install the explicit executable
publication and zero-fee execution policies. It also enables local publication;
`--enable-local-publication` alone still grants no execution authority. Keep
this development composition on loopback. Reopening an existing database does
not enable these routes unless the flag is supplied again.

Executable artifacts use `abi::executable_abi::ExecutableAbi` and
`encode_executable_abi`, not the non-executing CallAbi bytes from section 11.
The wrapper commits an initializer and transferable constructor declarations.
WASM uses the typed `sunrise` imports described in
[DR-0122](../architecture/decisions/0122-local-instance-execution.md); legacy
`env` imports are not accepted in this profile. Publish and query using the
section 11 commands with `--executable`. Export exact dependency references for
libraries before publishing their callers.

The executable inventory fixture exercises stock reservation, a dependency
library's dispatch policy, fulfilment and shipment ownership transfer, rather
than a counter. These commands run the real typed VM/SQLite and CLI/HTTP flows:

```bash
cargo test -p node-core --test local_inventory
cargo test -p sunrise-edge-cli --test devnet_execution_e2e
```

For your own artifact, prepare canonical argument bytes with `encode_call_value`
and access bytes with `encode_access_manifest`. Each access entry contains the
exact current object reference and declared mode; order is the ABI's signed
parameter order, not an unordered set. The program itself controls business
rules and state bodies. The host enforces type, defining-code, instance, owner
and access rights; it has no hardcoded inventory balances.

Using the trusted `EXPECTED_*` variables from section 4:

```bash
execution_cli() {
  cargo run -p sunrise-edge-cli -- contract "$@" \
    --endpoint 127.0.0.1:7400 \
    --expected-chain-id "$EXPECTED_CHAIN_ID" \
    --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
    --expected-epoch "$EXPECTED_EPOCH" \
    --expected-hash-suite-id "$EXPECTED_HASH_SUITE_ID" \
    --expected-domain "$EXPECTED_DOMAIN"
}
# Set these to your exact exported reference, initializer arguments and new IDs.
CONTRACT_REFERENCE=/absolute/path/to/executable-reference.bin
INITIALIZER_ARGUMENTS=/absolute/path/to/initializer-arguments.bin
INSTANCE_SEED=YOUR_NEW_64_HEX_CHARACTER_SEED
INSTANCE_REQUEST_ID=YOUR_NEW_64_HEX_CHARACTER_REQUEST_ID
EXECUTION_CAPTURE_DIR="$(mktemp -d /tmp/sunrise-execution-comparison.XXXXXX)"
execution_cli instantiate --seed-file "$SENDER_SEED_FILE" \
  --code-ref "$CONTRACT_REFERENCE" --instance-seed "$INSTANCE_SEED" \
  --args "$INITIALIZER_ARGUMENTS" --gas-limit 1000000 \
  --request-id "$INSTANCE_REQUEST_ID" \
  --submission-out "$EXECUTION_CAPTURE_DIR/signed-before.bin" \
  --result-out "$EXECUTION_CAPTURE_DIR/result-before.bin" \
  > "$EXECUTION_CAPTURE_DIR/instantiate-before.txt"
INSTANCE_NONCE="$(sed -n 's/^nonce=//p' "$EXECUTION_CAPTURE_DIR/instantiate-before.txt")"
test -n "$INSTANCE_NONCE"
execution_cli query-instance --creator "$SENDER_OWNER" \
  --instance-seed "$INSTANCE_SEED" \
  --instance-ref-out "$EXECUTION_CAPTURE_DIR/instance-before.bin"
```

Stop/restart terminal A with the same database/configuration and execution flag,
then reconstruct the exact original initialization, including its nonce:

```bash
execution_cli instantiate --seed-file "$SENDER_SEED_FILE" \
  --code-ref "$CONTRACT_REFERENCE" --instance-seed "$INSTANCE_SEED" \
  --args "$INITIALIZER_ARGUMENTS" --gas-limit 1000000 \
  --request-id "$INSTANCE_REQUEST_ID" --nonce "$INSTANCE_NONCE" \
  --submission-out "$EXECUTION_CAPTURE_DIR/signed-after.bin" \
  --result-out "$EXECUTION_CAPTURE_DIR/result-after.bin" \
  > "$EXECUTION_CAPTURE_DIR/instantiate-after.txt"
execution_cli query-instance --creator "$SENDER_OWNER" \
  --instance-seed "$INSTANCE_SEED" \
  --instance-ref-out "$EXECUTION_CAPTURE_DIR/instance-after.bin"
cmp "$EXECUTION_CAPTURE_DIR/signed-before.bin" "$EXECUTION_CAPTURE_DIR/signed-after.bin"
cmp "$EXECUTION_CAPTURE_DIR/result-before.bin" "$EXECUTION_CAPTURE_DIR/result-after.bin"
cmp "$EXECUTION_CAPTURE_DIR/instance-before.bin" "$EXECUTION_CAPTURE_DIR/instance-after.bin"
```

To invoke an ordinary entrypoint, use `contract call --instance-ref <file>
--entrypoint <name> --access <canonical-file> --args <canonical-file>` with the
same context, signer, gas and request/output flags. Initializers cannot be called
again with a new request. Instances are immutable and independent; state changes
update individual objects, not a mutable instance-wide root. Library calls stay
within that instance and cannot borrow another instance's capability.

Outputs are create-new files, reserved before POST; never reuse output paths.
Publication, asset transactions and execution share one sender nonce. A trapped
execution returns a nonzero CLI exit code but still writes the validated Rejected
result: application changes/events roll back, while its receipt and nonce commit.
Exact replay preserves that rejection and consumes nothing again. For uncertain
delivery or failed result-file writes, retain the signed bytes and original
request ID/nonce; do not submit a fresh request to guess whether it committed.
Query responses verify exact referenced code and record structure, not a
cryptographic inclusion/absence proof. Hardware signing, cross-instance calls,
asset/fee migration and public-network admission are separate capabilities.

## Optional remote TLS transport

Every network command (`context`, `object`, `receipt`, `next-nonce`, `transfer`,
`split`, `merge`, `mint`, and `burn`) accepts a paired optional flag set:

```text
--tls-server-name <dns-name> --tls-ca-cert-der-file <path>
```

With neither flag, `--endpoint` must be loopback and the CLI uses plaintext.
With both flags, `--endpoint` is an already-resolved remote `SocketAddr`; the
CLI performs no DNS resolution. Supplying exactly one flag fails locally before
network dispatch.

```bash
cargo run -p sunrise-edge-cli -- context \
  --endpoint 203.0.113.10:7443 \
  --tls-server-name node.example.internal \
  --tls-ca-cert-der-file /etc/sunrise-edge/ca.der
```

The DNS name is used for both SNI and hostname validation and is never inferred
from the endpoint IP. The CA file must contain exactly one non-empty DER-encoded
X.509 certificate no larger than
`sunrise_edge_client::MAX_CA_CERTIFICATE_DER_BYTES` (16 KiB). The client does
not use the system trust store, accept PEM/bundles, or present an mTLS client
certificate.

TLS authenticates the endpoint, not the intended chain or protocol. Therefore
`transfer` still requires the independently configured `--expected-*` values
and validates `/v1/context` before nonce/object queries or signing. Certificate
revocation, rotation, lifecycle management, and operator CA distribution remain
part of later production work.
