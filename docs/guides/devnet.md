# Local devnet and Rust CLI

This guide starts the local, non-production Sunrise Edge devnet and drives it
with the Rust CLI. The devnet binds loopback only, is single-validator, and
must never be used to custody real assets or exposed beyond your own machine.

The devnet activates Standard Asset v1 whole-coin transfer (DR-0107): each
configured `--dev-owner` is seeded with one transferable
`StandardAssetCoinV1` and one distinct fee-payer coin, and the separate
`--fee-treasury-owner` is seeded with one ordinary treasury coin. `transfer`
moves a whole coin's ownership to a signed recipient address; there is no
partial-amount transfer, `Create`, split, or merge yet.

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

Startup prints one line per seeded owner, including the treasury:

```text
owner=<owner> role=dev-owner seed_status=<created|verified-existing> transfer_coin=<object id> fee_coin=<object id>
owner=<owner> role=fee-treasury seed_status=<created|verified-existing> treasury_coin=<object id>
```

It also prints the derived asset id and preinstalled module identity:

```text
asset_id=<...> module_id=<...> module_version=<...> module_digest=<algorithm-label>:<hex digest>
```

Copy the sender's `transfer_coin` and `fee_coin`, the treasury's
`treasury_coin`, `asset_id`, `module_id`, `module_version`, and
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
EXPECTED_PROTOCOL_VERSION=4
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

## 5. Submit a whole-coin transfer

The sender signs a whole-object transfer of its transferable coin to the
recipient address, paying the fee from its distinct fee coin. The fee asset
must equal the transferred coin's asset (the protocol forces this: a single
shared type variable per entrypoint signature unifies both). After the
transfer, `SOURCE_COIN_ID`'s owner is `RECIPIENT_OWNER`; its body (asset id
and amount) is unchanged.

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
  --wait \
  --wait-max-attempts 20 \
  --wait-initial-backoff-ms 10 \
  --wait-max-backoff-ms 50 \
  --wait-max-elapsed-ms 5000
```

`transfer` requires `--recipient`, all five `--expected-*` flags, and the
complete fee configuration shown above (this devnet's committed base fee is
always non-zero, so a fee is always due). It rejects a malformed recipient,
zero max fee, a treasury equal to the source or fee coin, or an invalid
expected context before network dispatch. It then verifies `/v1/context`,
that both coins are owned by the signer, that they share one `AssetId`, and
that `--fee-asset-id` matches, before signing. A rejected or execution-failed
submission is a typed non-zero-exit error, including with `--wait`.

Once a fee coin's amount falls to exactly the currently settled fee, it
becomes permanently unusable as a fee payer (`StandardAssetCoinV1` forbids a
zero amount) — the seeded fee-coin amount is generous, but a long-running
devnet session should watch for this.

## 6. Capture post-transfer state

Capture the receipt, all three current coins, and next nonce. These are the
pre-restart observations used in the next step.

```bash
OBSERVATION_PREFIX="/tmp/sunrise-edge-$REQUEST_ID"
cargo run -p sunrise-edge-cli -- receipt --endpoint 127.0.0.1:7400 \
  --request-id "$REQUEST_ID" > "$OBSERVATION_PREFIX.receipt"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$SOURCE_COIN_ID" > "$OBSERVATION_PREFIX.source"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$FEE_COIN_ID" > "$OBSERVATION_PREFIX.fee"
cargo run -p sunrise-edge-cli -- object --endpoint 127.0.0.1:7400 \
  --object-id "$TREASURY_OBJECT_ID" > "$OBSERVATION_PREFIX.treasury"
cargo run -p sunrise-edge-cli -- next-nonce --endpoint 127.0.0.1:7400 \
  --sender "$SENDER_OWNER" > "$OBSERVATION_PREFIX.nonce"
```

## 7. Restart and compare

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

The automated E2E additionally replays one byte-identical signed request before
and after restart, including a restart that happens strictly after a real
ownership transfer. The CLI intentionally exposes no raw replay command
because `transfer` re-queries the current nonce and object references before
signing.

A data directory created under a different committed protocol version fails
closed rather than silently seeding a disjoint object set. Protocol 3 predates
the marker and is rejected as `UnmarkedExistingObjectState` when its object
store is non-empty; a later marked version or epoch mismatch is rejected as
`ProtocolVersionMismatch` or `EpochMismatch`. Start a fresh `--data-dir`
rather than reusing one across an incompatible devnet upgrade or epoch change.

## Optional remote TLS transport

Every network command (`context`, `object`, `receipt`, `next-nonce`, and
`transfer`) accepts a paired optional flag set:

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
