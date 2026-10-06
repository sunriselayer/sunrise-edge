# Offline Standard Asset genesis authoring

Create a signed original genesis from explicit local inputs, then pass the
exact manifest to [SQLite preparation and startup](sqlite-validator-startup.md).
This named operator preset uses the ordinary public Standard Asset contract.
It is not a native coin, arbitrary-package compiler, live transaction or
network deployment. PostgreSQL, Cloudflare credentials and deployed Workers
are not involved.

[DR-0196](../architecture/decisions/0196-standard-asset-genesis-authoring.md)
defines the trust and custody boundaries. Current implementation and release
gates belong only in [TODO](../../TODO.md).

## Choose and review inputs

Use independently chosen chain, protocol, original epoch, full hash schedule
and positive minimum Freeze block height. Do not reuse the public devnet key
or its fixed economic values for real custody.

Provide the expected genesis-authority public key and a protected regular file
containing exactly its 32-byte Ed25519 seed. The existing loader rejects
symlinks, unsupported size and permissive Unix permissions. No seed belongs in
arguments, tables, stdout, a checked-in file or this guide. The author derives
the public key and requires equality before signing anything. Validator private
keys are not needed here: validators supply registered public keys; possession,
independent custody and any multi-party ceremony remain separate obligations.

Prepare two UTF-8 text files. Every line has exactly the indicated
whitespace-separated columns, without headers, comments or blank lines:

```text
validators: validator-id-hex registered-ed25519-public-key-hex voting-power bond-amount collateral-object-id-hex
allocations: address-owner-hex positive-amount coin-object-id-hex
```

Each hex value has 32 bytes. Amounts and powers are canonical unsigned decimal,
without signs or leading zeros. Validators have positive power and bonds within
the explicit minimum/exposure bounds. Power is not derived from bond amount.
The committee is nonempty; the allocation file may be empty. Each table is at
most 16 KiB. Definition, TreasuryCap, allocation Coins and validator collateral
use distinct ObjectIds, with at most 32 objects total. Validator IDs and
registered keys are unique in this preset. Repeated allocation owners are
allowed: one owner can hold several distinct Coins.

Choose the public mint authority and fee recipient separately from the genesis
signer. The genesis authority owns the definition; the explicit mint authority
owns the TreasuryCap. Each allocation is an ordinary address-owned Coin;
collateral is an ordinary Coin under the existing validator bond custody scope.
The TreasuryCap's initial supply is the checked sum of allocations and
collateral, not a chain-level balance. The existing core verifies ordinary
code/instance/type/object provenance with no Standard Asset exception.

Choose all gas prices, conversion divisor, reserve/settle allowances, publication
prices and bond settings explicitly. Unsupported schedules or bounds refuse;
existing fixed execution-phase caps and contract hook/schema names are not
caller-configurable. These inputs require separate economic review.

## Run the author

Build the actual local executables:

```sh
cargo build --locked -p sunrise-edge-operator \
  --bin standard_asset_genesis --bin sqlite_genesis --bin sqlite_source_host
```

The following Bash command expects approved values in the environment and
existing regular input files. There is no economic, key or network default.
Set `SUITE_SPECS` to the complete approved Bash array before running it; each
entry is `epoch:id:transaction:object:effects:code:config:certificate`.

```bash
: "${CHAIN_ID:?}" "${PROTOCOL_VERSION:?}" "${EPOCH:?}"
: "${SUITE_SPECS[*]:?}" "${MINIMUM_FREEZE_BLOCK_HEIGHT:?}"
: "${GENESIS_AUTHORITY_HEX:?}" "${GENESIS_KEY_FILE:?}"
: "${ORIGIN_SEED_HEX:?}" "${INSTANCE_SEED_HEX:?}"
: "${PUBLICATION_REQUEST_ID_HEX:?}" "${INITIALIZATION_REQUEST_ID_HEX:?}"
: "${DEFINITION_ID_HEX:?}" "${TREASURY_CAP_ID_HEX:?}"
: "${MINT_AUTHORITY_HEX:?}" "${FEE_RECIPIENT_HEX:?}"
: "${VALIDATORS_FILE:?}" "${ALLOCATIONS_FILE:?}" "${GENESIS_MANIFEST:?}"
: "${INITIALIZATION_GAS_LIMIT:?}" "${BASE_FEE:?}" "${EXECUTION_PRICE:?}"
: "${READ_PRICE:?}" "${WRITE_PRICE:?}" "${STORAGE_PRICE:?}" "${SYSTEM_MODULE_PRICE:?}"
: "${CONVERSION_DIVISOR:?}" "${RESERVE_ALLOWANCE:?}" "${SETTLE_ALLOWANCE:?}"
: "${PUBLISH_ARTIFACT_BYTE_PRICE:?}" "${PUBLISH_CLOSURE_NODE_PRICE:?}"
: "${MIN_BOND:?}" "${UNBONDING_EPOCHS:?}" "${MAX_VALIDATOR_EXPOSURE:?}"
: "${VALIDATION_DOMAIN_HEX:?}" "${VALIDATION_CHECKPOINT:?}" "${TIMEOUT_SECONDS:?}"
AUTHOR_PINS=(--chain-id "$CHAIN_ID" --protocol-version "$PROTOCOL_VERSION" --epoch "$EPOCH")
for suite in "${SUITE_SPECS[@]}"; do
  AUTHOR_PINS+=(--suite "$suite")
done

target/debug/standard_asset_genesis author "${AUTHOR_PINS[@]}" \
  --minimum-freeze-block-height "$MINIMUM_FREEZE_BLOCK_HEIGHT" \
  --expected-genesis-authority "$GENESIS_AUTHORITY_HEX" \
  --genesis-key-file "$GENESIS_KEY_FILE" \
  --origin-seed "$ORIGIN_SEED_HEX" --instance-seed "$INSTANCE_SEED_HEX" \
  --publication-request-id "$PUBLICATION_REQUEST_ID_HEX" \
  --initialization-request-id "$INITIALIZATION_REQUEST_ID_HEX" \
  --definition-id "$DEFINITION_ID_HEX" --treasury-cap-id "$TREASURY_CAP_ID_HEX" \
  --mint-authority "$MINT_AUTHORITY_HEX" --fee-recipient "$FEE_RECIPIENT_HEX" \
  --validators-file "$VALIDATORS_FILE" --allocations-file "$ALLOCATIONS_FILE" \
  --initialization-gas-limit "$INITIALIZATION_GAS_LIMIT" \
  --base-fee "$BASE_FEE" --execution-price "$EXECUTION_PRICE" \
  --read-price "$READ_PRICE" --write-price "$WRITE_PRICE" \
  --storage-price "$STORAGE_PRICE" --system-module-price "$SYSTEM_MODULE_PRICE" \
  --conversion-divisor "$CONVERSION_DIVISOR" \
  --reserve-allowance "$RESERVE_ALLOWANCE" --settle-allowance "$SETTLE_ALLOWANCE" \
  --publish-artifact-byte-price "$PUBLISH_ARTIFACT_BYTE_PRICE" \
  --publish-closure-node-price "$PUBLISH_CLOSURE_NODE_PRICE" \
  --min-bond "$MIN_BOND" --unbonding-epochs "$UNBONDING_EPOCHS" \
  --max-validator-exposure "$MAX_VALIDATOR_EXPOSURE" \
  --validation-domain "$VALIDATION_DOMAIN_HEX" \
  --validation-checkpoint "$VALIDATION_CHECKPOINT" \
  --timeout-seconds "$TIMEOUT_SECONDS" --output "$GENESIS_MANIFEST"
```

`MAX_VALIDATOR_EXPOSURE` is an explicit decimal limit or the literal `none`.
The timeout is positive and at most 30 seconds, the defining storage-operation
bound. Output must be a fresh path under existing regular directories, not an
input alias, symlink, existing file or parent traversal.

Require exit zero and exactly one
`complete=true mode=author manifest_digest=... genesis_authority=...` line.
The package, publication, Instantiate initializer and outer manifest use the
existing canonical encoders and signing frames. The outer signature is made
last; it embeds the exact nested signed frames. Before creating an output file,
the author verifies the root and runs both real installers in a discarded
private in-memory namespace, including generic WASM, fees, objects and bonds.

The validation domain and checkpoint belong only to that discarded namespace.
The trusted clock supplies its bounded deadline and pacemaker. None enters the
manifest or successful stdout. Identical author inputs produce identical bytes
and digest regardless of those local validation observations.

## Distribute and prepare

Review the resulting manifest, allocation/economic choices and public authority
independently before distributing its exact bytes and approved expected digest.
The author output proves self-consistency and supported installer acceptance,
not human approval, key possession, custody or readiness to expose a network.

For each validator, use that same manifest and independently expected digest
with explicit chain/protocol/epoch/schedule/validator/domain pins and a distinct
fresh SQLite state/blob pair. Then run public-key preflight and the independently
reverified serving host using the [startup guide](sqlite-validator-startup.md).
The chosen local atomicity domain is not authenticated by the manifest. Do not
turn author stdout or an earlier successful preflight into live authorization.

Validation failures before output reservation leave inputs unchanged and create
no new manifest. After reservation, an I/O failure may leave a partial file:
preserve it for inspection, require a new destination for another attempt and
do not auto-delete, overwrite or repair it. Exactly one manifest is written;
there is no sidecar checksum file, seed export, listener or provider write.

Keep serving on loopback until independent economics/ingress audits, key custody,
genesis approval, transport/authentication/TLS and a selected actual activation
profile are complete. Local authoring is not a production/mainnet declaration.
