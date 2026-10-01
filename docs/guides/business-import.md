# Install a verified business cut into inactive SQLite

`business_import` privately reexecutes one complete first-epoch saved cut and
installs its verified raw inventory into a dedicated import-only namespace.
The result cannot admit new business, sign protocol votes/ACKs or serve an
activated epoch. See [the storage/authority contract](../architecture/verified-inactive-import.md)
and [DR-0176](../architecture/decisions/0176-verified-inactive-business-import.md).

## Inputs

First produce the complete output in the [business cut guide](business-cut.md).
Reuse its independently configured `CUT_CHAIN_ID`, `CUT_PROTOCOL_VERSION`,
`CUT_EPOCH`, `CUT_DOMAIN`, `CUT_SUITE`, `CUT_GENESIS_FILE`,
`CUT_GENESIS_DIGEST`, `CUT_HISTORY_DIR` and `CUT_OUTPUT_DIR`.

Choose two distinct absent destination database paths whose parent directories
already exist and are operator-controlled. Set `IMPORT_STATE_DB`,
`IMPORT_BLOB_DB` and `IMPORT_VALIDATOR_ID` yourself. The validator ID selects
the destination namespace; it does not certify eligibility in the next set.
Do not supply a private key, endpoint or source writer generation.

```sh
cargo build -p sunrise-edge-operator --bin business_import
BUSINESS_IMPORT_BIN="${CARGO_TARGET_DIR:-target}/debug/business_import"

"$BUSINESS_IMPORT_BIN" create-sqlite \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --state-db "$IMPORT_STATE_DB" --blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" \
  --max-new-batches 1 --timeout-seconds 300
```

Input parsing and independent plan verification precede destination creation.
Creation reserves fresh paths and a destination-local fence; it never reuses
an ordinary namespace or copies source-local authority. Creation failure may
leave reserved files. Do not delete/repair metadata or force resumption of
missing/invalid schemas; use another genuinely fresh destination instead.

## Resume after bounded work or restart

`business_import=partial` means bounded new batches were durably installed,
not that the target may serve. Close the process and rerun with the same exact
local pins, saved cut, destination paths and namespace:

```sh
"$BUSINESS_IMPORT_BIN" resume-sqlite \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --state-db "$IMPORT_STATE_DB" --blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" \
  --max-new-batches 4096 --timeout-seconds 300
```

Each invocation accepts one through 4,096 new atomic batches, each at most
128 rows and 64 MiB total new represented rows plus distinct required bodies.
The complete installed prefix is verified before any new material is written;
resumed bodies are checked using exact-length descriptors and at most 1 MiB
read ranges. This does not cap legal history or the CPU/memory cost of
independently reconstructing it. Resume uses verified
existing writable import/blob schemas without creating or repairing them.

`business_import=complete-inactive` means the complete raw inventory and
referenced immutable bodies were independently compared and the completion
was fenced atomically. The reported `cut`, `package` and `plan` identities must
remain fixed. It is not readiness, Seal, activation or a live-network release.

An ordinary target, wrong namespace/binding/pins, conflicting row, missing or
surplus material, corrupt progress or stale fence refuses. A deleted cursor
does not erase import origin. Exact original business replay remains receipt-
first and non-executing under the current fence; new execution and cached
protocol signatures/ACKs remain refused in every import phase.

The native durable schema is version 2. Older initialized durable files are
unsupported, not automatically migrated or reset. Preserve any needed old
data separately and request an explicitly scoped preservation workflow.
SQLite evidence does not certify PostgreSQL, D1, a deployed DO host, readiness
or production/mainnet safety.
