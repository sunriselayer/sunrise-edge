# Activate and serve the first verified successor

Use one separate, completed SQLite inactive-import target per incoming
validator. A readiness certificate or successful import is not serving authority.
Activation verifies the original root, saved cut, accepted terminal Seal and its
exact named certificate before installing a protected target-local record.
The host never performs activation itself.

See the [design contract](../architecture/first-successor-serving.md),
[inactive import](business-import.md), [conditional readiness](conditional-readiness.md)
and [ordered Seal](ordered-seal.md). Acceptance status belongs in
[TODO.md](../../TODO.md), not this procedure.

## Retained inputs

Keep the original locally trusted `CUT_*` pins and full hash-suite schedule.
`CUT_EPOCH` is the original genesis epoch, not an endpoint-provided successor
epoch. Repeat `--suite` for every local schedule entry in both examples below.

- `CUT_HISTORY_DIR`: ordered history through T used by the import plan.
- `CUT_OUTPUT_DIR`: the saved pre-Seal business cut.
- `SUCCESSOR_MANIFEST_HISTORY_DIR`: a complete verified [history export](ordered-history.md)
  through accepted terminal Seal height h, including its original application
  receipt and links to the cut. Export from the sealed historical source; do not
  synthesize missing evidence from remote status or receipt summaries.
- `READY_CERTIFICATE_DIR`: the exact `certificate.bin` named by that Seal.
  A different valid quorum-certificate variant is not interchangeable.

Use that validator's existing `IMPORT_STATE_DB`, `IMPORT_BLOB_DB` and
`IMPORT_VALIDATOR_ID`. Database files must be outside all archive trees.
`READY_PRIVATE_KEY` is the protected regular file containing exactly 32 raw
Ed25519 seed bytes described in the readiness guide. The derived key must match
the accepted member. Keep all evidence directories attached and immutable.

## Activate and start locally

```sh
cargo build -p sunrise-edge-operator --bin successor_activation --bin successor_host
SUCCESSOR_ACTIVATION_BIN="${CARGO_TARGET_DIR:-target}/debug/successor_activation"
SUCCESSOR_HOST_BIN="${CARGO_TARGET_DIR:-target}/debug/successor_host"

"$SUCCESSOR_ACTIVATION_BIN" activate \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --manifest-history-dir "$SUCCESSOR_MANIFEST_HISTORY_DIR" \
  --certificate-dir "$READY_CERTIFICATE_DIR" \
  --target-state-db "$IMPORT_STATE_DB" --target-blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" --signer-key-file "$READY_PRIVATE_KEY"

"$SUCCESSOR_HOST_BIN" serve \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --manifest-history-dir "$SUCCESSOR_MANIFEST_HISTORY_DIR" \
  --certificate-dir "$READY_CERTIFICATE_DIR" \
  --target-state-db "$IMPORT_STATE_DB" --target-blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" --signer-key-file "$READY_PRIVATE_KEY" \
  --listen 127.0.0.1:4101 --created-checkpoint "$SUCCESSOR_CHECKPOINT" \
  --confirm-offline-fence-advance
```

An exact activation retry reports `already-activated` only after fresh evidence
and target verification, preserving advanced business state. A timeout never
authorizes deleting metadata, re-importing over the target or repairing records.

Ensure the previous writer is offline before confirming fence advance. The host
claims and holds one newer generation. `SUCCESSOR_CHECKPOINT` is trusted local
operational input, not client authority. The startup line reports the actual bound
address and generation after verification and binding. This exact-loopback-only
executable is not a public deployment, TLS or keystore certification. Each request
re-verifies attached evidence and the protected Serving record; startup success
does not bypass later evidence replacement or a superseded writer fence.

## Independently pinned clients and recovery

For [ordered](ordered-economics.md) and [FastVote](fastvote-network.md) workflows,
declare the verified adjacent `--expected-epoch` independently and add all five:

```text
--successor-genesis-epoch ORIGINAL_GENESIS_EPOCH
--successor-plan-history-dir ORIGINAL_PLAN_HISTORY
--successor-cut-dir SAVED_CUT
--successor-manifest-history-dir VERIFIED_TERMINAL_HISTORY
--successor-certificate-dir EXACT_NAMED_CERTIFICATE
```

Ordered commands keep their pinned `--domain`; commands without that flag require
`--successor-domain`. Partial flag sets refuse. Remote responses never choose a
fallback genesis or signing context. The SDK loads the same evidence into
`SuccessorWorkflowAuthority` before signing. Fee preparation returns an unsigned
intent; SDK signing requires that workflow and checks exact request, recipient,
certificate-epoch claimant key and signed execution leg before using the seed.

Recover missed ordered certificates through the existing signerless prefix replay
and paid work through its certified publication path. Reopening preserves safety
keys and completed receipts. Freeze, DrainSet, Seal and new bond-registration
controls refuse before signing in this first-successor scope. This procedure grants
no recurring lifecycle or generic PostgreSQL/D1/DO activation capability.
