# Local FastVote fee-escrow inventory

The `fee_escrow_inventory` executable verifies every **present** certified
fee-escrow settlement key for one existing SQLite validator namespace. It is
an offline maintenance check, not a network-capacity or rollback proof.

1. Stop the validator and keep its data directory on the same local
   filesystem. Do not run this against a live node or a mutable copy.
2. Obtain the chain ID, validator ID, domain, protocol version and exact
   ordered hash-suite schedule from the trusted network configuration. Do
   not derive the expected values from the files under examination.
3. Run the command below. Each `--suite` is
   `activation_epoch:suite_id:transaction:object:effects:code:config:certificate`;
   the six algorithm fields use decimal wire IDs (1 = SHA-256, 2 = SHA3-256).
   Add one `--suite` for every activation, beginning at epoch 0. Use a small
   page size; each row performs full cryptographic and object-history checks.

```sh
cargo run --release -p sunrise-edge-devnet --bin fee_escrow_inventory -- \
  --data-dir /path/to/stopped-validator-data \
  --chain-id YOUR_CHAIN_ID \
  --validator-id YOUR_64_HEX_DIGIT_VALIDATOR_ID \
  --domain YOUR_64_HEX_DIGIT_DOMAIN_ID \
  --protocol-version YOUR_VERSION \
  --suite 0:1:1:1:1:1:1:1 \
  --page-size 32 --timeout-seconds 3600 \
  --confirm-offline-fence-advance
```

The confirmation flag acknowledges a **persistent writer-fence advance**.
It invalidates the stopped process's prior generation; restart that process
normally after the check. If another process starts while the sweep runs,
the command fails and its partial count must be discarded **if that process
uses the supported boot path that advances the fence**. A direct SQLite writer
that bypasses boot and adopts the sweep's generation is outside this proof;
keep the database offline and under operator control. Success prints
`complete=true`, namespace/data-directory identity, claimed generation, page
count, verified rows, claims and
signed split payouts. Any error exits nonzero without a complete result.
Keep the command output with the independently recorded stop/start and
configuration evidence. Zero rows means only that this namespace contains
no present settlement keys; it is not evidence of no earlier deleted rows.

The current binary covers local SQLite only. It does not make a PostgreSQL
deployment operable or certify sustained network load/soak/restart capacity;
see [DR-0142](../architecture/decisions/0142-fastvote-operator-escrow-inventory.md)
and `TODO.md`.
