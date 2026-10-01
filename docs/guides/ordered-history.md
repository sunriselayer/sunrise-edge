# Export and verify ordered history

This is a read-only native HTTP/Rust CLI workflow under
[DR-0169](../architecture/decisions/0169-authenticated-ordered-history-export.md).
It verifies consensus order and signed candidates from locally trusted
handoff-capable signed genesis. Original outcomes and receipts are
consistency-checked source companions, not independently executed business
results. It does not import state or authorize handoff, Seal or activation.
For independent business execution and PostgreSQL snapshot comparison under
the causal-admission profile, use the separate [business audit](business-audit.md).

Use the [ordered-network configuration](ordered-economics.md) with a locally
configured expected genesis digest, chain, protocol, epoch and atomicity
domain. Production HTTPS endpoints require their independently configured
TLS pins. Do not take these protocol pins from the endpoint being verified.
Loopback HTTP remains an explicit local test profile only.

```sh
sunrise-edge-cli economics history-export \
  --ordered-network "$ORDERED_NETWORK" \
  --ordered-genesis-manifest "$GENESIS_MANIFEST" \
  --ordered-expected-genesis-digest "$EXPECTED_GENESIS_DIGEST" \
  --expected-chain-id "$EXPECTED_CHAIN_ID" \
  --expected-protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --expected-epoch "$EXPECTED_EPOCH" \
  --domain "$EXPECTED_DOMAIN" \
  --target-validator-id "$SOURCE_VALIDATOR_ID" \
  --out-dir ./verified-ordering-history \
  --history-max-heights 1 \
  --history-chunk-bytes 1024 \
  --deadline-seconds 90 \
  --per-request-cap-seconds 10
```

The first invocation fixes the source-advertised target in `identity.bin`;
that advertisement is not authenticated until its full prefix verifies.
The height cap bounds new work per invocation, not the total allowed history.
A partial invocation leaves saved evidence but no `complete` file. Repeat
the same command to continue, including after stopping/restarting the source
and updating only its transport address in the network file. It must retain
the same target even when the source has advanced.

Optional `--history-through-height` and `--history-through-digest` must be
supplied together. On a new export they must match the source's advertised
applied tip; this profile does not discover arbitrary older targets. On
restart they check the already saved target, not the source's newer tip.
Neither case proves the target is the latest network state. Changing these
pins on an existing export refuses; use a different directory for a new tip.

Saved immutable files are organized as follows:

```text
verified-ordering-history/
  identity.bin
  chunk-size.bin
  height-00000000000000000001/
    descriptor.bin
    component-01/
      chunk-00000000000000000000.bin
      ...
    ...
  ...
  complete
```

Chunk names are their byte offsets within the individually typed component.
`chunk-size.bin` fixes the requested chunk size; resume with the original
`--history-chunk-bytes` value.
Chunks are raw canonical component bytes, not standalone signed results.
Descriptor lengths/digests and all assembled signatures/linkage are checked.
Restart re-verifies saved material from genesis; a filename, cursor or an
existing completion marker cannot replace verification. Changed/corrupt
files refuse and are not overwritten. Only a complete contiguous prefix
writes `complete`, containing the exact fixed identity bytes.

The verifier retains compact original-completion fingerprints so a later
recommit cannot change its first height, candidate identity or companions.
It does not retain every full component in memory, but this metadata grows
with the number of distinct original ordered requests. Downloaded data uses
disk proportional to the selected history.

An old store without the required pre-prune proofs or completion companions
cannot export a complete history. Missing history is not backfilled from
height counters or a SQL dump. An empty three-chain describes that proved
target and its successors only; it is not complete-drain or network-freshness
evidence. Operational status and remaining work belong in
[`TODO.md`](../../TODO.md).
