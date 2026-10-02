# Retain and verify conditional readiness

This local workflow freshly reconstructs one complete first-epoch saved cut
and compares a completed inactive import before signing. A public weighted
certificate is an assertion about a supplied exact candidate set, not an
activation capability. No command advances the live ordered engine, changes
its writer fence, installs a serving policy or authorizes ordinary signatures.
See [architecture](../architecture/conditional-readiness-seal.md) and
[DR-0178](../architecture/decisions/0178-conditional-readiness-wire-and-retention.md).

## Pins, target and key

First follow the [cut export](business-cut.md) and
[verified inactive import](business-import.md) guides. Each retained A/B/C and
incoming E needs its own separate completed inactive namespace. A namespace ID
is not membership; E needs its real [first bond registration](initial-validator-bond.md).
Reuse the independently trusted `CUT_*` pins and exact saved input directories.
Supply the complete locally trusted schedule, not merely its currently active
suite. The signed genesis file is not authority for this separate configuration.

`READY_NEXT_SET` must be the existing exact canonical ValidatorSet frame at the
adjacent epoch, at most 64 KiB and 256 members. Every member/key and actual
post-drain bond/resource eligibility is checked before the local vote is signed.
Freeze's advisory set is not irreversible membership. An eligible corrected
set may produce another readiness identity before Seal; it cannot rebind the
existing saved import or silently overwrite an earlier artifact.

Select existing distinct `IMPORT_STATE_DB`/`IMPORT_BLOB_DB` files outside both
input archive trees, with the exact `IMPORT_VALIDATOR_ID` namespace binding.
The signer file is one private regular nonsymlink file containing exactly
32 raw Ed25519 seed bytes (not hex). On Unix, group/other permission bits must
be absent. Its actual derived public key must match this member's registered
key before signing. This software-key composition is not a production keystore
or hardware-key certification.

`READY_VOTE_DIR` must already exist as a separate operator-controlled output
directory. It may contain only the exact previous `vote.bin` artifact for this
role. Paths inside either input tree are refused before target writes. Corrupt,
foreign or conflicting output is not overwritten or repaired.

## Vote and exact restart retry

This example assumes exactly one complete schedule entry. Repeat `--suite`
for every entry, including future entries, when configuration contains more.

```sh
cargo build -p sunrise-edge-operator --bin conditional_readiness
READINESS_BIN="${CARGO_TARGET_DIR:-target}/debug/conditional_readiness"

"$READINESS_BIN" vote-sqlite \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --next-set "$READY_NEXT_SET" --out-dir "$READY_VOTE_DIR" \
  --state-db "$IMPORT_STATE_DB" --blob-db "$IMPORT_BLOB_DB" \
  --validator-id "$IMPORT_VALIDATOR_ID" --signer-key-file "$READY_PRIVATE_KEY" \
  --timeout-seconds 300
```

`conditional_readiness=retained-vote` means the exact verified signature was
observed durably retained. Every invocation, including same-process and
post-restart retries, independently reconstructs the cut and rechecks the entire
target. A present exact record returns its original vote without re-signing or
changing its original local creation observation. The current retry token must
still be fresh; old-token equality is not a replay shortcut.

On uncertain commit acknowledgement, only full fresh target verification and
the exact landed record can justify returning the computed vote. An unlanded,
conflicting or unreadable result refuses; retry with the same inputs later.
No response or timeout authorizes deletion, metadata repair or ordinary serving.

## Public certificate assembly

Use a separate existing empty `READY_CERTIFICATE_DIR`. Supply one through 256
bounded vote files, all for the exact same subject and complete candidate set.
This mode needs no target databases or private key. It independently reexecutes
the saved cut and verifies exact configuration, keys, subjects, signatures and
distinct weighted quorum. Decoding/certificate assembly is not a constructor
of a member's private import/eligibility capability; later Seal acceptance must
independently establish those facts under its own reviewed authority.

```sh
"$READINESS_BIN" certificate \
  --chain-id "$CUT_CHAIN_ID" --protocol-version "$CUT_PROTOCOL_VERSION" \
  --epoch "$CUT_EPOCH" --domain "$CUT_DOMAIN" --suite "$CUT_SUITE" \
  --genesis-manifest "$CUT_GENESIS_FILE" \
  --expected-genesis-digest "$CUT_GENESIS_DIGEST" \
  --ordered-history-dir "$CUT_HISTORY_DIR" --cut-dir "$CUT_OUTPUT_DIR" \
  --next-set "$READY_NEXT_SET" --out-dir "$READY_CERTIFICATE_DIR" \
  --vote "$READY_VOTE_A" --vote "$READY_VOTE_B" --vote "$READY_VOTE_E"
```

The example is usable only if those distinct members exceed two thirds of the
candidate set's voting power; three files are not intrinsically a quorum.
Duplicate IDs never add weight. Saved output is immutable `certificate.bin`;
exact retries preserve it, while conflicting artifacts refuse.

SQLite readiness does not implement PostgreSQL import, D1 or deployed DO
readiness. Unsupported old durable schemas and missing/corrupt protected
metadata refuse without automatic migration or fallback. This guide grants no
Seal, activation, live deployment, audit or Delivery 3 completion. See
[TODO.md](../../TODO.md) for the remaining gates.
