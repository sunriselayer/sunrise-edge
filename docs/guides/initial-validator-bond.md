# Prepare and submit an initial validator bond

This first-epoch causal workflow creates a non-genesis validator's first bond.
It does not add the validator to a committee or authorize epoch activation.
See [architecture](../architecture/initial-validator-bond.md) and
[DR-0179](../architecture/decisions/0179-initial-validator-bond-registration.md).

## Independently trusted inputs

Use the signed genesis manifest, expected digest, chain/protocol/epoch, domain
and complete locally configured hash schedule of the ordered network. Genesis
does not authenticate the separate hash schedule or domain by itself. Never
learn those pins from the endpoint to which the transaction will be sent.

Provide an exact already-signed owned custody leg and a bounded predicted
generation-1 `FastPathBondRecord`. They must agree on the nonzero Ordered-lane
request ID, exact resource, validator/key, context, source authority, object
version, liability and checkpoint. The predicted row is a claim, not stored
state or execution evidence. Normal generic WASM execution must reproduce its
exact digest; a wrong prediction is refused with no partial application effects.
The actual source owner signs the leg; the actual incoming validator signs the
outer registration. The source may be donated by another owner.

The development CLI accepts a private seed file and derives the new ID from
its actual Ed25519 public key. It is not a production keystore. Preserve private
file permissions and never place seed contents, bearer tokens or DSNs in argv.

## Offline preparation and existing ordered transport

Set the variables below from local verified inputs. This example assumes the
complete schedule has exactly one entry; otherwise repeat `--suite` for every
entry, including future entries, consistently across all commands.

```sh
cargo run -p sunrise-edge-cli -- economics bond-registration-prepare \
  --ordered-genesis-manifest "$REG_GENESIS_FILE" \
  --ordered-expected-genesis-digest "$REG_GENESIS_DIGEST" \
  --expected-chain-id "$REG_CHAIN" --expected-protocol-version "$REG_PROTOCOL" \
  --expected-epoch "$REG_EPOCH" --domain "$REG_DOMAIN" --suite "$REG_SUITE" \
  --request-id "$REG_REQUEST_ID" --signed-leg "$REG_SIGNED_LEG" \
  --expected-bond-row "$REG_EXPECTED_ROW" --seed-file "$REG_PRIVATE_SEED" \
  --out "$REG_SIGNED_ENVELOPE"

cargo run -p sunrise-edge-cli -- economics candidate-wrap \
  --kind bond-registration --intent "$REG_SIGNED_ENVELOPE" \
  --request-id "$REG_REQUEST_ID" --created-checkpoint "$REG_CHECKPOINT" \
  --ordered-genesis-manifest "$REG_GENESIS_FILE" \
  --ordered-expected-genesis-digest "$REG_GENESIS_DIGEST" \
  --expected-chain-id "$REG_CHAIN" --expected-protocol-version "$REG_PROTOCOL" \
  --expected-epoch "$REG_EPOCH" --domain "$REG_DOMAIN" --suite "$REG_SUITE" \
  --out "$REG_CANDIDATE"
```

Preparation prints `executed=false`. Both commands reserve new output files
without overwriting inputs or prior artifacts. Save exact signed bytes; do not
re-sign a different operation under a previously used request ID.

Submit `REG_CANDIDATE` through the existing
[ordered network-submit/replay workflow](ordered-economics.md), passing the same
explicit `--suite` entries and local context/genesis/domain pins. That route's
TLS/authentication settings remain separate transport authority. A valid
prepared envelope or successful HTTP transport is not a committed bond: verify
the retained ordered outcome, original registration receipt, exact custody
object and bond on every validator, or use normal signerless catch-up.

## Replay and refusal

Exact replay preserves the original receipt, object, nonce, root and bond.
Request reuse, key/ID squatting, wrong pins, deleted/partial roots and stale
writers do not authorize repair. A healthy deterministic execution refusal
retains its ordered refused outcome, not an application receipt or custody
mutation; a subsequent valid candidate can progress normally.
No seed, force-Exited row, live policy mutation, automatic membership change or
unsupported new-key same-epoch lifecycle operation is part of this workflow.
