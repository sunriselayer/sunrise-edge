# First-epoch ordered Seal workflow

Seal is an outgoing consensus decision, not an operator database mutation.
It ends outgoing live signatures and ordinary writes; it does not activate a
successor or authorize serving. See the [closed design](../architecture/ordered-seal.md)
for authority and atomicity, and [TODO.md](../../TODO.md) for implementation and
release gates. Do not infer protocol completion from successful preparation.

## Prerequisites

Keep independently trusted chain, protocol, outgoing epoch, domain, signed
genesis digest and complete local hash schedule. Future schedule extensions
are separate configuration authority, not authenticated merely by genesis.
Use the [verified cut](business-import.md) and
[conditional readiness](conditional-readiness.md) workflow to obtain a saved
post-DrainSet cut and a genuine successor-quorum `certificate.bin`.

Each outgoing validator needs its own existing Ordinary SQLite state and blob
files. Staging must address those existing files, not a completed inactive
successor import. The ordinary ordered host needs the real local reconstruction
composition and its store's Seal capability. A PostgreSQL or unsupported host
does not gain that capability by receiving a candidate.

## Prepare and stage exact material

With variables set to independently verified values, run this once for each
outgoing validator's own state/blob files:

```sh
cargo run -p sunrise-edge-operator --bin ordered_seal -- prepare-sqlite \
  --chain-id "$chain" --protocol-version "$protocol" --epoch "$epoch" \
  --domain "$domain" --suite "$suite" \
  --genesis-manifest genesis.bin --expected-genesis-digest "$genesis_digest" \
  --ordered-history-dir history --cut-dir cut \
  --certificate ready/certificate.bin \
  --state-db "$state_db" --blob-db "$blob_db" \
  --validator-id "$validator_id" --out-dir "$candidate_directory"
```

Repeat `--suite` for the complete explicit schedule. The output directory must
already exist, be separate from the input archives, and contain only this
role's immutable `candidate.bin`. Exact retries preserve those bytes. A
different certificate variant requires a different output directory and yields
a different request, while retaining the same semantic target.

Preparation independently reconstructs the saved cut, verifies the exact
readiness subject and every weighted quorum signature, checks the existing
source is Ordinary and Unsealed, and stages the bounded immutable certificate
using Certificate at the outgoing epoch. It has no signer, writer-fence advance
or raw Seal-completion call. Staged content after a failed attempt is not
selection or authority. Live signing independently rechecks the current cut,
eligible successor set, empty-prefix extension and selected ancestry.

## Submit through ordinary ordered consensus

Use the existing [ordered network client](ordered-economics.md):

```sh
cargo run -p sunrise-edge-cli -- economics network-submit \
  --candidate "$candidate_directory/candidate.bin" --ordered-network peers.conf \
  --ordered-genesis-manifest genesis.bin \
  --ordered-expected-genesis-digest "$genesis_digest" \
  --expected-chain-id "$chain" --expected-protocol-version "$protocol" \
  --expected-epoch "$epoch" --domain "$domain" \
  --suite "$suite" --deadline-seconds 90 --per-request-cap-seconds 10 \
  --out seal-operation
```

The source preparation does not make any proposal succeed. Missing certificate
material, incomplete drain, unsupported storage, a changed verification token,
wrong roots or an incomplete authenticated prefix stop without an accepted
receipt. Keep every proposal, certificate and replay-manifest artifact. The
original accepted outcome, committed proof and protected Sealed barrier must
agree; an unsigned acknowledgement alone is not that evidence.

## Reconciliation and historical access

Recover using the original ordered replay manifest and signerless observation,
not a new candidate or request. Original receipt and outcome queries remain
historical. Sealed SQLite files can be opened through the named historical
access path; that path neither resets the barrier nor permits writes. Normal
live open and serving startup refuse Sealed namespaces. No force, unseal,
successor activation or recurring-epoch command is provided by this workflow.
