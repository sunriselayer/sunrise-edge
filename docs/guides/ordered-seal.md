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

## Host composition boundary

Start one `sqlite_source_host` per independently owned outgoing namespace.
The host consumes original trusted pins and existing Ordinary, Unsealed files;
it does not bootstrap or repair them. Stop competing writers first. The explicit
confirmation permits one writer-fence advance, not an authority bypass:

```sh
cargo run -p sunrise-edge-operator --bin sqlite_source_host -- \
  --chain-id "$chain" --protocol-version "$protocol" --epoch "$epoch" \
  --domain "$domain" --suite "$suite" \
  --genesis-manifest genesis.bin --expected-genesis-digest "$genesis_digest" \
  --validator-id "$validator_id" --signing-key-file "$signer_key" \
  --state-db "$state_db" --blob-db "$blob_db" \
  --listen 127.0.0.1:8000 --created-checkpoint "$checkpoint" \
  --timeout-seconds 30 --max-concurrent 16 \
  --confirm-offline-fence-advance
```

Repeat `--suite` for the complete independently configured schedule. The host
requires `--timeout-seconds` within 1..30, the existing native per-request
authority bound, and `--max-concurrent` within 1..256. A client's whole-workflow
deadline is separate; a long deadline does not enlarge a validator's authority.
The host
requires the original causal genesis profile, exact installed marker, fee
policy and original committee, and the local member's actual registered key.
Deciding storage reads use the newly claimed generation; refusal after that
claim can still advance the fence, but never installs business state or grants
serving permission. Listening is loopback-only. Use distinct addresses and
state/blob/key files for each validator and record those addresses in the
existing ordered network configuration.

This native process is transport convenience, not a protocol requirement or
public-provider deployment. The PostgreSQL host does not compose Seal.
Actual test/process and release evidence remain in [TODO.md](../../TODO.md).

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

Against validators with the explicit verified composition above, use the
existing [ordered network client](ordered-economics.md):

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
client may first certify up to two ordinary empty alignment rounds; their exact
artifacts stay in that manifest. No candidate-height exception is granted.
The original accepted outcome, committed proof and protected Sealed barrier must
agree; an unsigned acknowledgement alone is not that evidence.

## Reconciliation and historical access

Recover using the original ordered replay manifest and signerless observation,
not a new candidate or request. Original receipt and outcome queries remain
historical. Sealed SQLite files can be opened through the named historical
access path; that path neither resets the barrier nor permits writes. Normal
live open and serving startup refuse Sealed namespaces. No force, unseal,
successor activation or recurring-epoch command is provided by this workflow.
