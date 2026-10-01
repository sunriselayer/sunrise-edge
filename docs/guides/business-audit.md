# Audit one fixed PostgreSQL business snapshot

`business_audit_pg` independently executes authenticated owned publications
and the original ordered prefix, then compares all four portable collections
against an existing PostgreSQL namespace. It never claims a writer fence,
repairs source rows, imports state or signs a protocol vote. See the
[reconstruction contract](../architecture/business-reconstruction.md) and
[DR-0170](../architecture/decisions/0170-causal-business-reconstruction.md).

## Prerequisites

- A locally configured signed causal-admission genesis manifest and its expected
  commitment. Historical profiles cannot retroactively establish causal replay.
- Locally configured chain, protocol, epoch, domain, validator and complete hash
  suite schedule matching that manifest. Endpoint responses are not these pins.
- A complete [ordered-history export](ordered-history.md) for the source's fixed
  applied tip, including every bounded proof/candidate/result/receipt component.
- A quiescent existing source namespace with complete retained publication and
  availability material, referenced object bodies and an empty outbox.
- A PostgreSQL account allowed to read the source tables and namespace metadata.
  TLS trust is configured separately from protocol trust. The operator requires
  TLS and does not accept an insecure plaintext fallback.

Build the operator and set the DSN through your normal secret-delivery mechanism:

```sh
cargo build --release -p sunrise-edge-operator --bin business_audit_pg
# SUNRISE_EDGE_OPERATOR_POSTGRES_DSN is supplied by the environment.
./target/release/business_audit_pg \
  --tls-root-der "$POSTGRES_ROOT_CA_DER" \
  --genesis-manifest "$GENESIS_MANIFEST" \
  --expected-genesis-digest "$EXPECTED_GENESIS_DIGEST" \
  --chain-id "$EXPECTED_CHAIN_ID" \
  --protocol-version "$EXPECTED_PROTOCOL_VERSION" \
  --epoch "$EXPECTED_EPOCH" \
  --validator-id "$SOURCE_VALIDATOR_ID" \
  --domain "$EXPECTED_DOMAIN" \
  --suite "$EXPECTED_HASH_SUITE" \
  --ordered-history-dir ./verified-ordering-history \
  --out-dir ./business-audit-observation \
  --page-size 128 \
  --timeout-seconds 300 \
  --max-new-publications 1
```

Each `--suite` uses
`activation_epoch:suite_id:tx:object:effects:code:config:certificate`.
Algorithm `1` means SHA2-256 and `2` means SHA3-256. Supply one to 64 explicit
schedule entries; do not derive a schedule from untrusted saved material.
The genesis schedule `0:1:1:1:1:1:1:1` is an example, not a universal network pin.
If builds use `CARGO_TARGET_DIR`, run the corresponding release binary there.

## Bounded collection and immutable resume

`--max-new-publications` limits newly cached complete publications per invocation
to one through 4096. It is not a maximum allowed history length. A partial result
prints `audit=partial` and explicitly makes no semantic-equality claim. Repeat the
same command and output directory to continue collecting the same observation.

The directory contains a source token, fixed ordered identity and immutable
publication bundles, availability proofs and comparison-target metadata. Every
restart rereads the source under one backend-enforced snapshot token and
reverifies the saved ordered prefix and all cached material. A saved cursor,
metadata bit or completion file never authorizes execution or skips verification.
Files are published only after complete writes and synchronization; changed
saved bytes refuse instead of being overwritten.

The token binds the source namespace instance, writer fence and mutation
sequence. A restart that changes the writer fence, or any intervening source
mutation, refuses continuation even if some business values appear unchanged.
Use a new output directory and a matching history export for a new observation;
do not delete pins to force an old observation to continue. Restart the source
before starting collection if you want to audit its post-restart state.

## Meaning of a successful result

`audit=semantic-equal` and the immutable `complete` report are written only after
independent replay, closed semantic equality and a final same-token/outbox-empty
check. Comparison includes original receipts, nonces, object heads/versions,
contract code and authority, economics and authenticated epoch-control facts.
Valid certificate subsets are normalized only after independent verification
of the same certified subject and complete artifact closure.

Local CAS revisions, writer bookkeeping and explicitly identified unsigned
creation/installation coordinates are not protocol business facts. Signed
candidate checkpoints, hash-linked economic transitions and original result
bytes remain exact. Unknown reserved keys, malformed progress, extra or missing
business rows, corrupt artifacts and inconsistent companions refuse the audit.

This result proves equality at one fixed source snapshot. It is not proof that
the source is the newest network state, nor a persistent cut, incoming-validator
import, readiness authorization, Seal or activation. Those remain separate
workflows. Implementation and verification status live in [TODO.md](../../TODO.md).
