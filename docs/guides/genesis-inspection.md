# Inspect a signed original genesis without a private key

This local command describes an already signed original genesis after checking
independent public pins and running the defining generic installers in discarded
memory. It is not key-custody, economic-approval, security-audit or network-startup
evidence. [DR-0197](../architecture/decisions/0197-offline-original-genesis-inspection.md)
defines the authority boundary; current status belongs in [TODO](../../TODO.md).

## Supply independent public pins

Obtain the expected digest and genesis-authority public key through reviewed
local configuration, independently of untrusted manifest delivery. Do not copy
a replacement digest from a failed inspection. The original epoch and complete
hash schedule are explicit local configuration, never endpoint-selected trust.
Inspection neither needs nor accepts a private key.

Set all variables deliberately; this guide supplies no production defaults:

```bash
cargo run -p sunrise-edge-operator --bin genesis_inspect -- inspect \
  --chain-id "${SUNRISE_INSPECT_CHAIN_ID:?reviewed chain ID required}" \
  --protocol-version "${SUNRISE_INSPECT_PROTOCOL_VERSION:?reviewed protocol required}" \
  --epoch "${SUNRISE_INSPECT_EPOCH:?reviewed original epoch required}" \
  --suite "${SUNRISE_INSPECT_SUITE:?reviewed full suite entry required}" \
  --expected-genesis-authority "${SUNRISE_INSPECT_AUTHORITY:?independent public authority required}" \
  --expected-manifest-digest "${SUNRISE_INSPECT_DIGEST:?independent digest required}" \
  --genesis-manifest "${SUNRISE_INSPECT_MANIFEST:?local signed manifest path required}" \
  --validation-domain "${SUNRISE_INSPECT_VALIDATION_DOMAIN:?nonzero local domain required}" \
  --validation-checkpoint "${SUNRISE_INSPECT_VALIDATION_CHECKPOINT:?local checkpoint required}" \
  --timeout-seconds "${SUNRISE_INSPECT_TIMEOUT_SECONDS:?positive timeout at most 30 required}"
```

Repeat `--suite` for every reviewed entry, one to 64 entries in the form
`epoch:id:transaction:object:effects:code:config:certificate`. Every numeric
column and top-level number is canonical unsigned decimal, without a plus sign
or leading zeros. Domain/checkpoint/clock affect only discarded installation;
they are neither manifest-authenticated values nor descriptive output fields.

## What to examine

The deterministic key/value lines describe original context, authority,
commitment profile and Freeze height; original committee identities and powers;
separate fee prices and bond-resource settings; and each object's exact owner,
identity, version, schema and canonical bytes. Existing canonical policy and
object-authority frames are included for public-codec comparisons. Object bodies
stay opaque contract state, not privileged chain balances.

Published artifact origin/revision/context/digest and initialization code
reference are labelled separately. The defining original installer checks all
four fields through the same exact published-code reference owner as ordinary
execution ([DR-0198](../architecture/decisions/0198-genesis-publication-reference-alignment.md)).
Inspection does not replace that check with a display comparison or repair a
retained inconsistent root. Separately labelled signed records remain useful
for independent review; their presentation is not a second authority owner.

String values use a byte-defined escape grammar: printable ASCII passes through
except backslash and equals; backslash is doubled; spaces, equals, controls and
non-ASCII UTF-8 bytes become lowercase `\xHH`. Identifiers/entrypoint names
cannot add lines or terminal controls. The text is diagnostic, not a new signed
or stable protocol serialization.

Require exit zero **and** the final line:

```text
complete=true mode=inspect evidence=none
```

Validation refusals write no stdout summary. A stdout I/O failure can leave a
partial stream and remains failure; an earlier line is never completion.
Identical output with different local domain/checkpoint/clock is reproducibility,
not independent economic approval.

The manifest is read once within its defining byte bound, preserving the existing
read-only loader's symlink following. Inspection never creates a DB, claims a
disk writer fence, signs, repairs input, calls Cloudflare/D1 or another provider,
starts a listener, or grants serving/successor authority. Timeout bounds installer
storage operations, not arbitrary filesystem-open latency; keep input delivery
within the operator-controlled local environment.

The separate [authoring guide](standard-asset-genesis.md) produces an explicit
preset; the [SQLite preparation guide](sqlite-validator-startup.md) prepares fresh
independent stores. Serving rechecks its own actual state. A previous inspection
is never cached as an activation warrant.
