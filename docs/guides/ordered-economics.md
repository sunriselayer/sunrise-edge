# Ordered economics operator workflow

This is an opt-in, fixed-epoch rehearsal. It is not deployment authorization,
membership activation, or permission to manage real custody. See
[architecture](../architecture/ordered-economics.md) and
[`TODO.md`](../../TODO.md) for the separate acceptance/release gates.

## Host and independent pins

Use the same independently trusted genesis file, expected digest and explicit
chain/protocol/epoch/domain as the [certified FastVote host](fastvote-network.md).
Each validator keeps its own namespace, registered signing key and fixed writer
generation. Add `--enable-ordered-economics` to `fastvote_host_pg`. Host startup
validates existing genesis and ordered state; it never resets corrupt state or
installs an untrusted genesis. Stop a namespace's existing writer before the
explicitly confirmed startup fence advance. Never run the fence-advancing
offline economics operator against a namespace while its HTTP host is serving.

The Rust protocol is request/event-driven. The native listener is an adapter,
not a persistent consensus scheduler. A client drives an expired view with an
empty Tick; only the host clock can authorize its actual view progression.

`peers.conf` uses the FastVote format:

```text
validator_id endpoint tls_server_name tls_ca_der_file [private_bearer_token_file]
```

Loopback plaintext uses `- -` for the two TLS fields. Remote endpoints require
pinned TLS; never mix remote TLS and loopback plaintext in one cohort. Transport
credentials do not replace the local genesis/protocol pin. Keep token files
private and distinct; do not put tokens in argv, reports or manifests.

## Exact candidate submission

Input is an existing canonical, signed fee-claim or bond-lifecycle intent, an
evidence-driven slash intent with its authenticated sender leg, or the canonical
`OrderedEvidenceSubmission` wrapper containing one of the three real proof
families. `candidate-wrap` does not create signatures, infer a kind, fetch a
snapshot, or turn offline mutation into safe online preparation. Signed intent
construction must use verified prerequisites; SDK preparation reads require
caller-controlled quiescence rather than an assumed multi-read snapshot.

With these local variables set to independently verified values:

```sh
cargo run -p sunrise-edge-cli -- economics candidate-wrap \
  --intent operation.intent --kind fee-claim \
  --request-id "$request_id" --created-checkpoint "$checkpoint" \
  --ordered-genesis-manifest genesis.bin \
  --ordered-expected-genesis-digest "$genesis_digest" \
  --expected-chain-id "$chain" --expected-protocol-version "$protocol" \
  --expected-epoch "$epoch" --domain "$domain" --out operation.candidate

cargo run -p sunrise-edge-cli -- economics network-submit \
  --candidate operation.candidate --ordered-network peers.conf \
  --ordered-genesis-manifest genesis.bin \
  --ordered-expected-genesis-digest "$genesis_digest" \
  --expected-chain-id "$chain" --expected-protocol-version "$protocol" \
  --expected-epoch "$epoch" --domain "$domain" \
  --deadline-seconds 90 --per-request-cap-seconds 10 --out operation
```

Other closed kinds are `bond-lifecycle`, `bond-slash` and `evidence`. The SDK
authenticates the candidate before network I/O, routes only to the deterministically
selected leader, verifies each vote and forms each QC locally. It drives the
candidate window plus two empty descendants. A typed retained rejection is also
a completed ordered outcome: inspect the retained response rather than equating
successful workflow execution with acceptance of the economic operation.

Outputs are new files only: exact candidate, proposal and certificate artifacts,
an append-only certified-pair manifest, and per-peer phase results. All outputs
are reserved before mutation. Proposal bytes are synchronized before vote POSTs;
QC bytes and their manifest pair are synchronized before certificate POSTs.
Paths in the manifest are canonical absolute paths without whitespace/control
characters. Keep the whole artifact set even if the command later fails.

`committed_acknowledged=true` means an unsigned replica outcome bound to the
locally authenticated certified prefix was received. It does not prove every
replica applied, authenticate a result signature or certify whole-store durability.
Results distinguish acknowledgement, rejection, unreachability and skipped steps.

## Construct a DrainSet candidate offline

`economics drain-set-build` ([DR-0159](../architecture/decisions/0159-ordered-drainset.md))
is the offline analogue of `candidate-wrap` for the one control kind
`candidate-wrap` cannot handle: `DrainSet` carries no outer signature, so its
candidate is assembled, never wrapped, from a locally supplied signed
frontier-vote selection plus a saved
[`fastvote-drain-local-ready`](fastvote-drain-local-ready.md) union-identity
report. It never signs a vote, never trusts network-reported context, and
never submits anything.

```sh
cargo run -p sunrise-edge-cli -- economics drain-set-build \
  --drain-selection-manifest /secure/drain/selected-votes.txt \
  --drain-union-identity /secure/drain/union-identity.bin \
  --request-id "$request_id" --created-checkpoint "$checkpoint" \
  --ordered-genesis-manifest genesis.bin \
  --ordered-expected-genesis-digest "$genesis_digest" \
  --expected-chain-id "$chain" --expected-protocol-version "$protocol" \
  --expected-epoch "$epoch" --domain "$domain" \
  --out drain-set.candidate

cargo run -p sunrise-edge-cli -- economics network-submit \
  --candidate drain-set.candidate --ordered-network peers.conf \
  --ordered-genesis-manifest genesis.bin \
  --ordered-expected-genesis-digest "$genesis_digest" \
  --expected-chain-id "$chain" --expected-protocol-version "$protocol" \
  --expected-epoch "$epoch" --domain "$domain" \
  --deadline-seconds 90 --per-request-cap-seconds 10 --out drain-set
```

`--drain-selection-manifest` uses the exact same manifest grammar as
`fastvote-drain-local-ready`: UTF-8, one already-signed
`FrozenFrontierVote` file path per line. `--drain-union-identity` should be the
exact canonical `DrainUnionIdentity` bytes saved by
`fastvote-drain-local-ready --out-drain-union-identity` for that selection,
not its human-readable output. The builder cannot prove the provenance of an
arbitrary local file or another validator's readiness; every ordered voter
rechecks its own durable ready marker before signing. The supplied identity's chain/protocol/
epoch/domain are cross-checked against the independently pinned
`--expected-*`/`--domain` flags; a mismatch fails closed as a report/context
mismatch before any vote is even considered.

`--request-id` is nonzero and `--created-checkpoint` is explicit; together they
identify this ordered candidate's replay attempt. Neither is inferred from the report or
the selection. The command reuses the exact same `authenticate_ordered_candidate`
pure verification a validator applies before proposing/voting: canonical
round-trip, structural intent checks, and full outgoing-quorum signature and
power verification. Duplicate, non-ascending, foreign, or mixed-Freeze votes,
insufficient quorum power, an invalid signature, a malformed vote or report
file, or an `--out` path that already exists all fail closed before any
output is written.

## Declared signerless recovery

If submission was interrupted, do not invent a new request ID or nonce. A
completed-request response directs you back to the original saved manifest.
`--resume-proposal` reuses an exact retained round-0 proposal when it has not yet
completed; it does not discover missing history or replace later prefix recovery.
Recover the saved prefix, concatenating contiguous original manifest lines when
several complete windows are needed:

```sh
cargo run -p sunrise-edge-cli -- economics network-replay \
  --manifest operation.manifest --ordered-network recovery-peers.conf \
  --ordered-genesis-manifest genesis.bin \
  --ordered-expected-genesis-digest "$genesis_digest" \
  --expected-chain-id "$chain" --expected-protocol-version "$protocol" \
  --expected-epoch "$epoch" --domain "$domain" \
  --deadline-seconds 90 --per-request-cap-seconds 10 --out recovery
```

Replay verifies the entire bounded prefix before any POST, sends proposal bytes
to `observe` (never the voting route), then each original certificate. Per-phase
results are synchronized incrementally. A failed peer receives no later steps;
other replicas retain their own acknowledged prefix. Fix/recover its missing
prerequisites and replay the exact artifacts again. An empty prefix, forged or
reordered proof and an expired request budget are not success.

`GET /v1/ordered-economics/outcome/<64-hex-request-id>` reads only that replica's
original outcome. A 204 means locally not completed, not network-wide absence.
The SDK `query_replica_outcome` checks the expected candidate's identity and
digest; use the original certified prefix to reconcile finality separately.
