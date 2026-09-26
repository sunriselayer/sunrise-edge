# Certified-only FastVote HTTP network and CLI quorum client

This guide runs the DR-0148 opt-in FastVote network: one long-running,
certified-only HTTP host per validator (`fastvote_host_pg`, PostgreSQL-backed)
and the ordinary Rust CLI's paid Publish/Instantiate/Call, Standard Asset and
`contract fastvote-replay` actions. DR-0151 extends DR-0148's original
Call-only surface. It is a development implementation. The
independent Phase 3 and ingress security review gates remain open; this guide
does not authorize live exposure, deployment, or custody of real assets, and
`fastvote_host_pg` never terminates TLS itself (loopback listen only --
front it with your own TLS-terminating proxy for anything beyond a single
trusted host).

`fastvote_host_pg` never installs, resets, or migrates genesis and never
advances a live epoch. Bootstrap every validator's PostgreSQL namespace and
install its signed genesis manifest first, exactly as in
[the closed-PostgreSQL FastVote rehearsal](../operations/fastvote-pg-rehearsal.md),
using the same `fastvote_pg namespace-init`/`install-genesis` subcommands.
This guide picks up once every validator's namespace already has that
genesis manifest committed.

## Start one validator's host

Run this once per validator, each against its own PostgreSQL namespace and
its own signing-key file. It claims the namespace's writer fence exactly
once, at startup (`--confirm-offline-fence-advance` is mandatory and is an
explicit acknowledgement that this is the sole intended writer for this
namespace right now) -- stop every other writer against that namespace
first.

```sh
export SUNRISE_EDGE_OPERATOR_POSTGRES_DSN='postgresql://...'   # never argv
cargo run --release -p sunrise-edge-operator --bin fastvote_host_pg -- \
  --tls-root-der /secure/trusted-root.der \
  --chain-id YOUR_CHAIN_ID --validator-id YOUR_VALIDATOR_ID \
  --domain YOUR_DOMAIN_ID --protocol-version YOUR_PROTOCOL_VERSION \
  --epoch 0 --suite 0:1:1:1:1:1:1:1 \
  --genesis-manifest /secure/genesis.manifest \
  --expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --signing-key-file /secure/validator-seed.bin \
  --listen 127.0.0.1:8443 \
  --created-checkpoint 1 --timeout-seconds 20 \
  --max-connections 4 --max-concurrent 4 \
  --confirm-offline-fence-advance
```

`--protocol-version` must be at or above the transaction-auth-profile
activation floor (3): the ordinary CLI paid-call path queries `/v1/context`,
which fails closed below that floor. On success the process prints one
`complete=true mode=serving ... listen=<addr> manifest_digest=<digest>` line
to stdout and then serves `certified_fastvote_router` until `ctrl-C`. Only
`/v1/fastvote/prepare`, `/v1/fastvote/certificates`, liveness, and a handful
of bounded read queries (context, fee policy, instance, code interface) are
mounted -- no generic event-submission route exists on this router at all,
regardless of configuration. `--listen` must be a loopback address; put your
own TLS-terminating reverse proxy in front of it for anything beyond a
single trusted host on the same machine. Each validator's operator holds a
separate PostgreSQL credential and namespace -- this binary never assumes a
shared database role across validators.

## Configure the network for the CLI

`--fastvote-network` takes a small text config, one line per peer:

```
VALIDATOR_ID_HEX ENDPOINT TLS_SERVER_NAME TLS_CA_CERT_DER_FILE
```

Use `-` for both `TLS_SERVER_NAME` and `TLS_CA_CERT_DER_FILE` for a loopback
plaintext peer (matching `fastvote_host_pg`'s own loopback-only listen);
supply both, real values, for a remote peer -- each remote peer gets its own
independently configured hostname and CA, never one global pair reused
across peers, and never a system trust store. A config mixing loopback and
remote-TLS peers in one file is rejected before any peer is dialed. Blank
lines and lines starting with `#` are ignored; at most 32 peers.

For a same-host loopback-only cohort (replace the abbreviated IDs):

```
a1a1...a1 127.0.0.1:8443 - -
a2a2...a2 127.0.0.1:8444 - -
```

For a separate all-TLS cohort behind the operators' TLS proxies:

```
a1a1...a1 203.0.113.1:8443 validator-1.internal /secure/validator-1-ca.der
a2a2...a2 203.0.113.2:8443 validator-2.internal /secure/validator-2-ca.der
```

Endpoints are IP socket addresses; the separate DNS name is the certificate
verification name, not an endpoint resolved by this transport.

## Submit an ordinary paid contract over the network

`--fastvote-network` is accepted on `contract paid-publish`,
`paid-instantiate` and `paid-call`. It builds and signs
the same ordinary paid intent the direct path builds, then routes
final submission through prepare/quorum/apply against every configured peer
instead of one direct POST. Endpoint-to-validator mapping against the local
genesis pin is verified before any fee-policy query or signing.

```sh
cargo run -p sunrise-edge-cli -- contract paid-call \
  --endpoint 127.0.0.1:8443 \
  --expected-chain-id YOUR_CHAIN_ID --expected-protocol-version YOUR_PROTOCOL_VERSION \
  --expected-epoch 0 --expected-hash-suite-id 1 --expected-domain YOUR_DOMAIN_ID \
  --seed-file /secure/sender.seed \
  --fee-source YOUR_FEE_COIN_OBJECT_ID_HEX --fee-access write --max-fee 1000000 \
  --gas-limit 100000 --request-id YOUR_REQUEST_ID_HEX \
  --instance-ref /secure/instance-ref.bin --entrypoint transfer \
  --access /secure/access.bin --args /secure/args.bin --type-args /secure/type-args.bin \
  --fastvote-network /secure/fastvote-network.conf \
  --fastvote-genesis-manifest /secure/genesis.manifest \
  --fastvote-expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --fastvote-deadline-seconds 30 --fastvote-per-request-cap-seconds 10 \
  --fastvote-signed-intent-out /secure/signed-intent.bin \
  --fastvote-certificate-out /secure/certificate.bin \
  --result-out /secure/result.bin
```

`--endpoint` must exactly select an endpoint in the network configuration.
Ordinary preparation reads (context, fee policy, objects, nonce, instance,
publication and interface) reuse that peer's configured transport/TLS policy;
prepare/apply fan out across the configured cohort. Global TLS flags and
`--submission-out` are unsupported in network mode.
`--fastvote-deadline-seconds` starts immediately after flag parsing and
bounds preparation through apply, without renewal between phases.
`--fastvote-per-request-cap-seconds` also bounds each read or peer request.
Both must be positive; the whole budget is at most 3600 seconds, and the
request cap is at most 300 seconds and no greater than the whole budget.
These are resource ceilings, not network latency targets.

`--fastvote-signed-intent-out` and `--fastvote-certificate-out` are mandatory;
`--result-out` is optional. All requested outputs must be distinct, unused
paths in writable existing directories. The CLI reserves them all with
`create_new` before the first prepare POST, retains the original handles,
and strictly synchronizes files and parent directories. The signed intent
is durable before prepare; the certificate is durable before apply. Existing
files are never overwritten. A failure can leave reserved empty or partial
files: preserve them, and recover the exact original bytes rather than
re-signing or reserving a fresh nonce. Unix path-identity checks are tested;
other platforms have not been validated.

### Publish, instantiate, then call

Use the same expected-context, sender/fee, selected endpoint and network flags
from the command above for every step, with a new request ID and unused saved
intent/certificate/result paths each time:

| Action | Application inputs | Derived output |
| --- | --- | --- |
| `contract paid-publish` | `--wasm`, `--abi`, exact comma-separated `--entrypoints`, `--origin-seed`, optional `--dependencies` | `--dependency-ref-out` |
| `contract paid-instantiate` | `--code-ref` from publication, `--instance-seed`, `--args`, `--type-args` | `--instance-ref-out` |
| `contract paid-call` | `--instance-ref`, `--entrypoint`, `--access`, `--args`, `--type-args`, optional `--authorizations` | canonical `--result-out` |

Derived reference outputs are optional but, when requested, must be unused and
distinct from all retained inputs/outputs. They are reserved before mutation
and populated only for a verified successful result. A reserved empty file
after a charged failure is not a usable reference. Preserve exact submitted
bytes and inspect/replay the certified result before preparing the dependent
step. Prepare alone does not publish a definition or install an instance.

The top-level `create-asset`, `transfer`, `split`, `merge`, `mint` and `burn` accept the
same network/genesis/artifact flags. Their ordinary ownership, amount, asset
identity and local expected-context checks still apply; no special validator
authority is created for these commands. An arbitrary Standard Asset requires
its published code and instance, not a new native balance type.

A committed **charged trap** (the application was rejected but a real fee
was still reserved and settled) is reported with the actual fee/nonce and
the CLI exits non-zero -- this is a valid final committed result, not a
network failure or a condition to retry with fresh signing.

## Replay from saved artifacts

`contract fastvote-replay` reads back exactly the saved bytes and resubmits
them unchanged -- it never queries a fresh nonce, never re-signs, and never
invents a new request ID. It accepts the same `--expected-*` and
`--fastvote-*` network/genesis flags as the paid actions, plus:

```sh
cargo run -p sunrise-edge-cli -- contract fastvote-replay \
  --expected-chain-id YOUR_CHAIN_ID --expected-protocol-version YOUR_PROTOCOL_VERSION \
  --expected-epoch 0 --expected-hash-suite-id 1 --expected-domain YOUR_DOMAIN_ID \
  --fastvote-network /secure/fastvote-network.conf \
  --fastvote-genesis-manifest /secure/genesis.manifest \
  --fastvote-expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --fastvote-deadline-seconds 30 --fastvote-per-request-cap-seconds 10 \
  --submission /secure/signed-intent.bin \
  --certificate /secure/certificate.bin \
  --result-out /secure/result-replay.bin
```

An explicitly supplied `--certificate` must exist and contain a complete,
valid canonical certificate; a missing, empty, truncated or corrupt file
fails before any POST. Replay verifies it against the pinned validator set
and the saved intent's digest before apply. If no certificate was formed,
omit `--certificate` and provide `--fastvote-certificate-out` with a new,
unused path: replay collects and saves a certificate from the exact saved
intent, then applies it. `--fastvote-signed-intent-out` is unsupported in
replay, and `--fastvote-certificate-out` is unsupported when supplying
`--certificate`. Optional `--result-out` must also be an unused path distinct
from all inputs and outputs, and saves exact success or charged-trap bytes.
A result-output failure after acknowledgement requires exact replay, not
fresh signing. Either way, the epoch pinned by
`--expected-epoch` must still be the namespace's live epoch for *fresh*
work; replaying an already-applied historical receipt remains usable after
an epoch change, since `fast_path::apply` is receipt-first. A non-current
epoch for fresh work requires an explicit, out-of-band operator re-pin, not
a silent retry.

A quorum certificate (the `--fastvote-certificate-out` bytes) is a
cryptographically formed proof that a quorum of pinned validators voted for
the identical outcome; each per-peer apply acknowledgement printed
afterward is an unsigned, independent receipt from that one peer. Neither
this guide's tooling nor the CLI's own output ever claims global durability,
that every configured peer applied, or finality beyond what the printed,
per-peer results actually show.

For a same-epoch validator that missed prepare as well as application, use
[certified lifecycle catch-up](fastvote-catch-up.md). It reconstructs declared
certified Publish/Instantiate/Call against exact local prerequisites without a new prepare vote
or speculative locks; it is not full-state handoff or epoch activation.

## Executable regression

```sh
# Supply SUNRISE_EDGE_TEST_POSTGRES_URL through a protected environment first.
bash scripts/check-fastvote-pg.sh
```

This also runs `fastvote_host_pg_cli_multivalidator_e2e`: four real
`fastvote_host_pg` processes against four independent PostgreSQL
namespaces, driven through the compiled CLI library entry point, not a
separately executed CLI binary (`contract paid-call
--fastvote-network`, `contract fastvote-replay`), covering a charged trap,
a successful transfer, exact replay of both, a rejected request-id-reuse
conflict with independently re-verified unchanged durable state, a
stale-writer-fence rejection, and a real close/reopen of a validator's host
process with exact replay surviving the restart.
