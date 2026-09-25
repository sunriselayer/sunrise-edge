# DR-0144: Closed PostgreSQL FastVote operator rehearsal

## Status

Accepted, 2026-09-26. Implementation and validation status belong in
`TODO.md`. This decision does not authorize a public validator ingress or a
network launch.

## Context

DR-0134 keeps FastVote preparation and certificate application inside a
local-operator invocation. DR-0143 selects PostgreSQL for each validator's
first-network durable state and proves a certified fee-escrow write path and
offline inventory, but no operator can yet run independent validators through
the full prepare, quorum and apply sequence. An in-process fixture with a
PostgreSQL primary and memory-backed peers is not a multi-validator deployment.

## Decision

Add one closed, operator-invoked CLI workflow for the initial genesis epoch.
Every validator uses a distinct `(chain_id, validator_id, atomicity_domain)`
PostgreSQL namespace and its own independently controlled database authority.
The same canonical `GenesisManifest`, signed by **one genesis authority** over
the complete validator set, economics policy and objects, is installed and
restart-verified in each namespace. Validator signing keys are separate from
the genesis authority and from each other. Each validator must have the
committed positive bond required by genesis admission; a voting-power value is
not inferred from its bond amount.

The operator explicitly bootstraps a namespace, installs an externally
supplied signed manifest, prepares one sender-signed paid intent using that
validator's own local Ed25519 key, collects canonical `FastVote` files,
forms a deterministic `FastCertificate` only with the committed genesis
validator set, and applies that certificate independently in each namespace.
File transfer is untrusted delivery: duplicate, reordered, forged, foreign-
context and insufficient-quorum votes cannot authorize application. The
existing `node-core::fast_path::prepare`/`apply`, certifier, canonical codecs,
WASM execution and durable receipt reconciliation remain the only protocol
authorities. No new protocol type, hash domain, signed bytes or consensus rule
is introduced.

The PostgreSQL DSN is supplied through a protected local environment, not
the command line. A single TCP host and certificate-validating TLS connection
are mandatory. The operator independently configures its expected chain,
protocol version, genesis epoch, complete hash-suite schedule, atomicity
domain and genesis manifest digest; neither database rows nor client input
may silently supply those expectations. Before signing a vote, the CLI
compares the exact locally derived Ed25519 public key with its configured
validator identity and the committed current validator set. It reads the key
from a local, owner-only file; neither the key nor the DSN is printed.

Each mutating CLI command is an independent invocation. After checking the
existing schema, namespace and trusted inputs, it explicitly claims a new
writer generation and uses that generation for the complete operation. The
operator must stop competing writers before a fence advance; a fence is not a
distributed stop-the-world protocol. Exact replay returns the existing
verified output without re-execution. A stale generation, reused request ID
with different bytes, differing genesis, altered vote or inadequate quorum
fails closed. A failure after fence advancement still requires the operator
to restart its stopped writer under a newer generation.

The first CLI profile is intentionally genesis-epoch-only. An activated epoch
or missing current policy must not fall back to genesis data. Validator-set
change and historical hash-suite handling remain implemented in core, but a
later operator workflow must expose them explicitly before live use.

## Evidence and limits

The executable regression must use separate PostgreSQL namespaces for at
least a three-of-four real Ed25519 quorum, one signed manifest with four
bonded validators, independent prepare and apply processes, identical
committed receipt/object results, close/reopen replay and writer-fence
negatives. A shared disposable PostgreSQL service is acceptable for a local
regression but does **not** prove validator administrative independence;
deployment must use separately controlled database credentials and storage.

This workflow adds no `NodeEventKind`, public HTTP route, relay, watcher or
background process. It is a closed local rehearsal, not externally reachable
multi-validator testnet, capacity evidence, the Phase 3 review gate, or
production/mainnet readiness. Opening network ingress requires its own
family-specific authentication, authorization, bounded transport contract,
adversarial tests and security review.
