# Security Policy

Sunrise Edge is experimental, unaudited software. It is not production-ready
and must not be used to custody real assets.

## Reporting a Vulnerability

Report suspected vulnerabilities through
[GitHub Private Vulnerability Reporting](https://github.com/sunriselayer/sunrise-edge/security/advisories/new).
Do not disclose exploitable details in a public issue, discussion, pull
request, or social channel.

Include the affected commit, component, realistic attacker prerequisites,
impact, and a minimal reproduction when safe. Do not include private keys,
access tokens, production data, or unnecessary exploit payloads.

## System and Scope

Sunrise Edge is a serverless-native blockchain state-machine implementation.
The repository contains protocol crates, deterministic execution, runtime
contracts, SQLite and PostgreSQL persistence implementations, native and
serverless ingress adapters, a Rust client, and CLI/devnet applications.

The first independent code-security audit is intentionally narrower than the
whole repository. Its exact paths and exclusions are recorded in
`docs/security/initial-code-audit-scope.md`. Vulnerabilities in excluded or
deferred code may still be reported; an audit exclusion is not a suppression
or accepted-risk decision.

The implemented native external mutation surface accepts only authenticated
`SubmitTransaction` events. Other known event families must remain rejected
before identity allocation, clock access, storage I/O, state-machine
transition, outbox work, or transport delivery.

A separate, opt-in, operator-composed native surface
([DR-0148](docs/architecture/decisions/0148-certified-fastvote-network.md))
serves only the two FastVote prepare/certificate routes plus bounded reads; it
never mounts `SubmitTransaction` or any other mutating route, regardless of
configuration, and does not weaken or replace the `SubmitTransaction`
invariants above. It is a development implementation, not independently
security-audited, and is not authorized for live exposure or custody of real
assets.

The separate [DR-0149 offline fee-claim operator](docs/architecture/decisions/0149-offline-signed-fee-claims.md)
targets one explicitly stopped PostgreSQL namespace under independently pinned
configuration and a fresh writer fence. It adds no HTTP mutation. Preparation
must derive exact signed outputs through the defining public contract without
committing business state; apply independently authenticates and atomically
fences the claim. Historical claimant identity is distinct from the store's
validator identity. Local escrow-generation CAS is not cross-validator claim
ordering: concurrent online application through this tool is outside its
authority model. Exact retained claim artifacts, not new nonces/signatures,
are the authority for ambiguous-commit replay.
Restarting under a new writer generation after a local claim does not certify
replica convergence or authorize live cohort re-entry; settlement/state
handoff and catch-up remain independent requirements.

Devnet query routes are unauthenticated public reads. They expose context,
objects, receipts, and sender next-nonce values and must not be treated as an
authorization mechanism.

## Threat Model and Trust Boundaries

Assume an unauthenticated network caller can send malformed or canonical
bounded requests, repeat or reorder them, choose public lookup selectors, and
consume available admission capacity.

Assume a valid sender can choose every signed transaction field, including its
request ID, nonce, access manifest, module reference, entrypoint, arguments,
gas limit, and fee declaration. A valid signature authorizes only that exact
canonical transaction and must not grant authority over undeclared or
unauthorized state.

Relays, schedulers, transports, and cloud providers are untrusted for protocol
safety. They may drop, duplicate, delay, reorder, replay, or mutate messages.

Operator-supplied protocol configuration, active hash suite, atomicity-domain
placement, preinstalled module catalog, writer fence, persistence namespace,
fee treasury, trusted clock, checkpoint, and deployment credentials are
trusted composition inputs. Untrusted requests must not select or replace
them.

Do not assume that an attacker already controls an operator account, private
signing key, database administrator, trusted protocol configuration, or
release infrastructure. Findings requiring those privileges must state the
additional capability gained.

Local development seed files are not production keystores. Optional hardware
signing support has not completed physical-device validation or release
certification.

## Security Invariants

- Canonical bytes, type and field identifiers, enum tags, hash domains, and
  stable vectors must remain deterministic and versioned.
- A state-changing signed ingress, including `SubmitTransaction` and public
  paid execution, must authenticate its canonical frame, trusted chain ID and
  protocol version, signature scheme, sender binding, and signed epoch before
  runtime identity, clock, or storage work. `SubmitTransaction` additionally
  authenticates its profile and outer/inner signed-epoch consistency at this
  stage. Because the durable current epoch is itself stored state, that
  already-authenticated signed epoch must then equal the committed current
  epoch before replay reconciliation, application planning, transition, or
  mutation.
- Request replay and request-ID reuse must reconcile against persisted receipt
  and event-digest state before nonce, object, module, or application work.
- Sender nonce, application state, object versions, receipt, and outbox effects
  must commit atomically or not at all.
- Object access and execution effects must remain within the signed manifest.
  Owner, type, and schema changes must fail closed unless an exact committed
  policy explicitly permits them.
- `ProtocolCustody` ownership has no sender signature authority. Only a signed
  same-chain genesis manifest may introduce it until a later decision defines
  an exact protocol-authorized operation; ordinary execution reads, writes,
  consumes, owner transitions, fee use, contract creation, and FastVote locks
  fail closed. Public object queries remain read-only and return canonical state.
- Preinstalled WASM code and semantics must be resolved from trusted committed
  configuration, not uploaded or substituted by a transaction.
- Fee debits and treasury credits must use ordinary asset-account state and
  remain atomic with the application result or the defined rejected-result
  fee path.
- Writer fencing, deadlines, namespaces, and logical atomicity domains must be
  enforced by persistence implementations and must not come from request
  authority.
- Blob content must match its self-describing digest. Conflicting content must
  never overwrite an existing digest.
- TLS endpoint authentication and locally configured expected-protocol-context
  verification are separate mandatory controls before remote signing.
- Attacker-controlled collections, frames, bodies, modules, gas, outputs,
  deadlines, retries, leases, and concurrent work must remain explicitly
  bounded.
- Unknown algorithms, versions, event kinds, modules, encodings, and policies
  must fail closed without downgrade or fallback.
- The opt-in FastVote HTTP surface's prepare/apply routes must authenticate
  the caller's exact signed bytes against its own declared chain/protocol/
  epoch before identity allocation, clock access, or storage I/O; only after
  that does `fast_path::apply` reconcile a request already covered by a
  committed receipt for exact historical replay ahead of a current-epoch
  check, so a request whose epoch has since advanced can still replay its own
  already-applied outcome without silently re-executing or accepting a fresh,
  stale-epoch mutation. This does not change `SubmitTransaction`'s own
  authenticate-then-reconcile ordering above.
- FastVote mutation paths must fence a non-current epoch, a validator absent
  from the one committed active validator set, and a conflicting object or
  sender/epoch nonce lock before any lock, execution, or mutation. Validator
  membership must never be locally, unilaterally mutable by a single node;
  it changes only through a certified state transition every node observes
  identically. The general mutation fence is implemented by
  [DR-0131](docs/architecture/decisions/0131-fastvote-validator-lifecycle.md)
  slice 1, and the outgoing-set-certified `e -> e + 1` transition is
  implemented by
  [DR-0132](docs/architecture/decisions/0132-fastvote-epoch-transition.md)
  slice 2. Retired-validator and wrong-epoch rejection are therefore
  end-to-end observable across an activated transition. Local, durable,
  historical-validator-set-verified equivocation evidence is implemented by
  [DR-0133](docs/architecture/decisions/0133-fastvote-equivocation-evidence.md)
  without external ingress or punishment.
  [DR-0134](docs/architecture/decisions/0134-fastvote-authorization-boundary.md)
  declares the two-axis authorization boundary: every Phase 2 operation is
  local-operator-invoked, its signing or mutating branch requires the exact
  current/outgoing/historical validator proof, and external ingress remains
  closed. Its companion code and reviews landed in PR #180, closing Phase 2.
  Phase 3 economics remain open; DR-0135 defines the non-signable custody
  prerequisite and DR-0136 derives typed, positive genesis bond commitments
  through authenticated generic ABI metadata. Neither grants custody release
  or asset-mutation authority.

## Reportable Findings and Severity Context

A finding is reportable when a realistic attacker can violate an invariant,
gain authority they did not already possess, disclose protected secrets, cause
unauthorized state or asset movement, bypass replay protection, corrupt durable
history, or create material unbounded resource consumption.

- **Critical:** practical private-key compromise, unauthenticated arbitrary
  asset/state mutation, or protocol-wide integrity loss.
- **High:** authentication or authorization bypass, replay causing a second
  mutation or fee, exploitable atomicity failure, arbitrary module execution,
  or cross-chain signing under realistic deployment assumptions.
- **Medium:** bounded but meaningful integrity, availability, or information
  exposure requiring additional prerequisites.
- **Low:** limited hardening issue with concrete impact and realistic
  reachability.

Severity must account for actual exposure, prerequisites, existing effective
controls, and the new capability gained. A hypothesis, missing production
deployment, or behavior already available to the attacker is not by itself a
confirmed vulnerability.

## Initial-Audit Exclusions

The following are deferred from the first audit engagement:

- externally reachable FastVote/FastCertificate ingress, validator lifecycle
  completion, and economics/security completion (the local Phase 1
  certified-execution boundary and atomic certificate publication are
  implemented under
  [DR-0130](docs/architecture/decisions/0130-owned-object-certified-execution.md);
  Phase 2's architecture is fixed; slice 1's general mutation-fencing layer
  is implemented under
  [DR-0131](docs/architecture/decisions/0131-fastvote-validator-lifecycle.md),
  and slice 2's outgoing-set-certified epoch transition is implemented under
  [DR-0132](docs/architecture/decisions/0132-fastvote-epoch-transition.md),
  still with no externally reachable ingress. Phase 2 slice 3's local
  equivocation-evidence types, historical verification, durable recording,
  and point query are implemented under
  [DR-0133](docs/architecture/decisions/0133-fastvote-equivocation-evidence.md).
  Slice 4's authorization and closed-ingress boundary is implemented under
  [DR-0134](docs/architecture/decisions/0134-fastvote-authorization-boundary.md),
  and its companion code and reviews landed in PR #180, closing Phase 2.
  Phase 3 slashing/reward distribution remains incomplete; DR-0135 accepts
  its non-signable protocol-custody prerequisite and DR-0136 adds read-only,
  typed genesis bond commitments without a Standard Asset exception — see
  `TODO.md`'s FastVote Certified Execution Gate. Function-first network
  delivery, ahead of Phase 3 economics/security closure, adds a genuine but
  still opt-in, operator-composed HTTP ingress and CLI quorum client under
  [DR-0148](docs/architecture/decisions/0148-certified-fastvote-network.md):
  a certified-only router, a PostgreSQL-backed hosting binary, and CLI
  network submission/replay. This is a development implementation on its own
  separate design/security review gate per DR-0147, not an independent
  security audit, and does not authorize live exposure, deployment, or
  custody of real assets);
- externally accepted non-`SubmitTransaction` event families;
- production multi-validator consensus activation;
- checkpoint/state-root publication and verified restore;
- provider-specific production deployment and operations;
- PITR, backup, off-host restore, HA, failover orchestration, and PKI lifecycle;
- long-running load, soak, capacity, and additional physical-fault campaigns;
- TypeScript client, explorer, and wallet applications;
- remaining Ledger physical-device, HIL, reproducible-build, and release work.

New protocol-critical or externally exposed surfaces require a focused delta
audit before production activation.

## Known Limitations and Compensating Controls

- The concrete devnet is loopback-only, single-validator, and unsuitable for
  real assets.
- SQLite is a local developer persistence implementation, not a production
  backend.
- PostgreSQL implements the durable contract as a library, but this repository
  does not prove a deployed topology, credential lifecycle, backup, HA, or
  operator runbook.
- Blob publication occurs before the structured state commit. A later commit
  rejection may leave an unreachable content-addressed blob; this is not a
  partial state commit. Garbage collection remains deferred.
- Remote TLS authenticates the endpoint only. The client separately checks the
  locally expected protocol context; full canonical `ProtocolConfig` byte
  pinning remains deferred.
- Serverless adapters relay to a separately deployed trusted node capability.
  Deployment authorization, secret rotation, WAF/rate policy, and private
  connectivity are not established merely by adapter source code.
- Repository-owned Rust code forbids `unsafe` except for the existing raw WASM
  host-ABI boundary in `contract-sdk`, which must remain behind checked safe
  wrappers.

## Audit Revision and Verification

An audit target is identified by one complete 40-character Git commit SHA,
never by a mutable branch name. The initial engagement uses the final,
validated pull-request head commit; later changes require explicit delta
review.

Run the complete repository gate from that exact commit:

```bash
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
git diff --check
git status --short
git rev-parse HEAD
```

`git status --short` must be empty. The recorded audit handoff must bind the
exact commit SHA to the successful local gate and required GitHub checks.
