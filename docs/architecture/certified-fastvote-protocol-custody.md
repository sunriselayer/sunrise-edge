# Certified FastVote protocol custody

[DR-0268](decisions/0268-certified-fastvote-protocol-custody-worker.md) selects a
separate Linux deployment profile around the existing certified Native factory.
The selected worker owns the original local source/body databases, mandatory
independent anchor/lease, current writer fence, validator key and actual core
operations. The frontend owns public genesis pins and bounded HTTP/TLS ingress.
It has no database or validator-key interface.

The profile preserves all 21 entries in the existing certified route contract
and liveness, including publication retention and unsigned drain operations.
Three existing automatic signature families remain inside the owner: FastVote,
availability ACK and original frozen-frontier votes. Existing original ordered
IPC version 2, its modes and ordinary combined host composition are unchanged.
The private profile is not a protocol encoding or a generic signature service.

Configuration, ownership, finite lifetime, mutual peer UID checks and shutdown
use the existing local process owner. A separate explicit trusted local
`created-checkpoint` is required for this profile's worker. Core authentication,
committee/context, execution, exact saved replay, confirmed retention and
uncertain-commit decisions stay with their existing owners. Frontend output
verification is stateless and does not replace those decisions.

Implementation and exact validation status remain in TODO. This profile does
not imply all-M2 completion or authorize any stopped work.

## Fixed deployment modes

Use `sqlite_source_host certified-worker --config <private-file>` and
`sqlite_source_host certified-frontend --config <private-file>`. Each uses the
same role-owned 0600 UTF-8 key/value file below a 0700 directory as the original
ordered profile. Its original role-closed fields, explicit public manifest /
genesis digest, exact worker/frontend peer UID, private socket, source/body/key
and mandatory enrolled-anchor permissions remain unchanged. Only the new worker
also requires `created-checkpoint=<u64>`; zero must be explicit. The old ordered
configuration still refuses this key. The new frontend refuses it along with
all key/database/authority fields. No request selects the profile or paths.

Budgets retain the existing limits: 1..4096 requests/connections, total lifetime
1..3600 seconds, operation timeout 1..30 seconds and concurrency 1..256. Startup
uses one real context query before HTTP readiness and consumes one request at
both ends. Compare its public context to local pins; it is no cached live-state
warrant. The frontend's liveness handler is the existing local 204 operation,
which performs no worker or storage check and consumes no IPC request.

## Private framing and HTTP parity

Private inputs and outputs begin with `SCFV` followed by `00 00 00 01`. Ordered
IPC version 2 remains a different format and refuses these bytes. The new
closed request code table follows the existing 21-entry certified route
contract, plus liveness; no arbitrary method, URI or signing frame is carried.
Dynamic selectors are fixed 32-byte values, decoded with the original Axum
`Path<String>` / tuple extractors and original cheap selector rules. Media and
encoding fields retain each occurrence in order, with at most 64 values of
256 bytes per name. Original per-route input/output caps are unchanged; the
complete publication cap is 32 MiB. Outer framing reserves 37,888 bytes over
that canonical frame cap for bounded headers, selectors and identity.

The frontend uses original Axum routes/methods, automatic HEAD and method
refusals, exact path decode errors, ignored query strings and ignored GET bodies.
It applies each original body extractor cap, then the shared original content
and body-error owners before IPC; drain import retains selector checking between
media and body-error reporting. Frontier advance retains its empty-body error.
Responses carry the actual complete bounded status/header/body result, retaining
empty 204 media behavior and original no-store/error headers. A lost connection
never means a committed operation rolled back; there is no automatic retry.

## Returned signatures and unsigned results

FastVote output independently verifies the exact authenticated paid-intent
digest and configured validator with the existing `FastPathCertifier`.
Publication retention verifies the stateless complete bundle and intent binding,
then its exact availability identity, endpoint and ACK signature with the existing
`AvailabilityCertifier`. Stateful witness closure remains the core retainer's
condition, not a frontend assertion. Original frontier votes use the existing
`FrozenFrontierCertifier`; signer-progress binds its selected signer rather than
assuming every retained vote is this endpoint's own signature.

A frontier page or staged progress page is decoded and bound to its selector,
limit and signed vote. The stateless frontend does not authenticate a complete
page chain or recompute its final accumulator root. Core retains its actual
progress checks; the caller's existing `FrozenFrontierPageVerifier` must verify
consecutive pages and a terminal root before treating the log as complete.
Neither this transport nor a returned signature alone proves full retention.

Apply results retain canonical request, transaction, status and application-target
binding, including charged application failure. Receipt replay adds no frontend
current-epoch test. Drain member apply carries only a request ID, so its unsigned
result is bound to that ID and decoded status; it is not an independent transaction
or durability proof. Complete query/source/progress results use their existing
bounded codecs and selectors. Unsigned queries receive structural selector/context
checks over the authenticated local peer; this is not an inclusion proof,
independent freshness proof or independent execution of effects/fees. Live state, quorum, locks, fee state, execution,
confirmed commit, uncertain-commit refusal and exact saved replay stay inside the
existing real router/core. Original ordered modes and DR-0215 controls remain.

## Selected stopped same-identity key recovery

[DR-0274](decisions/0274-certified-stopped-key-recovery.md) extends the selected
disposable multi-UID fixture. Before its fence3 restart, all four original
workers must drain, exit0, reach physical stdout/stderr EOF and be waited; their
PIDs and sockets must be absent. Only a capability-free worker-UID helper then
copies each original32-byte seed to a private backup and a different restored
path, compares the bytes internally and removes the original key path. The
controller receives completion and metadata, never seed bytes. The operator UID
must receive EACCES when opening every restored seed and backup.

New worker-owned0600 certified and original ordered configuration files replace
only `signing-key-file`. Their public validator identities, genesis pins and
exact retained source/body/independent-anchor paths remain unchanged. Every
later certified or ordered generation selects and verifies those restored
paths. The original A vote/ACK equality, fresh paid B, original ordered Freeze,
new frozen-frontier signatures and fence6 retained replay retain their actual
core/SDK assertions. The existing read-only oracle compares unchanged complete
source/body/anchor images across downtime and key recovery.

This is same-identity recovery of known disposable fixture keys in the trusted
local OS profile. It introduces no production recovery command, key or membership
rotation, new identity, database/anchor restore, off-host backup or independent
device. Owning runtime qualification remains distinct from source implementation
and the final repository gates.
