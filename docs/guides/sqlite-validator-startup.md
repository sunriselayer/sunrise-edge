# Local SQLite validator preparation and startup

This guide prepares one original-epoch validator's independent local state
and blob databases, checks its public configuration, and starts the existing
loopback-only host. Each validator has its own database pair. PostgreSQL,
Cloudflare credentials and deployed Workers are not involved.

The authority boundaries are defined in
[DR-0195](../architecture/decisions/0195-local-sqlite-validator-startup.md).
Current completion and release gates remain only in [TODO](../../TODO.md).
Local startup does not approve public exposure, a genesis ceremony or custody
of real assets.

## Inputs and custody

Obtain the already signed original genesis manifest and its independently
trusted expected digest. Independently configure the chain, protocol version,
original epoch, complete hash-suite schedule, logical atomicity domain and
validator identity. The domain is local protocol configuration, not a value
authenticated by the manifest or inferred from a database filename.

Preparation accepts the defining genesis installer's supported profile: one
self-contained publication without dependencies, one Instantiate initializer,
and fee/economics resources pinned to that code and instance. It creates an
empty supported blob database; this does not establish generic paid code/body
closure. Use the ordinary paid publication and execution paths for subsequent
contracts. The Standard Asset package gains no special storage or node-core
authority from this preparation command.

Neither preparation nor preflight reads a private validator seed or signs a
transaction. Preflight requires the registered validator public key. Only the
serving host reads its protected signing-key file and derives the public key
again; a previous successful preflight is not serving authority.

## Fresh preparation

Choose two distinct unused paths in existing regular directories. Neither
main file may already exist, even as an empty file. Existing `-wal`, `-shm`
and `-journal` sidecars also refuse. Main/sidecar aliases between the two
normalized destinations, symlink ancestors and parent traversal refuse before
intentional destination creation.

Preparation initializes the ordinary namespace at writer generation 1, then
uses the existing signed-genesis and ordered-genesis installers at that same
generation. The two installers commit separately and the database files are
separate physical resources. This is not one cross-file atomic transaction.
The local clock supplies only the existing ordered pacemaker's liveness timer.

On failure, preserve any reserved or partially populated files for inspection.
There is no implicit resume, reset, overwrite or repair. A fresh attempt uses
new unused destinations; do not treat a partially prepared namespace as ready
to serve. A successful preparation synchronizes the created files and their
parent directories before advertising completion.

## Advisory preflight

Stop competing maintenance while preparing startup. Preflight inspects an
existing Ordinary/Unsealed original namespace without claiming a new writer
generation. It verifies the exact local root, fee policy, committee/live pin,
registered public key and existing ordered state. It refuses inactive imports,
Sealed namespaces and successors; the independently verified successor workflow
is described in [first-successor](first-successor.md).

The command compares two complete durable snapshot tokens around all deciding
reads. A changed namespace, domain, writer generation or mutation sequence
refuses. Successful output is explicitly advisory: another writer can change
the state immediately afterwards. The blob database is opened read-only and
its supported shape is checked, but it has no namespace-binding metadata; this
does not prove ownership of the state/blob pair.

Nonmutation means unchanged logical rows, objects, receipts, blob inventory,
writer generation and mutation sequence. Do not compare SQLite file hashes:
closing a connection can checkpoint WAL files without changing logical state.

## Serving and restart

The serving host keeps its existing flag-only invocation and requires explicit
offline-fence confirmation. Stop all other writers of this namespace first.
Every start claims a strictly newer writer generation once, then independently
rechecks its locally trusted root, fee, committee, protected signing key and
ordered state. It never installs, resets or repairs genesis or ordered state.

Keep the listener on loopback. Query context through the locally configured
transport and compare it with independent expected signing context before
submitting anything. The existing [FastVote network guide](fastvote-network.md)
describes quorum clients, paid Publish/Instantiate/Call, exact saved-artifact
replay and transport policy. Those rules are unchanged by SQLite preparation.

For a restart, stop the process, preserve both database files and all sidecars,
and start the same host with the same public pins and explicit offline-fence
confirmation. The new generation must be strictly greater than the previous
one. Never replace a running or previously prepared database with a fresh
genesis as a recovery shortcut. Subsequent epoch recovery and serving use the
existing verified successor path, not another original-genesis preparation.
