# DR-0223: Opt-in local Native observation export

Date: 2026-10-10, UTC

Status: Accepted local source contract. Implementation and execution acceptance
are separate; this decision closes no M5, custody or public-release gate.

## Context

[DR-0222](0222-native-stop-and-operational-observations.md) supplies fixed local
counters and one post-drain termination record. A live stderr write could block
the stop owner; stdout already carries startup output. Neither is a suitable
live observation channel. A new public endpoint or periodic background service
is unnecessary for an explicitly requested local snapshot.

## Decision

The SQLite source host, successor `serve` and signerless `serve-history` accept
one optional `--local-observations-socket ABSOLUTE_PATH`. Default behavior stays
unchanged. Validate all arguments before I/O: the new Unix pathname must be
absolute, contain no NUL and fit 100 bytes. Duplicate options and explicit
opt-in on an unsupported platform refuse.

After argument validation and before TLS, archive, key, store or writer-fence
access, prepare an **unbound** Unix datagram socket, set it nonblocking, then
connect to the existing caller-selected collector. Failure refuses this opt-in
startup. Create no collector, socket file or directory; never unlink, repair or
automatically reconnect the destination. Selecting and operating its trusted
directory and collector remain the caller's responsibility, not peer-identity
authentication or protected-key custody supplied by this feature.

Carry the prepared sender into the existing runtime and stop-owner installation
point before listener bind/readiness. Do not move SIGINT/SIGTERM installation or
the runtime. Opt-in installs SIGUSR1 only there; requests are valid only after
readiness. Signal installation can fail after an existing writer-fence claim,
which is not rolled back. Tokio signal disposition remains process-wide after
receiver drop; no restoration of the prior/default SIGUSR1 handler is promised.

The existing stop future prioritizes buffered stop and ready SIGINT/SIGTERM over
observation notifications. SIGUSR1 never closes work admission or completes
shutdown. Charge a monotonic one-second cooldown before each attempt, including
failed sends. Gate observation polling during cooldown so queued/coalesced
notifications cannot cause a busy loop; stop polling remains active. Disable a
closed observation stream permanently.

Each admitted notification reads the original fixed 15 saturating counters and
attempts one nonblocking datagram below 2 KiB. Its closed record starts
`native_operations schema=1 kind=live` and ends in one LF. The counter fields are
the same fields as DR-0222; the existing termination record bytes remain
unchanged. No paths, credentials, request bytes, peer identities or dynamic
labels enter either record. Throttled/coalesced notifications and send failures
may lose samples. Do not retry, log per-sample errors, spawn detached work, write
live stdout/stderr or reinterpret collector failure as protocol/stop failure.

## Acceptance and limits

Owning controls must cover option refusal/default-off behavior, all three real
callers, exact live/unchanged termination schemas, maximum-size counters,
cooldown after successful and failed attempts, collector disappearance/full
queues, closed notification streams and stop priority under notification load.
Preserve actual admitted-work drain and termination/error precedence. Synthetic
controls are not compiled-host signal or transport execution evidence.

Counters are independently loaded local observations, not an atomic snapshot,
readiness, committed application output or durable delivery. Nonblocking socket
mode avoids output-queue waiting; it is not a syscall-duration or global shutdown
guarantee. This is local IPC, not an IP listener, metrics server, network
telemetry deployment, alert policy, SLO, capacity qualification or launch
permission. No dependency, canonical/wire protocol or signer authority changes.
