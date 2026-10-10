# DR-0224: bounded caller-owned local observation collection

Date: 2026-10-10
Status: Accepted bounded design; source implementation and execution are separate gates.

## Context

[DR-0223](0223-local-native-observation-export.md) supplies an opt-in producer.
At design selection there was no operator executable receiving its fixed live
records, so an operator had to supply a separate trusted Unix datagram collector.
The missing receiver is a useful local operations seam under M5, not permission
to invent production alert thresholds, SLOs, custody or public monitoring.

## Decision

Add a foreground Linux-only `native_observations` operator binary. Its required
arguments are `--socket ABSOLUTE_PATH`, `--max-samples N` and `--timeout-ms MS`.
All arguments must be consumed exactly once and validated before filesystem IO.
Accept 1 through 1,024 samples and 1 through 300,000 milliseconds; reject signs,
nondecimal values and overflow. The socket path is NUL-free, at most 100 UTF-8
bytes and consists only of an absolute root plus normal components. Dot,
parent, repeated-separator and trailing-separator spellings are refused.
Other platforms refuse before socket or filesystem work.

The caller supplies an existing private parent directory. Capture the root and
each directory component with retained directory descriptors, opening children
relative to their held parent with no-follow/directory/close-on-exec flags.
Require the final parent to be owned by the process effective UID and have
exactly mode 0700. Obtain effective UID from a bounded Linux process-self status
read, not environment variables or a new unsafe call. Refuse symlinks and
unexplained held-versus-named directory identity changes before and after bind.
Use the retained final directory descriptor's `/proc/self/fd` path to bind one
flat socket leaf; keep the entire descriptor chain until collection ends.
The Linux procfs and same-UID caller are trusted local environment boundaries.
Directory attachment checks do not promise exclusion of a malicious same-UID
renamer. No cgroup, namespace, process-wide umask or host setting is changed.

Never unlink, overwrite, adopt or reconnect an existing socket. In particular,
do not add check-then-unlink cleanup: it cannot atomically distinguish a same-UID
replacement. Even the receiver's own closed socket leaf is retained on success
and failure. The caller inspects and removes it separately after the foreground
process has ended, then chooses a fresh path for another collection. Closing
descriptors is resource release, not pathname deletion or a stale-leaf repair.
An error after successful bind may leave that unqualified socket residue.

Collect into at most 1,024 typed snapshots, using one fixed 2,048-byte receive
buffer. A receive length equal to the buffer capacity is refused, including a
larger truncated datagram. Empty, malformed or unsupported records fail closed;
no invalid bytes or peer address are copied into errors or output. A shared
native-http decoder owns the exact DR-0223 live grammar: fixed prefix, schema 1,
kind live, the existing 15 named fields in their existing order, canonical
unsigned decimal u64 values and exactly one terminal LF. Refuse missing/extra/
duplicate/reordered fields, whitespace variants, embedded LF/CR/NUL, leading
zeros, non-ASCII digits, signs and overflow. The existing live and termination
serializations remain byte-identical. A decoded local observation is not an
authenticated peer message, atomic protocol snapshot, receipt or serving token.

One checked monotonic deadline starts before directory/procfs capture and bind.
Before each receive, bound its nonzero read timeout by the remaining duration.
Recheck the deadline after every return, including success. Charge every receive
attempt, including timeout and interruption, against a finite 4,096-attempt
ceiling; no unbounded retry or busy spin. Exact requested sample count before
expiry is success. Timeout, attempt exhaustion, invalid record or IO failure is
failure even after a valid prefix. There is no detached task, background daemon,
signal to a node, stop-handler installation or host listener change.

Only after successful complete collection and receiver/descriptor closure,
write the canonical live records to stdout. Failure during collection leaves
stdout empty and emits one fixed-category stderr error, without socket paths,
raw datagrams, peer identities or OS error text. A stdout write failure may
leave a canonical prefix and returns failure; do not call that a complete
collection export. Receiver deadlines and finite work bounds are not global
wall-clock guarantees against kernel stalls, scheduling or a blocked stdout
sink. The caller owns output redirection and any external process watchdog.

The producer is unchanged. Start the foreground collector first using a fresh
path, start the opted-in host against that path, and request samples only after
the host's ordinary readiness. DR-0223's cooldown/drop/coalescing behavior means
sample delivery is not guaranteed; the receiver may expire. Different hosts or
same-UID senders are not authenticated or attributed by this command, so use one
collector per explicitly selected local host. No termination records are accepted
by this live-only receiver.

## Source ownership and verification

Keep the grammar/typed decode errors in native-http beside the snapshot encoder;
the operator owns bounded argument parsing, Linux directory/socket lifetime,
collection and output. Add no dependency or protocol counter. Preserve existing
host startup, stop priority, work drain and termination output.

For later Native release qualification, add this actual operator binary after
`successor_host` and before `sunrise-edge-cli` in DR-0213's SAME closed A/B
owner. Retain all twelve existing targets, adding `native_observations` as the
thirteenth; do not replace a target, select arbitrary `--bins`, create a new
build lane or reuse old twelve-target output. Independently assert the full
thirteen-target list in the existing cheap fixture owner. All resource, byte
comparison, source/cache/tool and release rules remain unchanged. This source
amendment is not runtime admission or a target-directory/cache change.

Source controls must independently cover zero/maximal and distinct counter
vectors, all malformed grammar categories, exact receive-size refusal, invalid
arguments before IO, sample/deadline/attempt limits, actual private-directory
local datagram collection, existing regular/symlink/socket preservation,
retained own-leaf behavior and refused directory attachment changes. Pure
receive-loop tests may use private clock/receive seams, not public test-only
hooks or a weakened production deadline. Real socket controls remain separate
from pure parser/loop controls and must close their own descriptors.

Different design and exact implemented-delta source inspection precede adoption.
Compilation, formatting, focused/owning/full tests, final-head hosted CI and
the existing independent release gates remain required. Source declarations do
not complete M5, prove observed delivery or qualify production operations.

## Compiled-host source control, 2026-10-10

Extend the existing nonignored direct-TLS SQLite process fixture, not a new CI
lane or test selector. Only its selected host's first boot opts in on Linux;
later boot/rotation and other-host behavior remain default-off. A fresh private
collector uses one setup-through-collection deadline. Request one SIGUSR1 sample
after ordinary host readiness and TLS traffic, without consuming or stopping
the host. Require successful ordinary collector reap, both actual pipe EOFs,
empty stderr and a complete strict live record with positive admission/dispatch
counters. Recheck host liveness and exact authenticated context bytes before
continuing all original paid-state/replay/fencing/rotation/stop assertions.

The test-only owner bounds each captured pipe before append, joins both readers
on success and failure, and preserves read/poll/kill/reap/cleanup failures instead
of accepting an empty fallback. Signal delivery has no retry. Fixture cleanup
removes only its unchanged owned directory/socket after confirmed child release;
changed or unresolved residue is retained. These local trusted-environment source
controls do not establish atomic attribution or globally bounded kernel/output
behavior. Different exact-delta source approval remains separate from formatting,
compilation, execution and all existing release gates.
