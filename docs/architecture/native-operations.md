# Native stop and operational observations

This host contract extends the existing [Native connection owner](decisions/0219-native-direct-tls-connection-ownership.md).
It changes neither protocol transitions nor persistent state. Rationale is in
[DR-0222](decisions/0222-native-stop-and-operational-observations.md); work and
qualification status belong only in [TODO](../../TODO.md).

## Stop ownership

Original SQLite serving, activated-successor serving and signerless successor
history use one operator-owned stop boundary. On Unix, install SIGINT and
SIGTERM listeners inside the owned Tokio runtime before listener binding and
the startup status line. Installation failure refuses startup. A closed signal
stream stops the host with an error, not a successful operation result. A signal
buffered after installation must not be lost because serving has not started;
check buffered stop before printing readiness, not only in the later serve loop.
Non-Unix behavior is explicit and does not claim Unix signal support.

The stop sequence is:

1. Close admission on the exact blocking executor supplied to the router.
2. Stop accepting and drop the listener; cancel unfinished upgrades through the
   existing watch and gracefully join the existing connection tasks.
3. Wait for every admitted blocking job, including queued jobs and jobs whose
   HTTP future has disappeared, to actually complete or unwind.
4. Emit one operational summary and return. A successful return claims this
   local drain only, not successful execution of every request.

Acquire/register and close share one short lifecycle synchronization boundary.
A private RAII permit tracks admitted work independently of observation
counters and remains inside each existing blocking closure. Register a drain
waiter before checking for zero outstanding work. Request cancellation, panic
and pre-spawn refusal must not leak tracking. Closing is permanent for that
executor. Live reopening constructs a new host and advances the existing writer
fence. Signerless history reopening claims or advances no live writer fence.

No started database operation is aborted, declared rolled back, or turned into
a Rejected receipt because the host or client is stopping. A lost response
remains unknown until the exact saved intent and receipt reconcile it. Keep all
current header/body/handshake/output/operation budgets and error precedence.
There is no globally bounded shutdown promise for synchronous storage work.
An external forced kill is not an orderly-stop success oracle. A late startup
failure after fence advancement grants no repair, rollback or fence reuse.

## Observation ownership

One optional observed-serving seam consumes fixed atomic counters at the
existing connection, upgrade, bounded collector and I/O owner branches. Existing
serve APIs remain compatible wrappers. The operator uses the observed seam for
both plaintext and direct TLS; there is no second server, telemetry worker,
database, request queue or protocol dependency.

Counters saturate instead of wrapping. They cover connection admission and
refusal, coarse upgrade failure/timeout, bounded request dispatch/refusal,
coarse input/output timeout and connection/task failure. A per-connection latch
prevents repeated I/O polling from counting one timeout repeatedly. A typed
error/category is required for specific attribution; never classify raw error
strings. Router dispatch is not application acceptance or durable commit.

An observer can read an in-memory snapshot. Each host emits exactly one
fixed-schema stderr summary after serving and blocking drain, at most 2 KiB.
Its fields are fixed labels, a closed stop reason and numeric counts. Never
record keys, certificates, request/header/body bytes, arbitrary URLs, peer
addresses, request or object IDs, raw errors or caller-selected labels. No
per-request output means hostile traffic cannot flood these logs. Observation
values grant no readiness, signing or storage authority and are not canonical
or persisted; they reset on process restart.

This is not a public metrics endpoint, live alert policy, globally bounded
stderr I/O, an SLO or a capacity/abuse qualification. Those remain separate
deployment choices; no network telemetry destination is introduced.

## Opt-in live local observations

[DR-0223](decisions/0223-local-native-observation-export.md) adds a separate
local source contract for `--local-observations-socket ABSOLUTE_PATH` on the
SQLite source host and both successor serving modes. It is disabled by default.
The caller must already own an operational Unix datagram collector and its
trusted directory. The pathname must be absolute, NUL-free and at most 100
bytes; invalid/duplicate/unsupported options refuse before I/O. An unbound,
nonblocking sender connects before TLS/archive/key/store/fence access. The host
creates no socket file, collector or directory and never repairs, removes or
reconnects the destination.

Opt-in SIGUSR1 registration occurs at the existing stop installation point,
before listener bind/readiness, not at the beginning of startup. Wait for the
existing readiness output before requesting a snapshot. Registration failures
may follow a fence claim, without rollback. Tokio's process-wide signal handler
is not restored on receiver drop; only a fresh disabled process is guaranteed
not to install this handler.

After readiness, SIGUSR1 requests one fixed `native_operations schema=1
kind=live` record with the existing 15 counters and one LF. A monotonic
one-second cooldown is charged even when the nonblocking send fails; observation
polling waits during that cooldown while SIGINT/SIGTERM remain prioritized.
Samples may coalesce, throttle or be dropped; no retry, stdout/stderr write or
detached sampler follows. A closed observation stream disables its branch.
The termination record and actual close/drain/error owner remain separate and
unchanged. Counter loads are not atomic, application-success or readiness
evidence. This is no public endpoint, delivery guarantee, alert/SLO policy or
global timing/capacity qualification. Source controls and runtime acceptance
remain distinct.

## Bounded foreground collection

[DR-0224](decisions/0224-bounded-local-observation-collector.md) defines the
Linux-only operator receiver `native_observations`. It requires each of
`--socket ABSOLUTE_PATH`, `--max-samples N` and `--timeout-ms MS` exactly once.
Use an existing effective-UID-owned mode-0700 parent and a fresh absolute socket
path. The command validates arguments before I/O, retains a no-follow directory
descriptor chain, and binds through the held parent's process-self FD path.
Both the supplied path and that FD-relative address have separate 100-byte
bounds. Trusted Linux procfs and the same-UID caller remain environmental
assumptions; attachment checks do not exclude every malicious same-UID rename.

The receiver accepts 1 through 1,024 samples and 1 through 300,000 milliseconds.
One checked monotonic deadline covers setup and collection, with checks around
directory/procfs/bind work and every receive. A fixed 2,048-byte receive buffer
refuses a length at capacity, including truncated larger datagrams. Every
attempt, including interruption, is charged to a 4,096-attempt ceiling. The
shared native-http decoder accepts only the exact schema-1 live record with
15 ordered canonical u64 counters and one LF, not termination records or
arbitrary text. It changes neither existing encoder nor producer behavior.

Start this foreground collector before the opted-in host, then request samples
only after the host's ordinary readiness. The collector itself sends no signal,
starts no host, creates no directory and grants no readiness or node-control
authority. Producer coalescing, cooldown and dropped sends can make collection
expire. Use one collector per explicitly chosen local host; this command does
not authenticate or attribute same-UID senders.

Only exact-count collection completed before expiry, with the retained socket
and parent chain still attached, reaches stdout. Socket and directory descriptors
close first. Collection failure leaves stdout empty and reports a fixed category,
without paths, peer data, received bytes or raw OS errors. Output write/flush
failure may leave a canonical prefix but returns failure, not a complete export.
Deadline checks cannot interrupt a stalled syscall or blocked output sink; the
caller owns an external watchdog when needed.

There is no unlink or stale-path repair, including for the collector's own closed
socket. Success or a later failure retains that leaf; it is not qualified evidence
of delivery. After the foreground process ends, the caller separately inspects
and removes only its owned residue, then uses a fresh path. Do not restart by
adopting or removing an existing regular file, symlink or socket automatically.

## Acceptance

- Prove acquire/close races, pre-spawn permit release, multiple drain waiters,
  unwinding and a disconnected started job that keeps drain pending until its
  actual completion. Closed admission retains established refusal precedence.
- Exercise already-signaled stop, pending upgrades and normal serving with the
  unchanged transport budgets. Test counter saturation, one-time timeout
  attribution, the exact fixed summary schema and absence of untrusted input.
- Reuse the compiled original-host/direct-TLS SQLite fixture. Keep SIGINT
  coverage and add actual owned-child SIGTERM with successful ordinary reap,
  same-endpoint restart, exact receipts/nonce/objects/blobs, saved-intent replay
  and genuine stale-writer fencing. Forced teardown is failure cleanup only.
- In that existing nonignored fixture on Linux, opt in only the selected host's
  first boot against a fresh private foreground collector. After ordinary TLS
  traffic/readiness, request one SIGUSR1 sample without stopping the host. Require
  ordinary collector success/reap, complete bounded stdout and actual pipe EOF,
  empty stderr, strict full-record decoding and positive admission/dispatch
  counters. Check that the host remains alive and its authenticated context bytes
  are unchanged; retain every later transaction/replay/rotation/stop assertion.
  Use one setup-through-collection deadline and preserve cleanup failures. This
  source control is not an executed delivery pass or authenticated attribution.
- Keep activated-successor/history consumers under the same owner, preserve
  their existing authority/refusal fixtures, and add no duplicated recurrence
  runner, heavy CI lane, selected-PG claim or skipped required gate.
  The existing Linux successor TLS fixture now uses that private collector after
  its actual context/status, imported-receipt and CLI traffic and complete
  protected-state check. After one non-stopping sample, repeat authenticated
  context/status byte comparisons and the complete state oracle before the
  original certificate-refusal/restoration and successful-stop controls.
  Signerless history opts in only on restart zero, repeats the full actual
  material oracle after collection, and keeps the retired signing key absent
  through both restarts; restart one stays default-off. Both existing ignored
  fixtures keep their selectors and unconditional owning CI lanes. One original
  300,000 ms collector deadline covers setup, signal and strict full capture;
  a 600-second host bound grants no additional collection eligibility. Source
  inspection is separate from formatting, compilation and observed delivery.

Only disposable local SQLite and loopback traffic are authorized here. This
contract is not cloud deployment, production custody, power-loss safety,
public-network readiness or permission to launch.
