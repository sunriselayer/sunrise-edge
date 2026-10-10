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
- Keep activated-successor/history consumers under the same owner, preserve
  their existing authority/refusal fixtures, and add no duplicated recurrence
  runner, heavy CI lane, selected-PG claim or skipped required gate.

Only disposable local SQLite and loopback traffic are authorized here. This
contract is not cloud deployment, production custody, power-loss safety,
public-network readiness or permission to launch.
