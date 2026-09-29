# DR-0158: Resume bounded network drain from verified local progress

## Status

Accepted design direction, 2026-09-29. Implementation evidence and remaining
work belong in [TODO.md](../../../TODO.md). This composes the post-Freeze
possession and local union boundaries in
[DR-0156](0156-frozen-frontier-possession.md) and
[DR-0157](0157-frozen-frontier-readiness.md); it does not decide DrainSet,
Seal, a cut, or activation.

## Context

The certified-only transport now accepts a signed frontier page, a complete
publication bundle for its current staged member, one member confirmation,
and one union-advance step. These steps are individually CAS-fenced. A network
driver cannot safely infer after a timeout whether a step committed. Starting
again at page zero also fails after a later page has replaced the earlier
staged page. A process-local cursor, HTTP 204, or a caller-supplied ready flag
cannot repair this ambiguity.

## Decision

The driver uses a locally authenticated genesis/outgoing-set pin and an exact
configured validator-to-endpoint mapping. TLS authenticates each remote
endpoint independently of this protocol-context pin. The caller explicitly
selects ascending, distinct outgoing signers; the client checks their
signatures, one committed Freeze context, and quorum power before sending a
union step. A server's response cannot select a signer, committee or Freeze.
The target independently rechecks the same installed authority and its
committed Freeze in every mutating CAS.

A bounded read-only signer-progress response exposes the target's current
durable vote, confirmed accumulator identity/cursor/count, exact staged page
and complete bit for one signer. The response repeats the chain, epoch and
signer, and the driver rejects any mismatch with its local pin or the
source's signed vote. It is a scheduling hint, not authority: the target's
CAS transition remains the authoritative consecutive-page verifier. The
driver fetches from the confirmed cursor, compares an existing staged page
with the configured source, and never treats a response's cursor alone as
proof of a complete frontier.
After any ambiguous stage/import/confirm response, it reads progress and
continues from the actual durable state. A staged partial page resumes at its
next unconfirmed entry; a completed page resumes from its confirmed cursor.
The driver never skips a missing page or member, and an inconsistent,
tombstoned or foreign progress row stops rather than resetting state.

Each remote page is checked by the target's CAS against the signed terminal
count/digest and previous confirmed accumulator; a driver that independently
re-verifies from a midpoint must use the authenticated running accumulator
from the progress response, never an untrusted cursor alone. For each entry
the driver obtains a full publication bundle
from an authenticated configured source or a verified relay, independently
checks its certificate, signed intent and artifacts against the page identity,
imports it on the target, and confirms that exact request ID. The import may
rebuild only a pristinely missing local possession marker from the complete
verified proof under CAS. A tombstone is never treated as an empty marker.
The confirm's request-ID guard is checked in the core CAS read set.

Once all selected signers are complete, the driver repeatedly advances the
selection-specific union. Its 204 response means only progress. The
canonical ready identity is accepted only after the target's final CAS and
the client checks its chain/protocol/epoch/domain/Freeze/selection shape.
The future ordered DrainSet voter reads the matching ready row under the
same CAS as its own immutable vote identity. Neither this driver nor the
ready response signs or publishes a DrainSet vote.

One operator-visible monotonic deadline and a per-request cap bound network
work. A configured step budget may stop a long run without treating its
partial local progress as failure of safety; a later invocation resumes.
No fixed whole-chain entry cap is introduced. Permanent malformed proof,
tombstone or profile mismatch is distinguishable from retryable CAS/storage
failure. The driver retries only after reading durable progress, not by
blindly repeating an indeterminate mutation. The certified-only routes stay
behind trusted validator/operator ingress until peer authentication or
equivalent cumulative work budgets exist.

## Consequences

The local progress response may disclose frontier identities and is bounded
by the existing page size. It does not disclose signing keys, create an ACK,
extend the frozen publication log, execute an application, or alter fees,
nonces or receipts. A client-side process crash cannot by itself lose the
target's confirmed progress. Serving an outgoing epoch after target activation
still requires a separately authenticated historical-serving design; the
initial driver completes before activation.
