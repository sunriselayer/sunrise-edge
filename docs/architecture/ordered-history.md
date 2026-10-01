# Authenticated ordered-history export

[DR-0169](decisions/0169-authenticated-ordered-history-export.md) specifies
the history capability needed before [epoch handoff](epoch-handoff.md)'s
business-state reconstruction. Implementation and validation status belong in
[`TODO.md`](../../TODO.md).

## Authority boundary

Start from locally verified signed-v3 genesis and its outgoing committee,
context and shared-consensus anchor. Each archived committed height carries
its own complete three-chain proof, captured before the live engine prunes it.
Archive and consensus/application progress join one atomic commit. Empty
heights and controls remain in the history; request IDs and source height
counters do not establish order.

Verify consecutive heights and exact parent digests through a fixed target.
For each candidate-bearing height, verify the original candidate's bytes,
signatures and digest. Recommitment points back to its original committed
height; it is not a second execution or fee charge.

Full outcomes and original receipts are retained source companions. Their
canonical bytes, identities and origin links must agree, including deterministic
refusals. A QC authenticates the ordered candidate, **not** its supplied
execution result. Companion agreement does not establish correct business
effects, a state root, generation floor or cut completeness. Those require
the later causal reconstruction verifier.

## Transfer and restart

Select a fixed target, then retrieve closed component descriptors and bounded
chunks. Check exact digest/length and re-verify assembled signatures and linkage.
Do not concatenate unbounded full history or all components into one response.
Saved CLI files are synchronized and immutable. Restart re-verifies saved
material before continuing; completion requires the whole genesis-to-target
stream, not just a terminal proof or downloaded page.

Export never executes applications, creates a signature or changes the source
business/safety rows. It does not install imported state. No result grants
conditional readiness, Seal, new membership, fresh serving or activation.
An old valid target is not proof of network freshness; an empty target's
descendants are not proof that the whole DrainSet has completed.

The [portable snapshot](portable-reconstruction.md) contract remains a separate
local continuity tool for future whole-state enumeration. Proof-of-order
verification is not a substitute for that enumeration's closed projections or
for independent application reconstruction.

## Closed component and resource contract

The outer history identity binds protocol context, logical atomicity domain,
signed genesis digest, shared-consensus anchor and the exact target
height/view/digest. Canonical v1 frames allocate `0x6490` for that identity,
`0x6491` for a component reference, `0x6492` for a height descriptor and
`0x6493` for a summary. The new self-contained consensus commit proof uses
`0xD017/v1`; existing proposals, QCs, candidates and original receipts keep
their own bytes. These are not a new signature domain or a state-root scheme.

Each height has at most six closed component kinds:

1. Its own committed-block proof.
2. Exact candidate bytes, if the block carries a candidate.
3. The retained request header for that candidate.
4. Its full original retained outcome.
5. The original receipt's canonical dedup bytes.
6. Its original committed-block proof when a completed candidate recommits.

Descriptors bind each component's type, byte length and digest under the
committed protocol hash suite and existing NodeEvent purpose. They are at
most 16 KiB; chunks are at most 1 MiB. Components retain their existing legal
canonical bounds, rather than being concatenated into an oversized frame.
Digest agreement authenticates transfer consistency only; the assembled
commit/candidate signatures and all origin links are verified separately.
Only a complete contiguous stream produces the private verified-ordering
result. No component descriptor or persisted cursor grants serving authority.

The streaming verifier retains compact first-seen request/candidate,
original-height and completion-companion fingerprints. A later recommit must
match them, even if a source supplies mutually consistent replacement
companions. This metadata grows with distinct original requests; full
historical components are assembled one height at a time, not held together
as one in-memory history. The [CLI guide](../guides/ordered-history.md)
describes immutable saved export and process-restart continuation.

## Native read transport

The existing ordered-policy opt-in mounts three read-only routes. Summary is
an empty-body GET; descriptor and chunk requests are bounded canonical POSTs,
not consensus events or application invocations.

| Route suffix under `/v1/ordered-economics/history` | Request | Success |
| --- | --- | --- |
| `/summary` | Empty GET | Raw `0x6493/v1` summary |
| `/height` | `0xE110/v1`: fixed identity and height | Raw `0x6492/v1` descriptor |
| `/component` | `0xE111/v1`: identity, height, descriptor digest, kind, offset and limit | `0xE112/v1`: offset, total length and chunk bytes |

Canonical POSTs use the existing node-event media type; successes use the
existing node-result media type with `no-store`. Invalid framing, context,
height, kind or chunk limit refuses before runtime/storage I/O. Actual reads
use the host's trusted current writer-fenced operation context and existing
bounded-work admission; callers never supply a writer generation or clock.
The SDK checks offset and total length against the independently pinned
descriptor, then verifies full component digests and core signatures/linkage.
