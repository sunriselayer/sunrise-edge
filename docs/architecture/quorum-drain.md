# Quorum-retained DrainSet and certified member application

[DR-0168](decisions/0168-quorum-retained-drainset-and-member-drain.md) extends
[frozen frontiers](frozen-frontier.md) within the currently serving outgoing
epoch. It is not next-set readiness or activation. Work and release status
belong in [`TODO.md`](../../TODO.md).

## Complete selected union

Verify a unique, canonically ordered, strictly greater-than-two-thirds
weighted outgoing quorum of signed frontier descriptors. Every descriptor
binds the same committed Freeze request and actual block height, chain,
protocol, epoch and atomicity domain. A coordinator cannot change those
bindings or substitute a count/digest for complete pages.

Stage consecutive pages through CAS-protected per-signer progress. Confirm
each member only after retaining and independently verifying its full
certificate, original signed intent, witness and exact actual artifact
closure. The terminal accumulator/count must equal the signed descriptor.
Merge those complete streams incrementally; identical cross-signer identities
deduplicate, whereas a conflicting identity for the same request refuses.
The `0xD03A/v1` accumulator binds the exact selected signer/descriptor roster;
`0xD03B/v1` identifies its deterministic union. Request-ID ordering is only
canonical union enumeration, not causal execution order.

Imports and confirmation do not execute WASM, charge a fee, advance a nonce,
install an original receipt or produce an availability ACK. Original
publication/artifact/ACK addresses remain unchanged. Imported proof material
is separately retained under epoch-scoped `fastpath/drain-publication/` and
`fastpath/drain-publication-artifact/` families. Its local possession marker is
in the ordered-economics `drain-possession/` family.
Protocol writers never replace confirmed material with different bytes.

Each bounded step verifies and fences the proof material it observes. Voting
and commitment fence the immutable final readiness and selected complete
progress, as well as the serving epoch/committee/profile and committed
Freeze. They trust earlier confirmed local CAS transitions and protocol
immutability; they do not atomically reread the entire epoch's artifact bodies.
This uses the same trusted-local-storage boundary as frontier resumption,
not a claim of protection against arbitrary canonically valid DB alteration.
Member apply and proof relay freshly re-verify the selected member's full
closure. Missing, tombstoned, changed or corrupt encountered prerequisites
are refusals, never evidence of absence. Existing per-step artifact and
transaction capacity bounds still apply; there is no new whole-union count cap.

A page holds at most 128 entries; one publication closure holds at most 2,048
artifacts and 32 MiB of encoded bundle data. Member application combines that
member's proof, execution/head/nonce dependencies and selected completion
fences under the existing limits of 4,096 read assertions, 4,096 mutations
and 64 MiB per invocation.
An oversized legal member can therefore produce a typed capacity refusal
without effects or a receipt. These are per-step safety limits, not a measured
edge CPU budget or a claim of load readiness.

## Ordered authority and narrow application

`DrainSetIntent` `0x645E/v1` occupies kind 6 of the existing shared HotStuff
operation chain; existing Freeze remains kind 5. Before exposing a new vote,
the voter must have selection-scoped complete local proof possession. A
normal three-chain commitment atomically installs `DrainSetRecord`
`0x645F/v1` with its ordered outcome. A proposal or local readiness report is
not application authority. Inherited high/locked QCs remain intact.

The committed selection authorizes only verifying full-certificate members
in that still-current frozen epoch. Explicit member application re-derives
the ordinary generic paid operation and certified commitment, including
charged-trap semantics, fee settlement and logical provenance. No Standard
Asset-specific execution path is added. Missing code, instances, input
versions or nonce dependencies stop progress; this API supplies no automatic
causal scheduler or complete-drain assertion.

Only actually conflicting partial object/nonce reservations required by that
member may be resolved. Their exact observed revisions and a local
`0x6450/v1` resolution audit join the effects, original receipt, nonce, fees
and provenance in one atomic commit. Unrelated locks, partial preparation
records, newer heads and original receipts remain unchanged. A partial
request does not acquire a synthetic success or abort receipt. Completed
exact replay returns original output without another execution or charge.

## Sources and resumable transport

A descriptor signer fixes membership but is not the sole proof supplier.
The retained-source route returns independently verified original or imported
full material without signing, mutation or ACK manufacture. Artifact sources
are separate untrusted configured locators; the receiver authenticates every
bundle under its own pinned outgoing authority and exact expected identity.
Thus another honest DrainSet proof holder can relay an obligation after the
original sole holder fails.

Native frames `0xE109` through `0xE10F/v1` cover retained source, signer-page
staging, member confirmation, union advance, signer progress and member apply.
Mutations expose only confirmed CAS progress. The SDK checks complete page
linkage, context, signatures and bundle closure independently. A bounded
confirmation refusal may trigger a source/import step; ambiguous outcomes
in signer staging/import/confirmation require durable progress reconciliation,
not blind duplicate mutation. An ambiguous union-advance response stops the
driver; there is no separate union-progress read API. A fresh run may submit
the same selection to the idempotent core step, which reads and fences its
own persisted union progress before advancing.

The CLI separates signed genesis/protocol/domain/Freeze pins from per-peer
TLS identities. It supports bounded local readiness, an offline DrainSet
candidate builder using the existing ordered submission/recovery commands,
and explicit member apply/replay. Saved union/result bytes are immutable and
retries require equality. A fresh member result is staged privately and synced
before atomic no-replacement publication; failed attempts leave no final
authority and crash-orphan siblings are ignored. This CLI persistence requires
filesystem hard links and directory synchronization.
A staged page or complete signer resumes without
contacting that original signer; an unstaged page still requires authenticated
descriptor material from that signer. Artifact-source substitution alone
cannot reconstruct an unavailable page or authorize omitted membership.

See the [operator guide](../guides/quorum-drain.md). This capability does not
provide authenticated cut/import, conditional next-set readiness, Seal,
activation, deployment or production-readiness authority. Fresh Logical
activation stays unsupported, and frozen admission has no local unfreeze.
