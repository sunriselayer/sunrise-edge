# Ordered network economics

[DR-0153](decisions/0153-ordered-network-economics.md) defines the fixed-epoch
composition. Delivery status and remaining acceptance belong in
[`TODO.md`](../../TODO.md); the executable entrypoint is the
[operator guide](../guides/ordered-economics.md).

## Ordering and authority

Owned paid Publish, Instantiate and Call stay on FastVote. Fee claims, bond
lifecycle, equivocation evidence and evidence-driven slash use the existing
`consensus::ChainedHotStuff`. HTTP arrival order and a client's chosen peer are
not an economic sequencer. No escrow-generation lock selects the first claimant.

Each validator independently pins the signed genesis, chain/protocol/epoch,
domain, registered validator keys and fixed genesis consensus parameters. A
domain-separated anchor binds those values. Each proposal carries zero or one
authenticated candidate; only heights congruent to 1 modulo 3 may carry one.
Two empty certified descendants complete its three-chain window. A single QC
is not a three-chain commit. Remote timestamps are not a clock authority: only
the host's trusted clock may advance the request-driven pacemaker.

The candidate binds the original canonical intent, kind, request ID, context
and creation checkpoint. The checkpoint is an execution operand bound by the
certified candidate commitment, not a published checkpoint/root proof.
Existing intent and signature frames remain
unchanged. Authority derives from the registered validator signature and every
leg's own sender signature, or the exact registered-set equivocation proof.
Unregistered signers and mismatched contexts fail before runtime I/O.

## Durable execution

Before returning a signature, the validator persists the exact leader proposal
or vote identity and candidate. Address-owned economic inputs and consecutive
sender nonce ranges use the same lock keys as FastVote. Shared escrow and
protocol custody do not acquire permanent first-candidate locks. Only the
matching admitted leg can use or release its reservation; no safety timeout
silently frees it.

After the shared engine commits a block, the ordinary economics owner prepares
its effects through a read-only state view. Preparation cannot commit or report
a synthetic success. The shared completion kernel assembles one fenced atomic
invocation containing those effects, the original intent receipt, nonce changes,
consensus/order rows, retained outcome and exact lock cleanup; success requires
the store's actual commit result. Physical revision assertions remain separate
from logical business generations. See [operation preparation](operation-preparation.md).
Generic WASM/ABI custody and value checks are reused; there is no native Coin
decoder or Standard Asset exception.

Healthy stale generation, row digest, nonce or eligibility produces a typed
retained rejection without value movement or nonce advancement. The deciding
rows are revision assertions even for a refusal. Missing/corrupt prerequisites,
fencing, contradictory reads and indeterminate commits stop apply; they do not
become ordinary business rejection or advance an unknown applied prefix.

A fresh request for already-recorded identical evidence commits only its new
outer receipt and order/outcome rows with a CAS assertion on the immutable
evidence. It does not rewrite evidence or wedge the prefix.

## Replay and replica observations

The original `OrderedOutcome` is retained atomically with the business receipt
and cross-checked against it when read. Exact completed candidate reconciliation
precedes fresh module/policy/object/nonce reads and reservation work. Changed
intent, kind or checkpoint under that request ID is a boundary conflict. A
retained header alone is not completion. Corrupt or partial completion is a
stop, not a fabricated answer.

Historical exact proposal/certificate replay is read-only. A missed validator
recovers the declared authenticated prefix through signerless `observe` and
`certificate` requests. Every local prerequisite must already be available or
recover through its own certified path; no opaque snapshot import is allowed.
A validator cannot vote past an unapplied economic prefix or missing certified
ancestor payload. Recovery artifacts do not prove complete state handoff or
membership activation.

The SDK authenticates the whole declared prefix before its first recovery POST,
checks parent links and candidate placement, and bounds rounds and aggregate
bytes. It reports every peer separately, synchronizing artifacts and phase
results before subsequent requests. A failed peer receives no later prefix
steps in that invocation. Returned outcomes must bind to a candidate in the
certified three-chain and agree across acknowledged responses.

Unsigned HTTP outcomes and replica-local completion reads are acknowledgements,
not signatures over business results, whole-store durability proofs or network
absence proofs. TLS endpoint checks remain separate from protocol pinning.
Before driving a fresh window, a matching quorum of local completion hints
directs the SDK to original-artifact recovery. A matching quorum acknowledging
different candidate bytes under the same request ID stops as a boundary conflict
before any Tick or proposal POST. One peer hint alone cannot suppress submission.

## Scope

The opt-in native host shares FastVote's blocking admission budget and exposes
only ordered proposal/vote/certificate, signerless recovery and bounded reads.
It mounts no direct mutation or generic-event fallback. Fixed-epoch ordering
does not change validator membership. Cross-epoch activation, verified complete
handoff, independent economics/ingress audits and initial deployment are separate
gates. Cloudflare DO economics conformance is not implied by native tests.
In particular, a fixed genesis membership does not create the Exited/absent or
elapsed-epoch prerequisites needed for a genuine Deposit or Withdraw positive
flow; those integration cases belong with membership and epoch handoff.
