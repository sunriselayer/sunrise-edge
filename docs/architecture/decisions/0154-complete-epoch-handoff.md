# DR-0154: Complete epoch handoff without weakening retained history

## Status

Accepted implementation direction, 2026-09-27. This record fixes the design for
[DR-0151](0151-integrated-network-delivery-and-lightweight-stores.md)'s
integrated membership/epoch delivery after independent design review and
correction of the availability/drain/readiness gaps. The mechanism is specified
in [Complete epoch handoff](../epoch-handoff.md). At acceptance, this was a
design-only decision and did not activate a new runtime rule. Independent
implementation slices on 2026-09-28 allocate the availability wire family and
implement the handoff-capable logical commitment profile and a canonical
publication bundle with one replica's durable `retain_publication` step,
described below. The apply-admission gate, HTTP/CLI ingress and
Freeze/DrainSet/Seal remain unimplemented. The complete design requires a
publication-before-apply rule, not a new quorum-applied finality rule.
Implementation and validation status belong in [`TODO.md`](../../../TODO.md).

The independent logical-generation admission extraction on 2026-09-30
deliberately refuses Logical-profile epoch proposal/vote and fresh activation
with `EpochTransitionLogicalProfileUnsupported`. The existing transition
writer cannot install next-epoch policies with the required provenance in
this slice. Exact already-committed transition identity is reconciled before
the fresh-activation gate; Historical transitions remain supported. Full
Logical handoff and activation remain a later, independently verified
implementation, not authority conferred by these local admission guards.

## Context and reusable boundaries

The existing [epoch transition](0132-fastvote-epoch-transition.md) derives
the next validator set and policy writes, authenticates the outgoing-set
certificate, and installs the transition atomically. Genesis restart
verification checks the historical certificate chain. These are useful
primitives, not proof that a joining validator has every required code,
object or settlement fact.

`epoch_transition::propose_and_vote` currently casts a vote without a
durable one-outgoing-epoch vote identity. Exposing that in-process signer
directly as an HTTP operation would permit contradictory requests to produce
contradictory signatures. The immutable identity discipline in
`ordered_economics::identity` is the relevant reusable pattern.

The actual certified FastVote host pins execution to its configured epoch;
the ordered environment pins its epoch/set and retains chain-keyed consensus
state. Merely advancing the live epoch row does not make a restarted host
or its shared consensus engine usable under the next set. Separate the
immutable genesis trust anchor from the independently verified serving epoch.

The economics policy key is context-bound, but the fee/bond handlers resolve
that authority at the defining code's pinned context. Do not blindly copy or
rewrite it at every live epoch. Current execution/fee/publication policies,
old code provenance and current validator authority are distinct concerns.

Source boundaries:

- [epoch transition](../../../crates/node-core/src/epoch_transition.rs)
- [mutation fencing](../../../crates/node-core/src/mutation_fence.rs)
- [genesis history verification](../../../crates/node-core/src/genesis.rs)
- [owned certified apply/recovery](../../../crates/node-core/src/fast_path.rs)
- [ordered execution](../../../crates/node-core/src/ordered_economics/engine.rs)
- [certified HTTP](../../../crates/native-http/src/fastvote.rs)
- [PostgreSQL host composition](../../../apps/operator/src/bin/fastvote_host_pg.rs)

## Required design properties

### Decision and necessary semantic change

The existing prepare/apply contract cannot guarantee a non-lossy handoff while
replacing an absent replica. For A/B/C/D with Byzantine C, both partial votes
A+C for X and B+C for conflicting Y are possible. The surviving A/B/C cannot
tell whether absent D completed and applied X or Y. Byzantine C need not obey
our storage locks. Unique full-certificate safety does not solve this
surviving-observation ambiguity, and partial votes do not reconstruct the
missing certificate or original signed intent.

The selected direction adds one execution-free quorum publication round before
any owned application. Retain the full verifying certificate, original signed
intent and required replay artifacts before exposing an ACK. Then every
possible application intersects an outgoing frozen quorum in an honest holder
of its **full** artifacts. That holder need not know whether its ACK was
aggregated into an availability certificate. Drain every verifying full
certificate in the selected closed frontier, never merely partial prepares.

This is an explicit apply-admission/latency change, not a new rule that
discards minority applications, not an existing implemented guarantee and not
global ordering of owned calls. Use a fresh handoff-capable genesis/profile;
no unsafe bare-certificate fallback or automatic destructive legacy migration.

Use the existing HotStuff chain for Freeze/DrainSet/Seal control, with immutable
frontiers only after new retention ACKs close. Transition votes follow the
committed Seal, avoiding an epoch-wide first-writer-wins proposal wedge.
Preserve inherited consensus locks and resolve business-bearing suffixes
before sealing. Complete full-certificate operations through narrow cut-bound
reservation resolution, not arbitrary foreign-lock release or global receipts
invented from uncertified pending claims. Before a DrainSet vote, its complete
artifacts must be durably retained by that voter, not only the earlier holder.
Select a legally eligible ready next set before Seal; conditional readiness is
repeatable, while the post-Seal transition target is unique. In the initial
profile, committed
Freeze has no cancellation: resume the ordered protocol to activation; neither
elapsed time nor absence of an activation row reopens admission.

The decision also separates signed logical read observations from physical
CAS revisions. Current commitment v1 signs some state/head/nonce revisions;
normalizing only the transfer root would not solve portable re-execution.
Use deterministic authenticated semantic execution generations rather than
physical creation/admission checkpoints, including economics minimum-generation
checks. Historical witness bytes remain verifiable; new admission must not silently
reuse the physical-revision commitment under a different claimed guarantee.

### Sui research and applicability

The historical [Lutris v5 paper](https://arxiv.org/html/2310.18042v5),
sections 2.3 and 4, distinguishes transaction certification, signed effects
and checkpoint inclusion; its outgoing quorum closes only after sequencing
obligations. Its rollback of nonfinal, non-checkpointed execution is **not**
adopted here. These are historical design lessons, not proof of our current
implementation or permission to redefine retained application finality.

The [official Sui source inspected at commit d79a998](https://github.com/MystenLabs/sui/blob/d79a998f32bfedac63e7d3f1dbdc9e41c14adf38/crates/sui-core/src/epoch/reconfiguration.rs)
explicitly describes certificate names as legacy after fast-path removal.
Do not present the 2024 Lutris description as the current Sui implementation.
The Sunrise design deliberately keeps owned transactions outside global
ordering and chooses publication-before-apply rather than adopting rollback.

### Completeness comes from authenticated derivation

An individually valid caller-declared replay list proves only those supplied
operations. A digest or count of that list does not prove nothing was omitted.
An outgoing validator must derive the committed cut from its own verified
store; the outgoing authority must authenticate the exact cut identity. A
joining or recovering validator must independently reconstruct/verify the
required facts before eligibility, signing or activation is possible.

Define the portable collections explicitly: required code/ABI/publication,
instances and authority, immutable object history/heads/deletions, original
receipts/dedup/nonces, fee escrows/claims/settlements, bonds/custody/evidence,
and transition/consensus prerequisites. Establish how both ordinary state
keys and structured repositories are enumerated; a compatibility key scanner
alone must not be assumed to cover every structured collection.

Exclude local checkpoint markers, local revisions/writer generations and
delivery cursors from replica-equivalence material. Alternative valid QC
signer subsets bind the same certified payload identity. Never transplant a
writer fence or trust an opaque SQL dump. Local prepare/vote/lock metadata is
not a global state root, but its safety obligations cannot be forgotten merely
because its bytes are excluded.

Every page, collection and resumed step must bind to the same authenticated
cut. Concurrent old-epoch mutation, omissions, additions, duplicates,
reordering, divergent prerequisites, missing history, tombstones, fencing and
ambiguous outcomes must have explicit fail-closed behavior. Use the existing
centralized framing/hashing/signature abstractions; no ad hoc cryptography.

### Do not infer a new finality or loss policy

The investigation proposed quorum-attested replay equivalence and suggested
discarding an operation applied only by a minority of replicas. **That loss
policy is not accepted.** The warning that an unsigned HTTP acknowledgement
is not a durability/finality signature does not itself authorize a new rule
that deletes authenticated applied effects, receipts or settlements.

First establish the actual existing certificate/commit guarantees. Distinguish
an abandoned prepare, an unknown certificate, a certificate-backed operation
awaiting apply, and already retained authenticated application/history. The
cut must reconcile the relevant facts without silently dropping them,
manufacturing an abort, applying fees twice, or arbitrarily unlocking another
request.
Unresolved authenticated disagreement is a reason to refuse activation and
recover, not to silently select a lossy history.

Existing `apply_with_recovery` treats a verified FastVote certificate as
portable authorization to apply the exact intent at its own committed epoch;
application then atomically retains the local effects/receipt/nonce. This
does not define a new finality threshold. Authentication and verified
artifacts, not replica count, distinguish a valid omitted operation from a
forged or corrupt claim. Reconciliation must move valid missing operations
forward while that epoch still permits them, then re-derive the cut.

Also address liveness: simply requiring every local prepare row to disappear
could let one abandoned request permanently prevent an epoch change. The
resolution/drain/cancellation rule needs its own actual safety argument and
adversarial evidence before implementation. This ADR supplies no timeout,
expiry-unlock, force flag or operator-asserted-completeness escape hatch.

### Freeze, vote and activation must compose

Persist an immutable outgoing-epoch proposal/vote identity before exposing a
signature. Bind it to the exact verified cut, outgoing authority and next
set; retries return the retained identity and conflicts do not sign again.
Preserve commit-time writer/epoch CAS fences and exact ambiguity handling.

Specify which operations a frozen epoch may still reconcile, and how a cut
remains consistent while those operations complete. Absence of an activation
row alone is not sufficient justification for unconditional local unfreeze:
account for exposed votes, possible certificates and concurrent mutation.

Activation must verify local completeness and the same authenticated identity,
not accept a remote assertion that a store is ready. A joining validator does
not vote merely because it has a key or receives individually valid records.
Retired keys remain historically verifiable but cannot authorize fresh work.

### Recovery is ordered across epochs

An old-epoch operation cannot be replayed only after installing every later
epoch: existing execution correctly fences old fresh execution. The transfer
must interleave genesis, each epoch's authenticated application history and
its transition in the correct dependency order. Restart re-verifies the same
chain and cut identity rather than trusting a changed singleton row.

Initialize the new epoch's ordered engine/anchor under the verified new set
without overwriting old consensus history or treating tombstones as absence.
Reconstruct serving policies from committed authority; keep the local genesis
and protocol/TLS pins independent of untrusted peer hints. Original completed
request replay must remain exact before fresh epoch/module/object work.

## Integrated acceptance

Use four voting slots and five genuine identities: old A/B/C/D, then replace
D with a fresh E namespace. Generate non-genesis code/instance/object/receipt
and fee history through actual paid user contracts, including a charged
failure and exact replay. Submit real Unbond for D and capture its actual
unlock epoch; do not seed Exited/Jailed/Unbonding rows.

E verifies the complete handoff before outgoing A/B/C authority certifies
A/B/C/E. The new set must actually run paid Publish/Instantiate/Call and a
fee claim. Advance certified epochs to D's recorded unlock epoch; test early
and still-member refusal and then genuine Withdraw while D is absent.
Kill/reopen E and a survivor and compare original receipts, objects, nonces
and settlements on exact artifact replay.

Negative evidence includes incomplete/forged/divergent cuts, a valid page from
another cut, duplicate/reordered pages, contradictory outgoing votes, retired
signers, old fresh execution, unresolved prepares/certificates, real stale
writers, and restart after an interrupted freeze/transfer/activation.

## Implementation obligations

- Exercise the independently reviewed full-certificate retention intersection,
  freeze race, pre-vote artifact possession, partial-lock resolution, inherited
  shared branches and repeatable pre-Seal readiness in executable adversarial
  tests. Design approval is not runtime or security approval.
- Explicit portable collection schema/projections and runtime enumeration
  interfaces. Preserve semantic deletion tags and signed execution operands,
  not physical counters or synthetic admission receipts.
- Exact per-page/chunk/invocation limits and resumable resource tests, including
  large legal records. Do not silently introduce an arbitrary whole-chain cap.
- Versioned frame/key allocation after the namespace sweep, stable/adversarial
  vectors and explicit fresh-genesis profile enforcement. Original completed
  replay and historical verification must remain defined without an unsafe
  active legacy mutation bypass.

The 2026-09-28 stateless availability-library slice allocates canonical
`AvailabilityIdentity` `0xD030/v1`, `AvailabilityVote` `0xD031/v1`, and
`AvailabilityCertificate` `0xD032/v1`, plus the distinct signature message
domain `fast-path-availability-v1`. The IDs were checked against existing
canonical type IDs; no historical ID or byte encoding changes. This allocation
does not activate a publication, retention, or apply-admission rule. Later
epoch-control and remaining durable-state IDs remain unallocated. The usable handoff
implementation must include
the core, authenticated HTTP/SDK/CLI, genuine multi-validator E2E, stable and
adversarial vectors, documentation and the full repository/independent-review
gates as one usable feature. PostgreSQL is a tested profile, not a protocol
assumption. Operational independence, security audits and live startup remain
separate; no deployment, real custody, performance, HA or provider
certification is authorized or implied.

A second 2026-09-28 slice implements the handoff-capable logical commitment
profile itself, in
[`crates/node-core/src/logical_generation.rs`](../../../crates/node-core/src/logical_generation.rs).
It allocates `LogicalProfileRecord` `0x6480/v1` and `LogicalProvenanceRecord`
`0x6481/v1`, derives the authenticated `ExecutionGeneration` operand from
verified per-subject provenance instead of a physical creation checkpoint, and
wires that derivation and admission through every live application path that
installs effects, a receipt, a nonce advance or a settlement against an
already-installed profile: paid execution, local execution, publication, bond
lifecycle, fee-claim settlement, and the generic durable-event path, each
gated through `logical_generation::admit_application` or
`admit_generic_transition`. A store whose signed genesis binds the historical
model keeps its exact existing physical admission, commitment and
monotonicity rules unchanged. This does not implement Freeze/DrainSet/Seal
control or the publication-before-apply gate this ADR requires: no
cross-validator availability quorum is consulted before application, and the current
`NodeCoreError::LogicalProfileApplicationUnsupported` refusal is a local,
always-correctly-paired-by-construction invariant guard against a caller
presenting a resolved profile and derived evidence that disagree, not an
active gate on quorum availability publication. The complete design's
apply-admission rule, described above, remains open.

As of 2026-09-30, this second slice's As-Is/To-Be boundary is also recorded
standalone in
[Logical execution generation admission](../logical-execution-generation.md),
for a reader who needs only that mechanism. That document does not restate or
supersede this record's design; `TODO.md` remains the source of truth for
implementation and validation status, including branch/PR state.
