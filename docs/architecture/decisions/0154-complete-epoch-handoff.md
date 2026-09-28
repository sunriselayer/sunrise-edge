# DR-0154: Complete epoch handoff without weakening retained history

## Status

Accepted implementation direction, 2026-09-27. This record fixes the design for
[DR-0151](0151-integrated-network-delivery-and-lightweight-stores.md)'s
integrated membership/epoch delivery after independent design review and
correction of the availability/drain/readiness gaps. The mechanism is specified
in [Complete epoch handoff](../epoch-handoff.md). At acceptance, this was a
design-only decision and did not activate a new runtime rule. The first independent
implementation slice on 2026-09-28 allocates the availability wire family
below, but still does not implement durable retention or apply admission. The
complete design requires a new apply-admission rule and logical commitment,
not a new quorum-applied finality rule. Implementation and validation status
belong in [`TODO.md`](../../../TODO.md).

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

Implementation clarification (2026-09-28): retention must accept a full
certificate even if the retainer holds a conflicting partial local prepare.
Its canonical publication bundle therefore supplies the complete logical
commitment witness and all content-addressed replay artifacts; verification
cannot re-run admission against local heads or overwrite the local lock.
The quorum certificate authenticates the exact witness hash, while the
retainer verifies the bundle's content and closed dependency manifest before
an ACK. Local provenance rows alone are not transferable proofs. The later
cut/import verifies the provenance chain by independently replaying the
authenticated history. See the bundle rules in the linked design.

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

Implementation clarification (2026-09-28): classify outbox batches/messages,
delivery rows and attempt rows explicitly as known exclusions rather than
letting a generic scanner skip them. The current certified, paid and ordered
application paths do not emit outbox messages, and production state machines
have no nonempty outbound projection. A fresh handoff profile must verify that
there is no nonempty or pending outbox obligation, including in the legacy
keyspace, before excluding those rows. It must fail closed on any such
obligation. Delivery leases, errors and attempt counts are replica-local and
must never be imported. Supporting nonempty outbound messages later requires
a separate cross-epoch delivery policy and a deterministic reconstruction
proof; replaying an old-epoch message into ingress that rejects the old epoch
would silently lose it. The current handoff must not claim to support that.

The `fastpath/` prefix is not a blanket local-data exclusion. Its
`prepared/`, `lock/` and `nonce-lock/` families are local reservations;
certificate/witness, settlement/claim, bond/transition/evidence,
validator/economics policy and epoch/transition families are authenticated
business or control history. They keep their existing independent signature,
certificate and replay verification rather than acquiring a duplicate generic
logical-generation provenance row. The portable cut must include and verify
the required history families and derive its generation floor from verified
history; unknown future families fail closed. Excluding them from the generic
FastVote admission operand never authorizes omitting them from the cut.
`ordered-economics/` is likewise not a homogeneous local cache: `header/`
and `outcome/` retain original business history, while `state/`,
`applied-height/` and `candidate/` carry consensus control/prerequisites.
The cut must verify the former against receipts and certified prefix and
retain enough of the latter to prove safety. Unknown families fail closed.

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
epoch-control and durable-state IDs remain unallocated. The usable handoff
implementation must include
the core, authenticated HTTP/SDK/CLI, genuine multi-validator E2E, stable and
adversarial vectors, documentation and the full repository/independent-review
gates as one usable feature. PostgreSQL is a tested profile, not a protocol
assumption. Operational independence, security audits and live startup remain
separate; no deployment, real custody, performance, HA or provider
certification is authorized or implied.
