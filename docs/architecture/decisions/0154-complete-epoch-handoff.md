# DR-0154: Complete epoch handoff without weakening retained history

## Status

Proposed, 2026-09-27. This record captures the design investigation for
[DR-0151](0151-integrated-network-delivery-and-lightweight-stores.md)'s
integrated membership/epoch delivery. Its mechanism is not accepted for
implementation. No finality rule, canonical frame or type identifier is
changed by this document. Implementation and validation status belong in
[`TODO.md`](../../../TODO.md).

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
manufacturing an abort, applying fees twice, or unlocking another request.
Unresolved authenticated disagreement is a reason to refuse activation and
recover, not to silently select a lossy history.

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

## Deliberately unresolved

- The actual authenticated complete-cut construction and portable collection
  schema, including pending-operation reconciliation and safe unfreeze.
- Per-invocation/page resource bounds and any explicit profile-wide capacity
  restriction. Do not silently introduce an arbitrary whole-chain limit.
- Exact versioned frame/key changes after sweeping existing namespaces;
  original completed replay and historical verification must remain defined.

No new IDs or versions are allocated here. The implementation must include
the core, authenticated HTTP/SDK/CLI, genuine multi-validator E2E, stable and
adversarial vectors, documentation and the full repository/independent-review
gates as one usable feature. PostgreSQL is a tested profile, not a protocol
assumption. Operational independence, security audits and live startup remain
separate; no deployment, real custody, performance, HA or provider
certification is authorized or implied.
