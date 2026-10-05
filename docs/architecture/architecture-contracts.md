# Architecture contracts

This is the target responsibility and interface model, not implementation
status. [DR-0180](decisions/0180-architecture-first-interface-contracts.md)
records the architecture-first work boundary. Current implementation owners
are in the [code map](../development/code-map.md); progress and remaining
implementation belong only in [TODO.md](../../TODO.md).

## Design criteria

An abstraction is useful when it makes a real invariant explicit and removes
multiple implementations of that invariant. Moving code, adding a generic
trait or giving a large file a shorter name is not sufficient. The target
must explain how the remaining network functions fit without new authority
exceptions or another persistence or consensus mechanism.

Prefer one owner per decision, explicit inputs and typed outputs. Deterministic
execution does not choose storage; a storage adapter does not choose an epoch;
a network client does not choose trusted configuration. Keep raw transport
input separate from verified evidence and verified evidence separate from
permission to mutate or expose a signature.

## Responsibility graph

| Owner | Input contract | Output contract | Excluded responsibility |
| --- | --- | --- | --- |
| Protocol types and canonical encoding | Bounded values with one defining schema | Exact frames, IDs and domain-separated commitments | Storage, network credentials and live authority |
| Contract execution | Authenticated, ABI-bound invocation and exact object/code material | Deterministic application/fee effects and charged failures | Consensus selection, direct persistence or privileged native assets |
| Consensus | Verified committee, protocol parameters, explicit state and authenticated event | Next safety state, messages and committed block proofs | Store layout, business execution or reset at handoff |
| Core authority and lifecycle | Local trust pins, original completed receipts, verified protocol evidence and fresh local observations | Narrow admitted operation or typed stop/refusal/replay | Provider configuration as authority, arbitrary maintenance bypass |
| Atomic completion | Explicit observed state/object revisions and owned effects/receipt/outbox sections | One bounded durable transaction and classified outcome | Additional execution, independent partial section commits or invented refusal |
| Capability-specific stores | Trusted physical namespace, operation fence/deadline and validated transaction | Confirmed/rejected/indeterminate output and bounded reads | Membership, signatures, contract-specific business rules |
| Hosts, wire, clients and CLI | Closed frames, explicit local pins, authenticated routes and held artifacts | Bound acknowledgements and retained exact bytes | Creating completeness, changing an epoch from a peer response or bypassing core |

These are semantic owners. They do not require one crate per row, a universal
handler framework, or a common SQL interface for unrelated providers.

## Trust and authority are different axes

Keep the following separate in both the API and composition:

- Original genesis pins identify the chain's trust root. They never change to
  make the current epoch match a newly installed committee.
- A verified serving context identifies the current authorized epoch, active
  committee, policies and authenticated predecessor. A bare epoch row or
  caller-supplied context cannot construct this capability.
- Historical verification resolves the authority that signed an original
  certificate or lifecycle intent. An old key may verify its historical
  operation or authorize a legitimate withdrawal without becoming a current
  committee signer.
- A storage operation context identifies the local writer fence, deadline and
  correlation. It is not protocol or membership authority.

Construction belongs to the owning verifier. Do not expose public fields,
blanket trait implementations or `trusted: bool` constructors that let an
untrusted caller manufacture a verified capability. A verifier result must
also identify the exact observations which persistence rechecks before
exposing fresh authority.

Immutable verified evidence and a fresh admission warrant are different
contracts. An old committee remains a valid historical fact after retirement;
that fact cannot authorize a new vote. A warrant names the exact operation
and the observed local lifecycle/authority revisions which its completion
must assert. It is not a serializable transferable permission.

## One completion model

The common persistence language is an observed transaction, not a generic
business handler. It consists of state read assertions and mutations, exact
object-head observations and version changes, and the owning original receipt
and outbox sections where applicable. Related effects commit atomically in
one validator's transactional domain.

Share consistency and assembly rules where they are identical: conflicting
observations must stop; duplicate identical observations may combine;
conflicting mutations must not silently overwrite each other. Keep explicit
section ownership. Ordinary single-owner mutation insertion rejects every
duplicate key; deliberate ordered composition may coalesce identical
contributions but must reject disagreement. The API names the policy rather
than silently treating the two cases as equivalent. Failed additions must
leave their assembler unchanged or prevent it from being finished.

A metadata-only commit and an original business invocation
are distinct completions, not an optional-receipt bypass.

`StateObservationSet` binds exact-key revisions to one logical domain.
`StateTransactionBuilder` owns the shared count/byte limits and transactional
preflight of additions. `insert_mutation_once` is single-owner insertion;
`merge_state_exact` explicitly requests identical-contribution composition.
`finish_metadata` and `finish_invocation_state` retain the existing distinct
empty-mutation rules. Neither result is a commit receipt or an admission token.
The original transaction constructors share the same byte accounting rather
than maintaining a second definition of the bound.

Read-only verification also needs a read-only port. `VersionedStateReader`
supplies exact value/revision observations without receipt, object, lifecycle
mutation or commit methods. Existing durable adapters forward the distinct
read method without changing their checks; captured reconstruction rows
implement only the lower read contract. The port itself proves neither a stable
snapshot nor live protocol authority. Prepared-artifact and registered-bond
chain verification no longer need a pretend writable store with runtime-rejected
commit methods. No reverse implementation promotes a reader into a writer.

The outcome remains confirmed, authoritatively rejected, or indeterminate.
An indeterminate write is reconciled from exact retained data, never converted
into success or a deterministic business refusal. Completed original request
replay runs before fresh epoch/module/object resolution and never reapplies
effects. Cached live votes/ACKs have a different exposure policy: they still
need current authorization.

Business evaluation produces a prepared original completion: its owning
effects, deciding observations, original receipt and outcome. Preparation is
not a successful durable write. A single completion assembler combines that
plan with coordinator-specific protocol progress; only confirmed persistence
or exact retained reconciliation permits output exposure. Live ordering,
signerless recovery and private reconstruction consume the same owning
operation evaluator, not separate implementations of business behavior.

## Handoff contracts

Use the existing [complete handoff](epoch-handoff.md) authority chain and
the existing chained-HotStuff engine. The architectural stages are:

1. Verify the complete source material and derive the private business cut.
2. Install that exact verified plan under the destination's own fence in a
   permanently import-origin namespace; completion remains inactive.
3. Compare the complete destination and immutable body closure under a fresh
   local observation; retain conditional next-set readiness atomically.
4. Verify the complete business-free inherited suffix and normally commit
   one Seal target through outgoing consensus.
5. Under a separately accepted activation contract, verify Seal-derived
   successor authority and atomically install target-local serving without
   resetting permanent storage origin or outgoing safety history.
6. Reconstruct subsequent epochs from a verified predecessor and retain the
   original trust root, histories, receipts and logical provenance.

The interfaces must name these evidence transitions, not collapse them into
`complete`, `active`, `is_ordinary()` or a shared mutable context. Readiness
and a public certificate cannot create Seal or serving authority. Permanent
storage origin and current serving authorization remain separate.

For first-epoch Seal, [DR-0187](decisions/0187-first-epoch-ordered-seal.md)
defines the exact committed boundary and permanently stops outgoing own
signatures and ordinary completion. It supersedes the earlier proposed
post-Seal outgoing transition vote: neither fresh signing nor cached live
outgoing own-signature responses may be exposed after acceptance. Original
read-only reconciliation remains distinct. Successor activation needs its own
reviewed proof-backed contract; this outline approves no replacement schema
and does not treat a Seal or Ready certificate alone as serving authority.

The remaining interface partition is below. These are conceptual contracts,
not names of callable Rust producers or approved wire/storage schemas.

| Contract owner | Required input and result | Actual consumer boundary |
| --- | --- | --- |
| Namespace lifecycle | Permanent genesis/import origin, exact import binding/progress and separately verified serving authorization; a completed import remains inactive until verified activation | Runtime memory/SQL/selected PG mutation guards and namespace reopen checks must not erase import origin or treat a stored `active` tag as cryptographic proof |
| Serving-authority resolver | Original trust root or authenticated predecessor, fresh installed epoch/committee/policy/closure observations and local operation context; returns a private invocation-scoped warrant plus its deciding observations | Fresh owned/ordered admission and cached live vote/ACK exposure consume the same authority rules. Original receipt replay and historical certificate verification remain distinct consumers |
| Ordered epoch namespace | Verified epoch/predecessor selection and existing consensus engine; selects the safety, signing-identity and applied-prefix keys for that epoch | Successor state must not overwrite outgoing safety/history. A caller-supplied epoch or a host-held policy cannot itself select an authorized successor |
| Reconstruction predecessor | Immutable genesis root for the first epoch, or a separately authenticated activation chain for a later epoch; supplies the exact predecessor cut and generation floor | Reconstruction, cut verification and readiness retain their independent policy/history/domain checks. An activation-chain variant has no usable producer until those proofs exist |
| Seal-target verifier | Locally derived complete business cut, committed DrainSet, eligible ready next set and complete retained readiness/suffix companions; produces exact immutable target evidence | First-epoch commitment follows DR-0187; separately reviewed activation and recurring reconstruction must preserve that target without treating evidence as a fresh mutation warrant or granting post-Seal outgoing signing |
| Activation completion | Separately accepted proof-backed activation contract bound to the committed Seal, exact complete inactive target, fresh local serving/lifecycle observations and the target's own writer fence | One actual atomic target rollover installs the successor policies/provenance/serving state; output is exposed only after real confirmation or exact retained reconciliation, with import origin and outgoing history preserved |

The serving resolver removes repeated authority derivation only if its deciding
observations join the actual completion. It must not cache a live permission
across invocations. Its original-genesis evidence can remain immutable, while
installed authority is observed afresh. Namespace metadata is provider data
to verify, not a transferable serving capability.

Keep first-epoch chain-only safety rows byte-identical and retained for their
original historical interpretation. Successor epochs need separately scoped
safety and protected-signing keys; exact key families require a namespace
sweep before implementation. Original request identities/receipts remain
chain-wide so replay can reconcile before resolving a newer epoch. These
requirements do not globally order otherwise independent owned transactions.

DR-0187 defines the first-epoch Seal subject/proof ownership. Epoch-scoped
successor safety keys, non-circular activation commitments, protected
target-local activation retention and recurring reconstruction still need
their owning detailed contracts. The architecture outline does not approve
a wire format or fill those gaps with placeholder authority.
The proposed [recurring successor serving](recurring-successor-serving.md)
contract ([DR-0191](decisions/0191-recurring-successor-serving.md)) is the
pre-code proposal for recurring reconstruction. It extends DR-0187 and
DR-0189 additively and is not accepted authority.

[Functional handoff closure](functional-handoff-closure.md) and
[DR-0186](decisions/0186-functional-handoff-closure.md) propose concrete closures
for the decisions below; their separate activation/recurring proposals remain
pre-code design review, not serving authority. Their outgoing post-Seal signing
sketches are superseded by DR-0187.

Settle these coupled design questions before implementing those producers:

- Whether retained validators continue in the outgoing namespace or select
  their separately verified import target, and how outgoing safety and original
  Seal history remain available across crashes. An atomic transaction
  in one namespace does not imply cross-namespace atomic retirement/activation.
- Preserve DR-0187's bounded first-epoch Seal reference and quorum-retained
  companion closure in the separately reviewed successor/predecessor contract.
  Readiness evidence cannot simply be inlined if it exceeds the ordered
  candidate bound; a digest alone proves neither retention nor local target
  verification.
- Exact retained headers/justifications and bounded phase-aware high/locked
  traversal for the business-free suffix; pruning must not delete evidence
  which a later verifier requires.
- Successor activation/predecessor commitment schemas and verified host/client
  reconfiguration. A peer's newer epoch or an `epoch-repin-required` hint is
  never an authorized re-pin.

## Interfaces before bodies

Write the dependency and input/output contract before adding another feature
implementation. Prefer typed ports to a collection of unrelated free-function
arguments, but introduce a port only for a real consumer. Existing working
features must keep callable implementations during migration.

An incomplete design skeleton may be intentionally isolated from the shipped
composition. Missing bodies must fail explicitly, and their types must not
grant authority merely by being constructible. A `todo!()` is acceptable only
in an explicitly development-only, unreachable skeleton; neither default
builds nor advertised handlers may acquire a reachable panic. Compilation is
evidence about shape, not proof that a feature works.
Prefer sealed ports with required methods and absent concrete producers to
panic bodies for unfinished authority. Such a declaration can show the whole
dependency contract without manufacturing an executable permission.

Do not maintain two permanent frameworks. Once the defining interface has a
working owning implementation and equivalent acceptance, migrate its actual
callers and remove the superseded internal mechanism in the same coherent
slice. Unreleased public naming can change deliberately; historical evidence
must not be erased or made forgeable under the name of cleanup.

## Test and gate contracts

Tests follow the same ownership graph. Share signed input and environment
builders, not an implementation-derived expected result. Pure type/codec and
transition tests remain distinct from real durable restart/fencing/atomicity,
authenticated HTTP and compiled-CLI acceptance. A reusable fixture describes
its exact capabilities; it does not initialize every subsystem or silently
select PostgreSQL.

The gate registry owns profile membership and executable actions. Workflow
jobs already invoke common entrypoints; centralize the underlying execution
decisions rather than claiming that entrypoint sharing is new. The aggregate
fails closed for a missing, skipped,
cancelled or failing member. Independent gate-contract tests retain fixed
expectations so one edited registry cannot certify its own omissions. The
four required DB-free lanes and separately selected complete PG acceptance
remain distinct. Reorganization cannot reduce assertions or provider claims.

Acceptance for a redesigned boundary includes the actual migrated callers,
unchanged existing outcomes/bytes unless a separately reviewed semantic
change is explicit, negative controls, real-store evidence appropriate to the
affected capability, and independent exact-head review. Do not infer runtime,
compilation, whole-CI performance or deployment readiness from cleaner APIs.
