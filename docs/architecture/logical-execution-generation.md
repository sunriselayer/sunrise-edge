# Logical execution generation admission (DR-0154 slice)

## Scope

This is one bounded capability within
[DR-0154](decisions/0154-complete-epoch-handoff.md)'s complete design; the
decision record's own status section is authoritative for what this slice
does and does not implement. This document only sets the As-Is/To-Be boundary
for readers who need the logical-generation admission mechanism specifically,
without reading the full epoch-handoff design.

## As-Is: what is implemented

- [`ExecutionGeneration`](../../crates/protocol-types/src/execution_generation.rs):
  a checked causal generation type. `successor_of(floor, dependencies)` returns
  `1 + max(floor, every dependency)` via checked arithmetic and refuses on
  overflow rather than wrapping or saturating. It is a causal operand shared by
  independent operations, not a global serial counter.
- [`crates/node-core/src/logical_generation.rs`](../../crates/node-core/src/logical_generation.rs)
  derives this generation from verified per-subject provenance and admits an
  application only when the store's own signed genesis binding demands and
  receives exactly that evidence:
  - `LogicalProfileRecord` (`0x6480/v1`), one per genesis context, installed
    only by a signed version-2 `GenesisManifest` whose `commitment_profile`
    field sets `CommitmentProfile::LogicalGenerationV2`, and re-verified
    byte-for-byte against that signed manifest on every reopen. A historical
    (`PhysicalCheckpointV1`) store keeps its existing physical admission.
    Removing the profile row from a store whose signed manifest selected
    the logical model fails closed; absence does not authorize a downgrade.
  - `LogicalProvenanceRecord` (`0x6481/v1`), one per exact subject identity
    (generic state key, object id, or sender-nonce row), binding that subject
    to its authenticated generation and a closed semantic observation
    (present/deleted/object-live/object-deleted/nonce-next), so tombstones stay
    distinguishable from absence and a forged or mismatched pairing fails
    closed.
  - `admit_application` / `admit_generic_transition` (via `admit_resolved`)
    resolve the installed profile, derive the generation from the complete
    verified input set, stage the successor provenance rows into the same
    atomic commit, and call `require_application_admissible`, which refuses
    unless a `Logical` store carries a derivation whose generation strictly
    exceeds the profile's authenticated genesis floor, and refuses a
    `Historical` store that carries any logical derivation at all. The two
    models can never be mixed inside one commit.
  - Supported application paths that install effects, a receipt, a nonce
    advance, or a settlement against an already-installed profile are wired
    through one of these two entry points: paid execution
    (`paid_execution.rs`), local execution (`local_execution.rs`),
    publication (`publication.rs`), bond lifecycle (`bond_lifecycle.rs`),
    fee-claim settlement (`fee_claims.rs`), and the generic durable-event path
    (`lib.rs`). FastVote's v2 preparation additionally binds semantic
    observations and the derived generation into its commitment/witness;
    physical revisions remain local CAS evidence. Its certified apply path
    reaches logical admission through these same handlers. The separate
    [publication-availability capability](publication-availability.md) also
    requires quorum retention before a fresh Logical FastVote application.
  - A fresh handoff-capable genesis installs its first provenance rows
    directly through `genesis_provenance`, the one by-construction exception:
    no profile row exists yet for the gate to resolve against.
  - Logical-profile epoch proposal/vote and fresh activation refuse with
    `NodeCoreError::EpochTransitionLogicalProfileUnsupported`: the existing
    transition writer does not yet derive next-epoch logical provenance.
    Refusal happens before a vote signature or fresh policy mutation.
    Activation reconciles an already-committed transition's complete identity
    and checks the outgoing epoch before resolving the fresh-activation
    profile. Historical-profile transitions remain supported. This is a
    deliberate unsupported-operation boundary, not implemented handoff.
  - `NodeCoreError::LogicalProfileApplicationUnsupported` and
    `NodeCoreError::ExecutionGenerationRegression` are application-binding
    refusals; both are local invariant guards against a caller presenting a
    resolved profile and derived evidence that disagree with each other or
    with the genesis floor, not a cross-validator gate.

## To-Be: explicitly deferred by this slice

This slice does not implement, and must not be read as implementing, any of:

- Availability publication or ACK quorum gates are a separate composition,
  implemented for fresh Logical FastVote by
  [publication availability](publication-availability.md), not supplied by
  the generation primitive or local provenance checks themselves.
- Freeze, DrainSet, Seal, or any ordered epoch-control state machine.
- Frontier closure, cut derivation, or portable-collection enumeration.
- Import/readiness verification for a joining or recovering validator.
- Logical-profile transition votes, next-epoch provenance and activation of
  a next validator set, or any Delivery 3 completion claim.

The generation/provenance gate alone consults no cross-validator availability
quorum. Its refusal errors are single-node, always-correctly-paired-by-
construction guards, not availability authority. The separately composed
Logical FastVote apply gate does require a verified availability certificate;
direct local development handlers do not acquire public-network authority
merely by deriving a generation. See
[DR-0154](decisions/0154-complete-epoch-handoff.md) for the full design.

## Compatibility

There is no released compatibility promise being extended by this slice.
Historical (`PhysicalCheckpointV1`) stores and their existing stable vectors
keep their exact existing physical admission, commitment, and monotonicity
rules. Logical admission requires a fresh store initialized with a signed
version-2 (`0x6416/v2`) genesis manifest that explicitly sets
`CommitmentProfile::LogicalGenerationV2`. There is no upgrade
or migration path from a historical store into the logical profile.
