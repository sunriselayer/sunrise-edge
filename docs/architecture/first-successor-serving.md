# First successor target-local activation and authenticated serving

This is the accepted design contract of
[DR-0189](decisions/0189-first-successor-serving.md). It depends on the
accepted [verified inactive import](verified-inactive-import.md)
([DR-0176](decisions/0176-verified-inactive-business-import.md)),
[conditional readiness](conditional-readiness-seal.md)
([DR-0178](decisions/0178-conditional-readiness-wire-and-retention.md)) and
[first-epoch ordered Seal](ordered-seal.md)
([DR-0187](decisions/0187-first-epoch-ordered-seal.md)) contracts and closes
the successor-activation gap they and the aspirational "Recovery and serving
authority" section of [epoch-handoff.md](epoch-handoff.md) leave open.
Current status belongs only in [TODO.md](../../TODO.md). This is a design
document, not evidence of implemented serving: wire identifiers, keys,
schema and ports described here require the reviewed implementation and
acceptance below before any serving capability is claimed.

## 1. Authority chain and the evidence/warrant separation

Authority for the first successor at epoch e+1 composes, in order:

1. The immutable, privately constructed `VerifiedGenesisRoot`
   ([genesis trust](genesis-trust.md); DR-0182), unchanged.
2. The outgoing epoch-e committee, verified through the same root.
3. Source-free [authenticated ordered history](ordered-history.md) from
   height 1 through the committed [Seal](ordered-seal.md) at height h.
4. The committed Seal target, proof, outcome and original receipt
   (DR-0187, frames 0xD050-0xD053).
5. The [conditional readiness](conditional-readiness-seal.md) certificate
   named by that Seal (DR-0178).
6. The resulting checked-eligible e+1 validator set.

Every outgoing signature this chain relies on was created before Seal
acceptance; nothing here creates a new outgoing signature. Relaying an
already formed QC or certificate is historical relay, not signing.

Three opaque core types keep the roles apart:

All fields are private to one node-core `serving_authority` module; only
its own `verify_successor_activation`, `activate_successor` and
`resolve_live_authority` can construct them, so no other module can
fabricate evidence or a warrant. The module exposes one public wrapper,
`verify_successor_authority` (Section 3.2), for cross-crate callers.
`VerifiedSuccessorActivation` is module-private, `ActivationWarrant` is
crate-visible with private fields, and `LiveWarrant<'inv>` is a public
opaque type so native HTTP can borrow it without constructing one. Type
visibility never exposes a constructor or a writable field.

- `VerifiedSuccessorActivation` -- source-free evidence produced only by
  `verify_successor_activation(plan, manifest_identity, artifacts)`
  (Section 3). Its inputs are the existing `BusinessReconstructionPlan`, an
  untrusted claimed `OrderedHistoryIdentity` through h and a
  `SuccessorArtifactSource`; it never takes a destination store, lifecycle,
  token or local key. The Rust SDK consumes only this evidence, through the
  public `verify_successor_authority`/`VerifiedSuccessorAuthority` wrapper,
  never this private type directly.
- `ActivationWarrant` -- built only inside `activate_successor`
  (Section 6) while the destination slot is `Inactive`. It combines the
  evidence with a full `observe_complete` comparison, the namespace
  validator and the local key. It carries no serving observation, because
  none exists yet.
- `LiveWarrant` -- built only by `resolve_live_authority` (Section 8) from
  an installed `Serving` slot plus a fresh full rerun of Section 3.

None has a public constructor, `Default`, `Clone` or serialization, and no
decoded row, equality report or flag constructs any of them. Only the two
warrants read destination rows or the local key, and only they authorize a
destination write.

## 2. Closed public frames

All frames use canonical encoding version 1, closed fields, exact
decode/re-encode and checked lengths before copies. A workspace sweep on
base `aa0f664` found no allocation of `0xD054`-`0xD05F`, `0x64D5`-`0x64DF`,
`0x6441` v3, `durable_successor_serving`, `successor_activation`,
`successor_host`, or an `epoch-` ordered key infix.

| Frame | Fields in canonical order | Bound |
| --- | --- | --- |
| 0xD054 SuccessorActivationSubject (source-free, hash-only) | 1 chain, 2 protocol u32, 3 outgoing epoch u64, 4 genesis Digest32, 5 domain, 6 Seal target Digest32 (0xD051), 7 Seal request 32B (the exact candidate `request_id`, whose bit `0x80` of byte 0 is already set by 0xD052 derivation; verification requires it and never sets it), 8 Seal height u64, 9 Seal block Digest32, 10 successor epoch u64 (checked outgoing + 1), 11 successor-set Digest32 (= `ReadinessSubject.next_set_digest`), 12 schedule Digest32 (= `schedule_digest`), 13 semantic-cut Digest32 (= `cut_digest`) | 2 KiB |
| 0xD055 SuccessorActivationManifest (source-free) | 1 subject frame, 2 readiness certificate Digest32, 3 certificate length u32, 4 `OrderedHistoryIdentity` frame through h, 5 Seal 0xD017 commit-proof component Digest32 (`ordered_history_component_digest`, `crates/node-core/src/ordered_economics/ordered_history.rs:170`), 6 proof length u32, 7 saved-cut package Digest32 (= `ImportBinding.package_digest`), 8 raw-plan Digest32 (= `ImportBinding.plan_digest`) | 2 KiB |
| 0x6441 v3 successor consensus anchor preimage | fields 1-9 as v2 (label `se/ordered-economics/anchor/v3-successor`; field 2 context at e+1; field 4 the original pinned genesis digest; field 5 the e+1 `ValidatorSet` digest; fields 6-8 `ConsensusParameters::genesis()`; field 9 the original signed `minimum_freeze_block_height`), plus field 10 the 0xD054 subject Digest32 | hash only |
| 0x64D5 SuccessorServingRecord (protected) | 1 subject Digest32, 2 manifest Digest32, 3 exact `encode_import_binding` bytes (0x64C0, `crates/runtime/src/inactive_import.rs:318`), 4 exact `encode_import_progress` bytes (0x64C1, `:409`), 5 exact 0x64D2 frame of the activation token (`encode_readiness_creation_token`, `crates/runtime/src/conditional_readiness.rs:142`), 6 v3 anchor Digest32, 7 namespace validator id, 8 installed Ed25519 public key (32B) | 16 KiB |
| 0x64D6 SuccessorServingSlot (protected) | 1 phase u16 (1 Inactive with empty field 2; 2 Serving with one 0x64D5 record in field 2), 2 bytes | 17 KiB |

Subject and manifest digests use `NodeEvent` at outgoing epoch e, like the
0xD051/0xD052 preimages they embed. The v3 anchor uses `ProtocolConfig` at
e+1, like `ordered_economics_authority_anchor`
(`crates/node-core/src/ordered_economics/policy.rs:72`). Manifest field 2
uses `Certificate` at e, like SealIntent field 5. The 0x64D5/0x64D6 codecs
live in the runtime crate beside 0x64C0/0x64D2 so a backend can compare
fields 3, 4, 5 and 7 without parsing node-core rows. No frame carries a
path or other local-only value (Section 3.1).

No new signing label, signature purpose or hash suite is introduced.
Unknown phases, tags or versions stop. Transport bounds are unchanged:
16 KiB descriptors, 1 MiB chunks, the 1 MiB / 256-vote certificate, the
32 MiB canonical proof cap. Ordered-history length stays unbounded; the
verifier is linear in it.

## 3. Source-free verification

### 3.1 Artifact source

The node-core trait over existing transport types only:

```rust
pub trait SuccessorArtifactSource {
    /// Whole saved cut, as `read_business_cut_archive` assembles it today.
    fn saved_business_cut(&mut self) -> Result<SavedBusinessCut, SuccessorArtifactError>;
    /// Height `1..=identity.through_height` of one fixed history export.
    fn history_height(
        &mut self,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError>;
    /// Exactly `length` bytes, `length <= 1 MiB`, else refuse.
    fn readiness_certificate(&mut self, length: u32) -> Result<Vec<u8>, SuccessorArtifactError>;
}
pub enum SuccessorArtifactError { Missing, Oversized, Malformed, Io }
```

The operator and successor host implement it over files they already
write: the saved-cut directory through `ImmutableArchive` and
`read_business_cut_archive` (`apps/operator/src/business_cut.rs:418`), the
`history_export` layout (`height-{h:020}/descriptor.bin`,
`component-{kind:02}/chunk-{offset:020}.bin`, as
`clients/rust/src/ordered_history_archive.rs` reads it), and the
certificate file through `ImmutableArchive::read`. node-core never depends
on `apps/operator`. Every returned value is untrusted transport. The
verifier knows every reference independently: the height index is its own
loop counter; component kind, length and digest are the descriptor
`OrderedHistoryComponentRef`s checked by `verify_material`; the package
digest is recomputed by saved-cut verification; certificate length and
digest are SealIntent fields 6 and 5. Missing or corrupt files stop, never
skip; a directory listing is never authority.

### 3.2 Verifier

```rust
fn verify_successor_activation(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuccessorActivation, SuccessorActivationError>;
```

This stays module-private: the one private verifier, called only from this
module. The public surface the SDK and operator actually use is a thin
wrapper over it, in the same module:

```rust
pub fn verify_successor_authority(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError> {
    verify_successor_activation(plan, manifest_identity, artifacts)
        .map(VerifiedSuccessorAuthority)
}
pub struct VerifiedSuccessorAuthority(VerifiedSuccessorActivation); // private field
impl VerifiedSuccessorAuthority {
    pub fn subject_digest(&self) -> Digest32;
    pub fn manifest_digest(&self) -> Digest32;
    pub fn validator_set(&self) -> &ValidatorSet;
    pub fn policy_inputs(&self) -> &SuccessorPolicyInputs;
}
```

`VerifiedSuccessorAuthority` has no `Clone`, serde or `Default` impl and no
constructor besides this wrapper; it calls the one private verifier with
no duplicated verification logic, and takes no destination store, signing
key or live-authority input beyond what `verify_successor_activation`
already takes. `activate_successor` (Section 6.2) and
`resolve_live_authority` (Section 8) call `verify_successor_activation`
directly, in the same module; only cross-crate callers, namely the SDK's
`load_successor_authority` (Section 9), call `verify_successor_authority`.

`plan` is the existing `BusinessReconstructionPlan`
(`crates/node-core/src/business_reconstruction.rs:248`) with all ten real
fields: `genesis_root`, private `operation_context`, `domain`,
`resolver_history`, `ordered_policy`, `ordered_history_identity` (the cut
identity through T), `ordered_leg_policy`, `ordered_engine`,
`paid_base_policy`, `paid_engine`. The hash-suite schedule is
`plan.genesis_root.genesis_resolver()`; the readiness schedule digest is
derived from it. `manifest_identity` is a distinct input through h. The
function copies the borrowed references it needs before moving `plan`.

1. `verify_saved_business_import(plan, &artifacts.saved_business_cut()?)`
   (`crates/node-core/src/business_reconstruction/inactive_import.rs:363`)
   yields the `VerifiedImportPlan` with cut identity C through T (from the
   saved Proofs stream, heights 1..T) and `binding().generation_floor`.
2. Validate `manifest_identity` against `ordered_policy` and require equal
   context, domain, genesis digest and anchor to C, with
   `through_height = h > T`.
3. Run `OrderedHistoryVerifier::new(ordered_policy.clone(),
   manifest_identity.clone())` and `verify_next_height` over
   `artifacts.history_height(manifest_identity, k)` for k = 1..=h, then
   `finish()`. Additionally: the block at T equals the view/digest of C;
   heights T+1..h-1 carry no transaction; h carries exactly one candidate,
   a Seal, as its first occurrence (five components, no
   `ReplayOriginProof`), authenticated by the existing DR-0187 pure Seal
   authentication (`crates/node-core/src/ordered_economics/seal.rs`):
   0xD051/0xD052 re-derived, predecessor tag 1 equal to the pinned genesis,
   `created_checkpoint == T`. The h proof has empty child h+1 and
   grandchild h+2 (`target_is_empty_three_chain`). The h-1 link is checked
   once: besides the existing justify link of h to h-1, the h-1 proof
   `child` proposal digest must equal the Seal block digest
   (`ordered-seal.md:128-130`). A required extension of the verifier
   accepts a Seal candidate only at `through_height`; it does not exist
   today.
4. From the SealIntent: `seal_cut_identity_digest(intent.cut) ==
   intent.subject.cut_digest == binding().cut_digest`; subject
   chain/protocol/epoch/genesis/domain equal the plan root and domain;
   `outgoing_set_digest == binding().validator_set_digest`;
   `check_configuration(genesis_resolver)` fixes `schedule_digest`.
5. `artifacts.readiness_certificate(intent field 6)`; its `Certificate`
   digest at e must equal intent field 5 (one certificate variant per
   committed Seal); canonical decode; `ReadinessCertifier::new(resolver,
   &intent.subject, &certificate.next_set)?.verify_certificate(&certificate)`
   (`crates/consensus/src/readiness.rs:400,456`).
6. `check_next_set_eligibility`
   (`crates/node-core/src/epoch_transition.rs:359`) at epoch e for
   `seal_next_members(&certificate)` over a crate-private `PlanStateReader`
   implementing `VersionedStateReader` from the plan `ImportRow::State`
   rows only. Its fencing output is discarded.
7. Refuse any plan row under `ORDERED_ECONOMICS_STATE_PREFIX` whose suffix
   starts with `epoch-`, and any live fast-path lock or sender-nonce-lock
   row.

`VerifiedSuccessorActivation` holds the subject and manifest bytes and
digests, the `VerifiedImportPlan`, the e+1 `ValidatorSet` and members, the
v3 anchor, and the exact verified component bytes for heights T+1..h. It
contains no destination fact. Only the proof QC subset may differ between
independently activated hosts (0xD055 fields 5-6); each host installs the
bytes its own run verified.

Every step reruns on every invocation that needs the evidence --
activation, reconciliation, startup and every live request -- with no
cache or memo: cost grows linearly with the saved cut, including contract
re-execution, plus the whole history through h.

## 4. Scoped generation floor and Logical provenance for new rows

[`LogicalProfileRecord`](logical-execution-generation.md)
(`crates/node-core/src/logical_generation.rs:178`) stays byte-identical and
its `genesis_floor` remains the floor of every Original-namespace
derivation. A successor uses the verified cut floor, `ImportBinding.
generation_floor` (`inactive_import.rs:414`).

`logical_generation::derive` (`:879`) folds every present CAS-read key not
recognized by `is_excluded_subject` and `observe_state_subject` (`:1437`)
fails closed with `MISSING_PROVENANCE`. The new
`execution_policy_key_for_profile(ctx@e+1, 4)`, `paid_fee_policy_key(ctx@e+1)`
and `publication_policy_key_for_profile(ctx@e+1, 4)` rows live under
`INSTANCE_STATE_PREFIX`, which is not excluded, so they need provenance.
Only `derive` (`:893`) and the `Logical` arm of
`require_application_admissible` (`:1531`) hard-code `genesis_floor`;
`provenance_mutations` (`:947`) already writes at `derived.generation`.

Crate-private additions, opaque, no raw-value constructor:

```rust
pub(crate) struct GenerationScope(Scope); // Scope is private to this module
enum Scope {
    Original { floor: ExecutionGeneration },
    Successor { floor: ExecutionGeneration, epoch: Epoch, anchor: Digest32 },
}
impl GenerationScope {
    pub(crate) fn from_profile(profile: &LogicalProfileRecord) -> Self;
    pub(crate) fn for_activation(warrant: &ActivationWarrant) -> Self;
    pub(crate) fn for_live(warrant: &LiveWarrant) -> Self;
    pub(crate) fn floor(&self) -> ExecutionGeneration; // the only accessor
}
```

No module outside `logical_generation` can name `Scope` or build a
`Successor` variant; a caller holding no warrant cannot construct a
successor floor. Both successor constructors take floor, epoch and anchor
only from the warrant, whose values come only from
`VerifiedSuccessorActivation`: floor from the binding, epoch e+1 from the
verified subject, anchor the v3 anchor computed from the verified subject
and set. Neither reads an installed anchor, so there is no
install-before-anchor circularity.

`derive_scoped(&scope, ..)` is the body of `derive` with `scope.floor()`;
`derive` becomes `derive_scoped(&GenerationScope::from_profile(..), ..)`,
byte-identical for every Original call site and vector.
`require_application_admissible_scoped` compares against `scope.floor()`.
The Successor anchor binding does not go through `GenerationScope`, which
exposes only `floor()`: at activation, the `epoch-state/` key built from
the warrant's own verified epoch/anchor (`policy_inputs()`, Section 9) is
asserted INITIAL and written in the same transaction (Section 6.3); live,
that same anchor equals 0x64D5 field 6 of the warrant observation, which
every successor port rechecks byte-exactly inside its lock (Section 6.5).
Live transactions do not CAS `epoch-state/`, which would serialize
fast-path traffic behind consensus.

Activation names the existing derivation
`epoch_transition::derive_activation_set`
(`crates/node-core/src/epoch_transition.rs:499`), which reads
`paid_fee_policy_key(ctx@e)` as a CAS read and carries it forward
(`:549-567`). The fold set for the three new rows is exactly this one
dependency: `paid_fee_policy_key(ctx@e)`, folded through `derive_scoped`, so the three
rows depend on it; `provenance_mutations` writes exactly the three target
provenance rows at `derived.generation`. Every successor live path (normal
prepare/apply, ordered paid execution, fee claims) calls the `_scoped`
siblings with `GenerationScope::for_live`. Protected 0x64C0/0x64C1/0x64D5/
0x64D6 rows and the barrier are read only through typed ports, never
through the generic CAS fold. `committed-proof/` for T+1..h and the Seal
candidate/header/outcome/receipt keys (Section 6.3) are typed archive
writes outside this fold, exactly as `engine.rs:1973,2801` writes them
today for the outgoing epoch: they take no provenance and are asserted
must-absent, never folded as dependencies.

## 5. Epoch-scoped consensus safety state

Five chain-only families are live mutable signing safety: `state/`
(`OrderedStatus`, `crates/node-core/src/ordered_economics/engine.rs:430-460`),
`applied-height/` (`:484`), and in
`crates/node-core/src/ordered_economics/identity.rs:41-61`
`leader-proposal/<chain><view>`, `vote/<chain><view>` (first-writer-wins
per view) and the `vote-high/<chain>` watermark that
`reconcile_local_vote` (`:282-333`) enforces. Each gets an e+1 counterpart
through an opaque `pub(crate) struct OrderedKeyScope(KeyScope)`, whose
`enum KeyScope { Chain, Successor { protocol, epoch, anchor } }` is
private to `policy.rs`. The key builders in `identity.rs` and `engine.rs`
take `&OrderedKeyScope` and call only its read-only selectors (the bytes a
builder appends); they never match on `KeyScope` directly, so no other
module can name it. `OrderedEconomicsPolicy`'s three constructors are the
only producers: `from_successor` (Section 9) builds `Successor` from its
verified `SuccessorPolicyInputs`; `from_genesis_root` and `historical`
build `Chain`. The v3 anchor hash itself
(`ordered_economics_authority_anchor`) only computes a digest from given
inputs; it never selects or inspects a scope, so every existing key byte
is unchanged. Layout: `PREFIX || infix ||
encode_chain_id(chain) || protocol u32 BE || epoch u64 BE ||
encode_digest32(v3_anchor) [|| view u64 BE]`, checked by
`validate_transactional_state_key`. Infixes: `epoch-state/`,
`epoch-applied-height/`, `epoch-vote-high/` (no view) and
`epoch-leader-proposal/`, `epoch-vote/` (view). No existing infix starts
with `epoch-` and `epoch-vote-high/` does not start with `epoch-vote/`.

`classify_ordered_row` (`crates/node-core/src/logical_generation.rs:724`)
gains exactly these five literals in `CONTROL`. Its existing lists
(`CONTROL` = `state/`, `applied-height/`, `candidate/`; `HISTORY`;
`LOCAL_PROGRESS`) are unchanged; the chain-only identity families and
`committed-proof/` stay unclassified exactly as today.

Exactly three singleton roots exist: `epoch-state/`,
`epoch-applied-height/`, `epoch-vote-high/`. Activation asserts all three
absent at `StateRevision::INITIAL` and writes only `epoch-state/` with the
successor engine `genesis_state(now)`; the other two stay virgin, which
the existing readers interpret as applied height 0 and no watermark. A
tombstone or any other revision refuses. Per-view rows have no singleton
root and are never installed. They cannot pre-exist because: the full
`observe_complete` proves every destination state row equals the plan;
plan rows come from independent re-execution and Section 3 step 7 refuses
any `epoch-` row; and the in-lock token sequence check (Section 6.4)
proves no write occurred after that observation.

All imported chain-only rows through T -- `state/`, `applied-height/`,
`vote-high/`, `committed-proof/`, `candidate/`, `header/`, `outcome/`,
receipts -- are retained byte-exact with unchanged classification and are
never written in a target. `audit_projection.rs` and cut capture refuse
any `epoch-` infix; a cut of a successor store is out of scope.

## 6. Atomic target activation

### 6.1 Runtime types and ports

```rust
// runtime crate
pub struct SuccessorServingObservation {
    pub record: Vec<u8>,          // exact 0x64D5
    pub binding: ImportBinding,
    pub progress: ImportProgress,
}
pub enum SuccessorServingSlot { Inactive, Serving(SuccessorServingObservation) }

// DurableDomainStateStore, required, no default:
fn get_successor_serving(
    &self,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<SuccessorServingSlot, DurableReadError>;

// StructuredStateReader, required, no default; the existing blanket
// forwarding implementation delegates to get_successor_serving:
fn read_successor_serving(
    &self,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<SuccessorServingSlot, DurableReadError>;

// StructuredDurableDomainStateStore, like outgoing_seal_repository:
fn successor_serving_repository(&self) -> Option<&dyn SuccessorServingRepository> {
    None
}

pub trait SuccessorServingRepository: InactiveImportRepository {
    fn read_namespace_validator(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError>;
    #[allow(clippy::too_many_arguments)]
    fn commit_successor_activation(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        record: &[u8],
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome;
    fn commit_successor_durable(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome;
    fn commit_successor_invocation(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome;
}
```

The observation is raw continuity data, never authority. The physical
namespace validator is the persisted `durable_metadata.validator_id`
(`crates/runtime-sql-durable/src/schema.rs:62-117`), which open already
binds to `SqlDurableNamespace::validator_id`. Memory exposes the repository
only from a new `MemoryDurableStateStore::new_successor_bound(domain,
validator, fence)` that stores that id explicitly; every other memory
constructor, PostgreSQL and Durable Object return `None`. The logical
registered authorization key is the `FastPathBondRecord.authorization_key`
at `fastpath_bond_record_key(chain, id)`, read only by core.

The generic `commit_durable`/`commit_invocation`
(`crates/runtime-sql-durable/src/engine.rs:1423,1529`) keep their
`!is_ordinary()` refusal and add one in-lock check, slot `Inactive`.

### 6.2 Core producer

```rust
pub fn activate_successor<S, B>(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
    destination: &S,
    destination_blobs: &B,
    operation: &DurableOperationContext,
    signer: &ReadinessSigningKey,
    now_unix_millis: u64,
) -> Result<SuccessorActivationOutcome, SuccessorActivationError>
where
    S: StructuredDurableDomainStateStore + InactiveImportRepository,
    B: PortableBlobRepository;

pub enum SuccessorActivationOutcome {
    Activated { subject: Digest32, manifest: Digest32 },
    AlreadyActivated { subject: Digest32, manifest: Digest32 },
}
```

`ReadinessSigningKey` (`crates/node-core/src/conditional_readiness.rs:38`)
is reused as is and signs nothing here. Steps, all before any write:

1. `verify_successor_activation` in full (Section 3).
2. `get_successor_serving`: `Serving` goes to Section 7; `Inactive`
   continues.
3. `observe_complete(destination, destination_blobs, operation)`
   (`inactive_import.rs:326`) in full, returning `(progress, token)`.
4. `repository = destination.successor_serving_repository()` or refuse
   `Unsupported`; `id = repository.read_namespace_validator(..)`; require
   `id == signer.validator_id()`, `id` a member of the verified e+1 set,
   member scheme Ed25519 and `member.public_key == signer.public_key()`;
   read the bond row at `fastpath_bond_record_key(chain, id)` through the
   destination, require `Active` and `authorization_key ==
   member.public_key`, and keep its revision as a CAS read.
5. Construct the `ActivationWarrant` and `GenerationScope::for_activation`.
6. Build and preflight the transaction (6.3) and the 0x64D5 record (field
   5 = the step 3 token, field 7 = `id`, field 8 = the signer key), then
   call `commit_successor_activation`.
7. Map `Committed` to `Activated`, `Rejected(r)` to an error carrying `r`.
   On `Indeterminate`, re-read the slot: `Serving` with a record
   byte-equal to the one just built is `Activated`; anything else is an
   indeterminate error.

### 6.3 Activation transaction and preflight

One `DurableInvocationTransaction` contains:

- CAS reads at observed revisions: the `FastPathEpochRecord` key (value
  `current_epoch == e`), `paid_fee_policy_key(ctx@e)`, the local bond key,
  and every other read `derive_scoped` folds.
- Must-absent reads (`StateRevision::INITIAL`, no value):
  `fastpath_validator_set_key(ctx@e+1)`,
  `fastpath_epoch_transition_key(chain, e+1)`, the three e+1 policy keys
  and their three provenance keys, the three singleton roots of Section 5,
  `committed-proof/(chain, e, k)` for k = T+1..h, and the Seal
  `candidate/`, `header/` and `outcome/` keys.
- Puts: the e+1 validator-set, execution, paid-fee and publication rows
  from `derive_activation_set` over the verified members; the three
  provenance rows; `FastPathEpochRecord { current_epoch: e+1,
  current_validator_set_digest: verified subject field 11,
  previous_epoch: Some(e), activated_at_checkpoint: h }` encoded by the
  existing owning codec; `epoch-state/`; `committed-proof/(chain, e, k)`
  for k = T+1..h with the exact verified CommitProof bytes (empty heights
  carry only that component); the exact Seal Candidate, RequestHeader and
  RetainedOutcome bytes at their keys.
- Receipt: `DurableRequestReceipt::new(seal request id, event digest,
  exact OriginalReceipt bytes)` -- the original Seal receipt, never a
  synthesized activation receipt.
- No object changes and no outbox.

Not written: `epoch-applied-height/`, `epoch-vote-high/`, any per-view
row, any chain-only row, any row at or below T. Imported T rows, including
the committed proof at T, stay byte-exact even when the history export
carries an equivalent QC variant for T.

Preflight builds the complete transaction through the existing
constructors before any write: at most `MAX_ATOMIC_STATE_READS` (4096)
reads and `MAX_ATOMIC_STATE_WRITES` (4096) writes
(`crates/runtime/src/lib.rs:243-246`), keys within `MAX_STATE_KEY_BYTES`,
each value within `MAX_STATE_VALUE_BYTES` (32 MiB), the receipt within
`MAX_DURABLE_RECEIPT_BYTES`, and the whole envelope -- domain, receipt,
state, objects -- within `MAX_ATOMIC_STATE_TRANSACTION_BYTES` (64 MiB) as
`DurableInvocationTransaction::new` computes it; the record within 16 KiB.
Count every actual staged assertion and mutation, including provenance
dependency reads; do not substitute an estimated suffix-length formula. Any constructor
failure returns `SuccessorActivationError::ActivationTooLarge` before the
port call. All rows are inline, so no blob is published first. This is no
new consensus validity limit and never a partial install; a larger
suffix needs a separately reviewed producer.

### 6.4 In-lock checks of `commit_successor_activation`

In one backend transaction, in order, refusing with `Rejected` and no
write on any failure:

1. Writer fence active and deadline not passed; `domain` is the bound
   domain and namespace.
2. `fresh_token.check(namespace, domain, fence, current mutation
   sequence)` -- no write since `observe_complete`.
3. Lifecycle `CompleteInactive` with byte-exact `binding` and `progress`.
4. Outgoing barrier `Unsealed`.
5. Slot `Inactive`.
6. Record decodes as 0x64D5; field 3 and 4 equal the encoded binding and
   progress; field 5 decodes to exactly `fresh_token`; field 7 equals the
   persisted namespace validator.
7. Transaction domain equals `domain`; object changes empty; outbox
   absent; no receipt exists for its request id.
8. Every state read assertion holds.

Then, atomically: all mutations, the receipt, slot `Inactive ->
Serving(record)`, and one mutation-sequence advance.

### 6.5 In-lock checks of later successor commits

`commit_successor_durable` and `commit_successor_invocation` check fence,
deadline and domain; lifecycle `CompleteInactive` with binding and
progress byte-equal to the observation; barrier `Unsealed`; slot `Serving`
with record bytes equal to `observation.record`; record field 7 equal to
the namespace validator. Then they apply the existing read, receipt,
object and outbox checks of `commit_durable`/`commit_invocation` and
commit. This is raw continuity only; cryptographic and membership
authority stays in core.

## 7. Reconciliation

`activate_successor` re-reads the slot first:

- **Inactive** -- run Sections 3 and 6 in full; a lost earlier attempt left
  nothing to reuse.
- **Serving(record)** -- rerun Section 3 in full; require record fields
  1-4 and 6 to equal the verified subject digest, manifest digest,
  binding, progress and anchor, field 7 the namespace validator, field 8
  the signer key and the member key. Field 5 is only decoded as 0x64D2;
  a used token is never compared with a fresh one (DR-0178 retry rule).
  Compare the installed Seal closure rows (proofs T+1..h, Seal candidate,
  header, outcome, receipt) and the four e+1 rows byte-for-byte with the
  verified evidence, and require the installed `FastPathEpochRecord` to
  equal exactly `{current_epoch: e+1, current_validator_set_digest:
  verified subject field 11, previous_epoch: Some(e),
  activated_at_checkpoint: h}`, not `current_epoch` alone. Each history
  proof variant is re-verified cryptographically by
  Section 3, and the installed bytes must be the variant this host
  verified. Never compare advanced business inventory or the values of the
  singleton safety rows, and never write. Return `AlreadyActivated`.
- **A different record** -- refuse; no overwrite or repair.

## 8. Per-invocation serving authority

```rust
pub fn resolve_live_authority<'inv, S: StructuredDurableDomainStateStore>(
    store: &'inv S,
    context: &'inv DurableOperationContext,
    domain: AtomicityDomainId,
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
    signer_public_key: [u8; 32],
) -> Result<LiveAuthority<'inv>, ServingAuthorityError>;

pub enum LiveAuthority<'inv> { OriginalGenesis, Successor(LiveWarrant<'inv>) }
```

`LiveWarrant` has private fields and exposes the crate-private
`generation_scope()` (returning the crate-private `GenerationScope`),
`policy_inputs() -> &SuccessorPolicyInputs` (Section 9: e+1 context,
`ValidatorSet`, v3 anchor, binding floor -- source-free only, no local
member), `serving_observation()` and `reads()`. The destination's local
namespace validator/key is a separate, warrant-only fact, never part of
`SuccessorPolicyInputs`; it is read fresh at each check below, not cached
on the warrant. It is tied to the store borrow and never stored past the
call. Decision:

- `Ordinary` and `Unsealed` and slot `Inactive` -> `OriginalGenesis`;
  existing behavior and gates unchanged.
- `CompleteInactive` and `Unsealed` and `Serving(observation)` ->
  1. observation binding/progress equal the lifecycle binding/progress;
  2. `verify_successor_activation` reruns in full;
  3. record fields 1-4 and 6 equal the verified subject digest, manifest
     digest, binding, progress and anchor; field 5 decodes;
  4. `read_namespace_validator` equals field 7, which is a verified e+1
     member whose key equals field 8 and `signer_public_key`;
  5. CAS reads that become `reads()`: `fastpath_validator_set_key(ctx@e+1)`
     equal to the verified set record; the three e+1 policy rows equal to a
     fresh `derive_activation_set` over the verified members; the imported
     `paid_fee_policy_key(ctx@e)` row itself, included in this CAS read set
     as a real deciding dependency, not merely the immutable-closure
     inspection of step 6; and
     `FastPathEpochRecord` equal to exactly `{current_epoch: e+1,
     current_validator_set_digest: verified subject field 11,
     previous_epoch: Some(e), activated_at_checkpoint: h}`. The local bond
     row is checked only at activation (Section 6.2 step 4); live
     resolution relies on the fixed e+1 committee membership this step
     already re-verifies, matching current non-successor behavior;
  6. fenced exact reads of the immutable Seal closure rows (proofs
     T+1..h, Seal candidate/header/outcome, Seal receipt) equal to the
     verified bytes. They are not added to every CAS set: no e+1 path
     writes an epoch-e proof key or a Seal-keyed row, and e+1 candidates use
     distinct digests and request ids under INITIAL CAS.
- Anything else refuses; `Ordinary` with `Serving` is corruption.

Each step reruns on every request, with the cost stated in Section 3.2.
`NamespaceLifecycle::is_ordinary()`, `require_ordinary_namespace` and
`require_ordinary_reader_namespace`
(`crates/node-core/src/mutation_fence.rs:60,82`) and the generic commit
ports stay unchanged, so an unmigrated call site keeps refusing a
successor store.

Migrated `_successor` entries, each taking `&LiveWarrant`: ordered
proposal, vote, vote-high and applied-prefix retention (through
`OrderedEconomicsPolicy::from_successor` and its internal `Successor` key
scope);
FastVote prepare and ACK (`load_validator_set` at ctx@e+1); paid
evaluation and fee claims (`GenerationScope::for_live`); receipt exposure;
and native-http cached-signature exposure. Each folds `warrant.reads()`
into its CAS read set and commits only through
`commit_successor_durable`/`commit_successor_invocation` with
`warrant.serving_observation()`. Cached FastVote, ordered, ACK and
frontier exposure resolves a fresh warrant per request and requires
message epoch == warrant epoch and message key scope == warrant anchor;
no startup-time check substitutes. On receipt and query routes,
original-receipt replay runs before ordinary authority or object work;
the original Seal receipt is replayed through the receipt route, not by
resubmitting an epoch-e candidate to the epoch-e+1 pure authenticator.

At `Successor` authority, readiness (new and retained),
Freeze/DrainSet/Seal, initial registration, `install_ordered_genesis` and
legacy `activate` refuse with a typed error before any signing. Candidate
kinds are refused in `authenticate_with_policy` (Section 9), and the other
controls at their entry points. Readiness signing/retention check the
protected Serving slot first and return the corresponding
`ConditionalReadinessError::UnsupportedSuccessorControl` before new or
retained exposure, not an incidental inventory or token mismatch.
Historical read-only open, export and query stay legal and may relay the
Seal and its QCs without signing.

## 9. Ordered and FastVote policy at e+1

`OrderedEconomicsPolicy::from_successor(root, inputs:
&SuccessorPolicyInputs)` is a third constructor beside `from_genesis_root`
and `historical` (`crates/node-core/src/ordered_economics/policy.rs:149,183`).

```rust
pub struct SuccessorPolicyInputs { /* private fields */ }
impl SuccessorPolicyInputs {
    pub fn context(&self) -> &PublicationContext;   // ctx@e+1
    pub fn domain(&self) -> AtomicityDomainId;       // verified plan domain
    pub fn subject_digest(&self) -> Digest32;        // 0xD054, v3 field 10
    pub fn genesis_digest(&self) -> Digest32;        // original, unchanged
    pub fn validator_set(&self) -> &ValidatorSet;    // checked e+1 set
    pub fn anchor(&self) -> Digest32;                 // v3 anchor
    pub fn generation_floor(&self) -> ExecutionGeneration;
}
```

`SuccessorPolicyInputs` has no public or `pub(crate)` constructor and no
`Default`/serde. Its fields are private to `serving_authority`; the private
verifier constructs it from verified evidence and retains it in that
evidence. `ActivationWarrant::policy_inputs()`,
`LiveWarrant::policy_inputs()` and
`VerifiedSuccessorAuthority::policy_inputs()` (Section 3.2) return shared
read-only references to those same verified inputs, never raw constructors.
It holds only
these source-free facts -- never a local validator id or key: the SDK has
no local key, and both warrants keep the destination's local member on a
separate, warrant-only accessor, not on this shared struct. It is the only
input that selects the internal `Successor` key scope. A reviewed extension
of `ordered_economics_authority_anchor` itself accepts the v3 inputs;
genesis policies keep byte-identical v1/v2 anchors and keys. No
caller-supplied epoch or `epoch-repin-required` hint selects a policy.

`from_successor` takes its domain only from `inputs.domain()`. It refuses
unless the supplied root digest equals `inputs.genesis_digest()` and the
root chain and protocol equal those of `inputs.context()` (the root epoch
stays original; the successor epoch is independently verified). It
recomputes the v3 anchor through the owning extended anchor function with
the root resolver, verified context/domain/genesis/set, the original
signed minimum Freeze height and `inputs.subject_digest()`, and refuses
unless it equals `inputs.anchor()`. It accepts no separate domain or epoch
argument. The returned policy carries
`admission_profile = Some(root.admission_profile().clone())`, the original
verified causal profile, so `fence_policy` still fences against the imported
installed profile and external-request lane and causal-prerequisite checks
still apply. It carries
`minimum_freeze_block_height = root.manifest().minimum_freeze_block_height`,
the original signed value bound into v3 anchor field 9. Only
`registration_economics` is `None`. The retained profile and Freeze height
would pass `authenticate_freeze`, `authenticate_drain_set` and
`authenticate_seal`, so the refusal is in the one shared pure chokepoint,
not individual candidate call sites: `authenticate_with_policy`
(`ordered_economics/policy.rs:680`), as its first check before context,
lane or kind-specific authentication. It refuses
`OrderedOperationKind::{Freeze, DrainSet, Seal, BondRegistration}` with a
new typed `OrderedEconomicsError::UnsupportedSuccessorControl` whenever
the policy's private `OrderedKeyScope` is `Successor`. This is a
crate-private read-only selector, so no caller flag skips it. Proposal,
vote, committed-block preview/apply, reservation and native-http admission
all reach this function through `authenticate_candidate`; an honest
successor replica therefore never signs, votes for or applies such a
candidate. `Chain`-scope policies, including the epoch-e history verifier
(`ordered_history.rs:319`), are unchanged. Non-candidate controls
(readiness signing, `install_ordered_genesis`, legacy `activate`, frontier
and drain publication) refuse at their entry points with a corresponding
typed unsupported-control error; existing ordinary-namespace guards remain
where present. Readiness has the explicit Serving-slot check of Section 8.
A missing profile is not an authorization gate.

FastVote reuses `load_validator_set` at ctx@e+1 against the installed row.
The SDK gains `load_successor_authority(plan, manifest_identity,
artifacts)`, a thin wrapper over the public
`node_core::verify_successor_authority` (Section 3.2) -- `clients/rust` is
a separate crate and cannot call a `pub(crate)` item, so this is the one
entry point the SDK uses, never `verify_successor_activation` directly --
and authenticates the e+1 set itself rather than trusting a destination
claim.

## 10. New-epoch business admission

The e+1 anchor and safety namespace are not a replacement genesis and do
not change historical object, code or instance provenance.
`paid_execution.rs` checks only `chain_id` and `protocol_version` of a
called instance context (`crates/node-core/src/paid_execution.rs:1438-1439`),
so a paid `Call` on an epoch-e instance admits at e+1 unchanged. Fee claims
verify at their own `certificate_epoch`
(`crates/node-core/src/fee_claims.rs:1119`), so an imported epoch-e escrow
needs no re-signing. This contract adds no check to either path.

A retired validator D is refused only as a consensus signer, by the
membership checks of Sections 6.2 and 8 and the pre-signing refusals.
Ordinary signed-sender requests of D, including
`BondLifecycleOperation::Withdraw`
(`crates/node-core/src/bond_lifecycle.rs:218`), are unaffected; unlock
remains separate work (Section 15).

## 11. Storage schema

| Store | Change |
| --- | --- |
| Shared SQL | `SQL_DURABLE_SCHEMA_IDENTITY` (`crates/runtime-sql-durable/src/schema.rs:36`) v5 -> v6: mandatory `durable_successor_serving(id = 1 CHECK, serving BLOB <= 17408)` created `Inactive` with every namespace. Read phase and length before the body. |
| Native SQLite | `STRUCTURED_SCHEMA_VERSION` (`crates/runtime-sqlite/src/structured.rs:56`) 4 -> 5; implements `SuccessorServingRepository`; ordinary `open` still refuses import origin. |
| Memory | Mandatory `Inactive` slot; repository only via `new_successor_bound`. |
| PostgreSQL | `POSTGRES_SCHEMA_GENERATION` (`crates/runtime-postgres/src/lib.rs:71`) 6 -> 7 with a real mandatory `Inactive` row read by `read_successor_serving`, the generic-port slot check, and no repository. The full selected PG gate (DR-0172) is required. |
| Durable Object / other | Shared DDL only; no repository. |

Older initialized files are unsupported: no migration, repair or reset.
`get_successor_serving` and its `read_successor_serving` reader counterpart
have no default on any store.

## 12. Executables and workflows

- `apps/operator/src/bin/successor_activation.rs`: pinned genesis and
  digest, schedule, domain, saved-cut directory, history export,
  certificate file, target SQLite file and local key file; runs
  `activate_successor` and prints the subject and manifest digests.
- `apps/operator/src/bin/successor_host.rs`: loopback only (`127.0.0.1` or
  `::1`, anything else refused before listening); pins genesis and
  schedule, owns its writer fence and artifact source, and serves the
  existing native-http ordered/FastVote/paid/claim/receipt/query routes
  through `resolve_live_authority` on every request.
- The Seal suffix is exported with the existing `cli history_export` from
  the historical read-only open of the Sealed source (DR-0187).
- Workflows reuse `ordered_economics_network`, `fastvote_network` and
  `paid_execution`, fed by `load_successor_authority`.

## 13. Operational scope and fault model

- **One key activated into two successor namespaces.** The virgin checks
  prove only that one namespace never signed. Preventing reuse is
  operational key custody; detection is the existing equivocation path
  (`crates/node-core/src/equivocation.rs`) once conflicting messages are
  observed.
- **Whole-database rollback** to a pre-activation state is undetectable by
  CAS or fencing without an independent external anchor, as in
  DR-0178/DR-0187.

One controlled key and namespace per predecessor member and an independent
anchor are operational preconditions; software does not enforce them.

## 14. Acceptance unit

**Genuine flow:** the PR #265 A/B/C/D Seal over TCP -> A/B/C/E SQLite
staging with genuine E registration (DR-0179) -> four
`successor_activation` runs -> four `successor_host` processes -> CLI over
TCP. Required: e+1 ordered and FastVote quorum; new paid `Instantiate` and
`Call`, including a `Call` on an epoch-e instance; a fee claim against an
imported escrow; byte-equal replay of the Seal and other original receipts.

**Negatives:** D refused for activation and votes but not `Withdraw`;
e-epoch votes, QCs and legacy transition certificates refused at e+1;
wrong subject, manifest, certificate digest or variant, or history; a
non-terminal or extra Seal; T mismatch; broken h-1 child link; ineligible
set; namespace validator, signer or bond key mismatch; memory store
without `new_successor_bound`; bad pins or schedule; a repin hint; a
caller-supplied context or flag; `Ordinary` with `Serving`; a planted
`epoch-vote/` or `epoch-` row in plan or destination; a tombstoned or
non-INITIAL singleton root; a token advanced after `observe_complete`; a
present receipt or must-absent row; an oversized suffix refused whole with
no write; an e+1 policy row without provenance; tampered Seal closure or
e+1 rows at live resolution; cached-signature exposure with a stale scope;
successor-scoped Freeze, DrainSet, Seal and BondRegistration candidates refused by the typed
unsupported-control error before authentication or signing, not by a
missing admission profile.
Both vote validation of a leader proposal containing any of those four
candidate kinds and committed-block preview containing one must return
`UnsupportedSuccessorControl`, not `Unauthenticated`, with no signature
or state mutation.

**Durability and races:** SQLite restart and refencing; stale fence and
token; inventory race between plan comparison and commit; both reply-loss
directions, including `Indeterminate` reconciliation; corrupt or missing
slot and artifacts; signer counters zero before `Serving`; non-loopback
bind refused.

**Vectors:** independent stable vectors for 0xD054, 0xD055, 0x64D5, 0x64D6
and the v3 anchor, plus a generation-floor versus genesis-floor pair. Older
vectors unchanged.

**Gate:** `npm ci --prefix adapters/cloudflare-workers` and
`./scripts/check-all.sh`, plus the full selected PG acceptance for the
schema change (DR-0172).

## 15. Out of scope

Recurring Freeze/DrainSet/Seal and a second successor; e+1 governance
changes to the installed policy rows; genuine `Unbond`/`Withdraw` unlock
for D; PostgreSQL or Durable Object activation; public readiness
production; independent security audit; Delivery 3. Design acceptance is
not completion of these deferred outcomes or of the implementation.
