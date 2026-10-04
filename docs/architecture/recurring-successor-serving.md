# Recurring successor serving

This is the **Accepted pre-code** design contract of
[DR-0191](decisions/0191-recurring-successor-serving.md). It extends, without
rewriting, the accepted [first successor serving](first-successor-serving.md)
([DR-0189](decisions/0189-first-successor-serving.md)) and
[first-epoch ordered Seal](ordered-seal.md)
([DR-0187](decisions/0187-first-epoch-ordered-seal.md)) contracts from one
link to an ordered chain of links. Fresh independent Opus approved the design
at `5ee07de` on 2026-10-04, with the implementation clarifications below. It
authorizes implementation, not serving or deployment. Current status belongs
only in [TODO.md](../../TODO.md). Source
references are to `1b86d4a`.

## 1. Model and fixed invariants

Link k moves epoch e_k to e_{k+1}. Link 0 is exactly the DR-0189 link from
the signed genesis epoch e_0. On each member host, epoch e_k is served by its
own namespace N_k. N_0 is the ordinary original. N_{k+1} is a fresh target:
it starts with the genuine staged import of the e_k cut under its own writer
fence, and the existing `commit_successor_activation` activates it.

- **Bytes unchanged.** Tag-1 0xD050-0xD055 bytes, the v3 anchor,
  0x64D3/0x64D4/0x64D5/0x64D6, every key family and every stable vector stay
  as they are. Only SealIntent predecessor tag 2 is new (Section 9).
- **Existing consumers preserved.** Existing single-link signatures, supported
  operations and accepted bytes are preserved. The explicitly described new
  successor controls are a deliberate feature extension, not a requirement to
  preserve an unreleased unsupported-feature refusal through a second engine.
  Recurring entry points are additive (Section 7).
- **Guards unchanged.** `require_ordinary_namespace`,
  `OutgoingSealRepository` and the generic commit ports are not widened.
  PostgreSQL and Durable Objects expose no successor repository and stay
  unsupported for successor activation, serving and Seal.
- **Origin and outgoing safety are permanent.** N_k keeps `CompleteInactive`
  and its S_k safety rows forever; after its Seal the barrier stays Sealed.
  Nothing is re-genesised, renamed, repaired or deleted.
- **Original host reused.** The accepted SQLite composition that dispatches
  the e_0 Seal (`apps/operator/src/ordered_seal.rs`, `source_sqlite.rs`) is
  reused unchanged. Only the successor branch is added.
- **No new machinery.** No daemon, cache, trusted checkpoint or epoch reset.
  Evidence is reverified in full on every invocation (DR-0189 Section 8).

## 2. One verified chain owner

The new private module `node-core::serving_authority::chain` is the only
constructor of chain evidence. Each link runs the single private DR-0189
verifier body (`verify.rs:414`), parameterized by a base. It is not a second
engine.

```rust
/// Local resource budget, not a consensus rule. Exceeding it refuses before
/// any artifact access; it never truncates, skips or resets the chain.
pub struct SuccessorChainBudget(NonZeroU32);
impl SuccessorChainBudget {
    pub const fn new(max_links: NonZeroU32) -> Self;
    pub const fn get(self) -> u32;
}
/// Untrusted operator pins for one link, supplied in link order.
pub struct SuccessorLinkPins {
    pub cut_identity: OrderedHistoryIdentity,      // e_k history through T_k
    pub manifest_identity: OrderedHistoryIdentity, // e_k history through h_k
}
/// Untrusted per-link transport. The verifier lends the privately derived
/// read-only link plan or policy so archive readers can decode; every
/// returned value is still a claim.
pub trait SuccessorChainArtifacts {
    fn saved_business_cut(&mut self, link: u32, plan: &BusinessReconstructionPlan<'_>)
        -> Result<SavedBusinessCut, SuccessorArtifactError>;
    fn history_height(&mut self, link: u32, policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity, height: u64)
        -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError>;
    fn readiness_certificate(&mut self, link: u32, length: u32)
        -> Result<Vec<u8>, SuccessorArtifactError>;
}
// New SuccessorActivationError variant: ChainBudgetExceeded { links: usize, budget: u32 }

struct VerifiedSuccessorChain {           // private; no Clone/Default/serde
    links: Vec<VerifiedSuccessorActivation>, // 1..=budget; last is current
    committees: VerifiedCommitteeHistory,
    owners: VerifiedOwnerRegistry,
}
enum CommitteeProvenance { Genesis, Link { index: u32, subject_digest: Digest32 } }
pub(crate) struct VerifiedCommitteeHistory { // private fields; built only in chain.rs
    by_epoch: BTreeMap<Epoch, (ValidatorSet, Digest32, CommitteeProvenance)>,
}
enum OwnerProvenance {
    Genesis { genesis_digest: Digest32 },             // signed manifest validator
    Registration { anchor_epoch: Epoch,               // anchor.context epoch
                   intent_digest: Digest32,           // bond_registration_intent_digest
                   initial_row_digest: Digest32 },    // signed expected_initial_row_digest
}
pub(crate) struct OwnerEntry { validator_id: ValidatorId, scheme: SignatureSchemeId,
                               key: [u8; 32], provenance: OwnerProvenance }
pub(crate) struct VerifiedOwnerRegistry {    // private fields; built only in chain.rs
    by_id: BTreeMap<ValidatorId, OwnerEntry>, by_key: BTreeMap<[u8; 32], ValidatorId>,
}
struct LinkInputs { ordered_policy: OrderedEconomicsPolicy,   // owned per iteration
                    leg_policy: LocalExecutionPolicy, paid_policy: LocalExecutionPolicy }
```

**Fold.** `verify_chain(plan, pins, budget, artifacts)`:

1. Require `pins.len()` in `1..=budget` before any artifact call. A counting
   transport proves zero calls on refusal.
2. Require `pins[0].cut_identity == plan.ordered_history_identity` byte for
   byte. Link 0 runs on the genesis base with the caller plan, as today.
3. For each k >= 1: derive owned `LinkInputs` from `&links[k-1]`; build a
   `BusinessReconstructionPlan` borrowing them and `pins[k].cut_identity`
   (root, operation context, domain, resolver history and both engines come
   from the caller plan); build `ReconstructionBase::successor` over
   `&links[k-1]`; call `verify_link(base, plan, &pins[k], adapter(k))`. It
   returns an owned activation that borrows nothing. Append link k committee
   and owner entries, then push. Borrows end before the push, so there is no
   self-reference, recursion or `Vec` of trait objects.
4. Links must be contiguous: link k outgoing epoch is e_0 + k. A skipped,
   duplicated or reordered link refuses.

**Policy derivation.** Later plan policies are never caller-supplied.

- Link 0 uses the existing defining verifier's policy checks in both entry
  paths. A new wrapper must not introduce stricter first-link policy checks
  which make an existing supported first link unverifiable.
- Link k uses `generic_object_results(e_k)` for both, and the crate-private
  `OrderedEconomicsPolicy::from_successor_chain(root, inputs, committees,
  owners)` with `inputs = &links[k-1].policy_inputs`. It runs the
  `from_successor` body, except that its genesis-only predecessor block
  (`policy.rs:348-360`) becomes a scoped verified-predecessor check:
  - the predecessor epoch is `inputs.context.epoch() - 1` (checked);
  - the predecessor committee comes from `committees` at that epoch;
  - its digest must equal `inputs.predecessor_set_digest()`.
  For one link this is exactly the current check against the genesis
  committee.
- The policy keeps the verified subject digest in a new private field,
  `successor_subject: Option<Digest32>`. It is the value `build` already
  receives, and the tag-2 chokepoint compares against it. The key scope bytes
  are unchanged.
- Both engines are borrowed once from the caller plan; they are
  deterministic and hold no state across links.
- `BusinessReconstructionPlan` is unchanged, so public literal construction
  still compiles. The base is a separate crate-private argument.

**Per-link rules** (base gives epoch e_k, committee C_k, anchor A_k):

- **Binding:** context e_k, `validator_set_digest = digest(C_k)`, the original
  genesis digest, the plan domain. Both pins carry e_k and A_k (the v2 anchor
  for k = 0, the v3 anchor produced by link k-1 otherwise).
- **Seal predecessor:** tag 1 with the genesis digest at k = 0 (unchanged);
  tag 2 with `links[k-1].subject_digest` at k >= 1. The readiness subject
  carries epoch e_k and outgoing set digest `digest(C_k)`.
- **History:** the existing `OrderedHistoryVerifier` with the link policy;
  Freeze, DrainSet, Seal and BondRegistration authenticate per Section 6.
- **Eligibility:** the existing `check_next_set_eligibility` over link k plan
  rows with `current_epoch = e_k`. **Plan rows:** Section 4.
- **Output:** exactly what `finish` produces today. Policy inputs carry
  context e_{k+1}, the link k binding floor and
  `predecessor_set_digest = digest(C_k)`.

**Provenance.** Committee history maps e_0 to `root.genesis_committee`
(Genesis) and e_{k+1} to link k certificate `next_set` after eligibility
(`Link{k, subject_k}`).

The owner registry starts with each genesis validator bond scheme and key
from the signed manifest. Then, in ascending anchor epoch and id order, each
`bond-registration/` anchor in link k plan rows is verified in **Existing**
mode (Section 6) and inserted with its full identity and digests.

Insertion rules:

- Re-encountering an anchor whose id, key and provenance are byte-identical
  is the same identity carried forward, not a conflict.
- Any other repeat of an id or key refuses.

Membership in a set never stands in for provenance.

## 3. Reconstruction base and scope-aware replay

```rust
pub(crate) struct ReconstructionBase<'c>(Base<'c>); // built only in chain.rs
enum Base<'c> {
    Genesis,                                     // today’s install, unchanged
    Successor { root: &'c VerifiedGenesisRoot,
                predecessor: &'c VerifiedSuccessorActivation, // link k-1
                committees: &'c VerifiedCommitteeHistory,
                owners: &'c VerifiedOwnerRegistry },
}
// Read-only: context() e_k, committee() C_k, anchor() A_k,
// current_scope() Chain or S_k, generation_floor().
```

New crate-private seams: `BusinessReconstructionOverlay::new_with_base`,
`verify_saved_business_import_with_base`, `derive_source_cut_with_base` and
`proof::verify_saved_with_base`. `new(plan)` becomes
`new_with_base(plan, Genesis)`. About forty direct reads of
`plan.genesis_root.manifest().context()` (projection, `cut/derive`,
`inactive_import` 384, `conditional_readiness` 213) move to
`base.context()`; the Genesis base returns the same value.
`plan.genesis_root` stays the original root for resolver, digest and signed
economics at every link.

**Successor bootstrap.** Generic `commit_invocation` cannot load a plan:

- every invocation needs its own receipt (`runtime/src/lib.rs:1941`);
- object versions must advance one step at a time (`lib.rs:1780`);
- a staged import ends non-Ordinary, and generic commits then refuse.

The runtime therefore owns one memory-only checked constructor:

```rust
impl MemoryDurableStateStore {
    /// Ordinary in-memory data fixture preloaded from checked import batches.
    /// Not a restore or authority constructor; successor capability is absent.
    #[doc(hidden)]
    pub fn new_bound_from_import_batches(
        binding: &ImportBinding, active_writer_fence: WriterFenceGeneration,
        batches: &[ImportBatch],
    ) -> Result<Self, DurableCommitRejection>;
}
```

It is `pub` only because core is another crate. What it does:

- Domain comes from `binding.domain`.
- Every batch must name `binding`.
- Progress must be continuous: the first `expected` is ordinal 0 with no
  previous digest, each `expected` equals the previous `next`, and the final
  `next_ordinal == binding.row_count`.
- Rows are validated and installed by the existing private
  `inactive_import/memory.rs` owners:
  - `validate_rows` checks the chain id, version provenance and conflicts;
  - `expected_head` checks heads against their versions;
  - `install_rows` writes state at revision 1, head revision FIRST, receipts
    exactly as given, and versions with their own provenance, checkpoint and
    payload.
  These are refactored to take domain and chain instead of an in-progress
  batch. `ImportBatch::new` already enforced per-batch count, locator order
  and byte limits.
- The resulting lifecycle is Ordinary, the barrier Unsealed, the slot
  Inactive, with no successor validator and no receipt beyond the plan
  receipt rows. The existing domain-bound memory `outgoing_seal_repository`
  getter remains `Some`, but `successor_serving_repository` is `None`.
  The private replay gate refuses Seal. All core Seal consumers resolve
  through `ServingGate::seal_port`; an architecture regression check forbids
  direct getter calls outside that owner in non-test core code. Port availability
  is not verified serving or Seal authority.

SQLite, PostgreSQL and Durable Objects gain nothing: there is no production
restore, no import-origin bypass, and no provider write capability.

Core calls it only from the private `ReconstructionBase` bootstrap:

1. **Plan.** Build the fixture from `links[k-1].import`, using its batches and
   binding. Put its referenced blobs into the overlay `MemoryBlobStore`
   through `put_blob`.
2. **Activation rows.** One private
   `activation_mutations(root, evidence, reader, now)` is shared with
   `activation_transaction` so the two cannot drift. Here it reads through
   the fixture as a `VersionedStateReader` over exactly the plan rows; that
   covers `derive_activation_set`, `fence_commitment_profile`,
   `derive_scoped`, `provenance_mutations_scoped` and the outgoing-epoch
   check. It returns:
   - the four e_k set and policy rows, the e_k epoch record and the Logical
     provenance rows;
   - the suffix proofs and the Seal candidate, header and outcome;
   - the S_k epoch-state root with `now = 0`, as genesis install uses 0;
   - the real Seal receipt.
   Their reads are checked, then discarded. No local-bond read, namespace
   validator or key is consulted. One `commit_invocation` applies exactly
   these mutations and that single real receipt, with no object changes.
3. **Postcondition.** Capture the overlay with `capture_import_target`. Its
   `raw_rows(&snapshot, false)` must equal the plan rows merged in locator
   order with the activation mutations and Seal receipt. An activation Put
   replaces the prior plan State row at the same key; it never creates a
   second row or silently keeps the old epoch value. Referenced blobs must
   equal the plan blobs.
   - This is the existing logical equality of `verify_prefix`
     (`inactive_import.rs:291`).
   - It excludes only physical state revisions and head revisions.
   - Values, tombstones, receipts (event digest and bytes), heads, and full
     version records (digest, schema, provenance, created checkpoint,
     payload) all compare.

Never installed: a Serving slot, a 0x64D5 record, a CompleteInactive
lifecycle, a namespace validator, a local key or a local bond revision. The
link k-1 import origin travels only as its typed `ImportBinding` in the
base.

**Replay gate.** New variant `ServingGate::Replay(&'w ReplayScope<'w>)`:

```rust
pub(crate) struct ReplayScope<'o> {   // private fields; no Clone/Default/serde
    issuer: &'o MemoryDurableStateStore, context: &'o DurableOperationContext,
    domain: AtomicityDomainId, floor: ExecutionGeneration, // link k-1 floor
    committees: &'o VerifiedCommitteeHistory, owners: &'o VerifiedOwnerRegistry,
}
```

`BusinessReconstructionOverlay` owns its private `store` and the
`ReconstructionBase` it was built with.

- **Minting.** A private overlay method mints a fresh `ReplayScope` for each
  replay call, from `&self.store` (store methods take `&self`) and the base
  floor, committees and owners.
- **Lifetime.** The scope lives only inside that call. It is dropped before
  any `&mut self` progress update, so no long-lived borrow conflicts with
  overlay mutation.
- **Visibility.** No other constructor exists, and the scope is not
  exportable.

| Gate method | Replay behavior |
| --- | --- |
| `require_live`, `require_origin`, `require_reader` | Address identity with `issuer`; same context and domain |
| `require_local_signer` | Always refuses; replay never signs |
| `generation_scope` | `Successor{floor}` |
| `predecessor_certificate_anchor` | Typed digest of any verified epoch below e_k |
| `commit_durable`, `commit_invocation` | Issuer generic memory ports after `require_issuer` |
| Seal retention and completion | Refused; `verify_suffix` verifies the e_k Seal, it is never replayed |

The existing handlers, evaluators and economics run unchanged under this
gate; only their source of guard, floor and port changes, as with DR-0189
`Original`/`Successor`. The generic consensus-state install
(`engine.rs:1043`) keeps refusing successor scope; replay reads the
bootstrapped S_k root. No public function turns caller rows, readers or
decoded records into a base, scope or warrant.

## 4. Scope classification: earlier history is retained

Every ordered row in a capture, plan or overlay is classified by its owning
scope:

- the five live safety families (state, applied-height, vote-high,
  leader-proposal, vote) by key scope bytes: no suffix is Chain, protocol,
  epoch and anchor bytes are S_j;
- chain-literal archive families (candidate/, header/, outcome/, freeze/,
  drain-set/, committed proofs, closure) by decoded context epoch;
- epoch-keyed progress families (frontier, drain, reservation nonce) by key
  or nonce epoch.

P is the auditing policy scope: Chain at e_0, S_n at e_n.

| Class | Rule |
| --- | --- |
| Current (P, epoch e_n) | Existing typed validation of `validate_local_rows` with the P policy, then exclusion of exactly the families original projection excludes; current committed history is reconstructed and compared |
| Earlier (Chain or S_j, j < n; epoch e_j < e_n) | Never excluded and never validated against the P engine; must be a reconstructed key whose bytes equal the base, which installed them from verified link plans; the link that accepted it verified it |
| Incoming (S_{n+1}), unknown scope or epoch | Refuse |

Applied at:

- **Cut capture** (`cut/source.rs:146`): under a source warrant of scope S_n,
  admit Chain and verified S_1..S_n rows and refuse others. Without a
  warrant, the refusal of every `epoch-` row stays.
- **Audit projection** (`audit_projection.rs:179`, candidate authentication
  at 205): the blanket refusal becomes the table. At e_0 the outcome is
  byte-identical.
- **Raw plan of link k** (`verify.rs:refuse_plan_rows`): admit Chain and
  S_1..S_k rows (S_k rows can only come from link k reconstruction, since
  source rows are never installed). Refuse S_{k+1}, because activation
  installs it virgin and `require_absent` stays. Refuse unknown scope. The
  live lock refusal is unchanged.
- **Registration projection** (`projection.rs:626`): earlier anchors are
  verified through the scoped variant at their own epoch.
- **SQLite source composition:** `ExistingSqliteSource` keeps excluding
  import origin. A successor source is read only through the warrant-bound
  cut producer (Section 7).

### 4.1 Bounded frozen-frontier progress and material

Physical publication traversal and the logical current frontier are separate.
Every inspected retained row, including a byte-exact prior publication, consumes
the physical step budget. Historical-only steps persist their physical tail
without changing the current count, accumulator, logical tail or signature.
The original publication addresses and full prior-byte authentication stay.
Traversal also accounts for verified prior keys that disappear from the store.
Each bounded step detects missing or changed carriers at the initial position,
the upcoming merged keys and its exact persisted physical tail. It does not
rescan every key behind that tail. Freeze and protected writer fencing prevent
legitimate behind-tail publication changes; hostile backend changes are a
separate boundary. Current behind-tail entries are reverified by page reads,
and a fresh whole source-cut audit requires historical carriers to equal the
verified prior before Seal. No snapshot-token reset or per-step full-scan
guarantee is implied.

The same frontier owner in Original and Successor modes maintains a private
current-epoch index. A current entry's exact index slot, accumulator and physical
cursor commit atomically through the existing protected gate, deciding CAS reads
and fence. Tombstoned/conflicting slots, rejection and reply loss cannot expose
a partially folded entry. Finalization requires complete physical and prior-key
traversal. Replay creates no signature or independent authority.

Public pages traverse only this bounded current index, validate exact owning
keys and identities, and reverify each actual publication, certificate, intent,
ACK and artifact body. The index is a locator, never evidence. Public logical
cursors, identities, votes, page encoding, signed count and accumulator stay
unchanged; empty nonterminal pages remain invalid. A complete stream must pass
the existing frontier verifier. No page refolds the entire history.
Index values bind a contiguous ordinal and exact availability identity. A page
cursor must name an index member; page ordinals are consecutive and the terminal
ordinal equals the signed count. Preserve an exactly full page as nonterminal,
followed by the empty terminal page, so existing reader page bytes do not change.
Cut proofs paginate through their independent authenticated material owner.

Cursor/index rows are closed typed local metadata. The owning projection
validates exact scope, Freeze binding and publication identity before excluding
those exact rows from semantic cuts and inactive imports. Unknown fields,
malformed keys, orphan rows and foreign/future epochs refuse. DrainSet and
business reconstruction still verify authenticated signer streams independently.
Pre-index persisted progress is not a compatibility promise: refuse incomplete
private state rather than serve a partial index or use an unbounded fallback.
New private progress must survive exact retry, reopen and writer refencing.
Use a new private cursor type or encoding version rather than reinterpreting
old cursor bytes. Prior tombstones explicitly refuse or require exact absence;
they never disappear silently from traversal. An `Advanced` result may repeat
the logical count while physical progress advances; consumers wait for
`Finalized`, not for a changed count.

Read-only material has a distinct private gate, used only by the frontier page
and drain signer progress readers. Original mode verifies origin-only lifecycle
and fencing without forbidding its post-Seal material. Successor mode retains
the fresh Unsealed warrant; Replay mode retains the exact issuer. Advancing,
signing, commits and HTTP exposure keep their live/Unsealed guards. This does
not turn material access into live authority or make a sealed successor serve.

## 5. Closure variants, receipts and provenance

Subject k is transitively semantic: field 6 (Seal target, 0xD051) hashes the
predecessor tag and digest, so subject k commits subject k-1 back to the
genesis digest. It does **not** commit earlier 0xD055 manifests, certificate
bytes beyond digest and length, the Seal commit-proof QC subset, or earlier
suffix proofs. 0x64D5 of N_{k+1} persists only link k digests. Therefore:

- **Own variants.** Each link carries and verifies its own certificate bytes
  (against the SealIntent digest and length), history heights 1..h_k with
  their proof QC subsets, and Seal closure.
- **Bootstrap reuse.** Bootstrap of link k+1 installs exactly the link k
  variants verified in the same chain run.
- **Byte equality.** The N_{k+1} source cut holds the proofs and closure its
  host installed at activation, and the earlier-class rule demands byte
  equality. So link artifacts must be the source host’s own activation
  artifacts. A different QC variant fails closed and is never normalized.
- **Receipts.** The e_k Seal receipt (accepted 0xD053 outcome) is installed
  byte for byte at activation and bootstrap and compared as a receipt record
  (event digest and bytes). Earlier request receipts travel as plan receipts
  and compare byte-equal. A receipt id appearing in two epochs refuses.
- **Import origin.** N_{k+1} keeps `CompleteInactive{binding_k, progress_k}`
  and its 0x64D5 record permanently. The chain re-derives `binding_k` and
  compares it through the existing reconciliation; replay uses it typed.

## 6. Ordered policy at e_k

**Chokepoint** (`policy.rs:950`, today a blanket successor refusal):

| Kind | Chain scope (e_0) | Successor scope S_k |
| --- | --- | --- |
| Freeze, DrainSet | Unchanged | Unchanged kind checks against the e_k engine and the signed minimum Freeze height |
| Seal | Tag 1 with the genesis digest only; tag 2 refused | Tag 2 with digest equal to the policy private `successor_subject` only; tag 1 refused |
| BondRegistration | Unchanged | RegistrationScope (below) |
| FeeClaim, BondLifecycle, BondSlash, Evidence | Unchanged | Unchanged, using the authorities below |

**Registration: one owner, `bond_lifecycle/registration`.** A crate-private
scope replaces `handler.rs:11-26` (`policy_inputs`) at every caller:
preflight, admission, `require_pristine` and completion.

```rust
pub(crate) struct RegistrationScope<'p> {     // private fields
    profile: &'p VerifiedAdmissionProfile,     // immutable e_0 causal profile
    economics: &'p FastPathEconomicsPolicy,    // signed genesis economics
    live_context: PublicationContext,           // owned genuine registration context
    registry: &'p ValidatorSet,                // committee at live_context epoch
    owners: Option<&'p VerifiedOwnerRegistry>, // None exactly at e_0
}
pub(crate) enum RegistrationMode<'a> { Admit, Existing(&'a BondRegistrationAnchor) }
impl<'p> RegistrationScope<'p> {
    fn for_policy(policy: &'p OrderedEconomicsPolicy) -> Result<Self, BondRegistrationError>;
    fn for_genesis(root: &'p VerifiedGenesisRoot) -> Self;
    fn for_epoch(root: &'p VerifiedGenesisRoot, committees: &'p VerifiedCommitteeHistory,
                 owners: &'p VerifiedOwnerRegistry, epoch: Epoch)
        -> Result<Self, BondRegistrationError>;
}
```

There is no caller Boolean: the policy private key scope selects the case.
`for_epoch` derives the owned context from the immutable root's chain/protocol
and the verified committee epoch; it never borrows a nonexistent history
context or accepts a peer-provided context.

- **Chain policy** keeps today’s rule: `profile.context() ==
  policy.context()`, live context = profile context, owners None.
- **Successor policy** requires `profile.context() ==
  root.genesis_context()` (still e_0) and `live_context ==
  policy.context()` (e_k). It takes economics only from
  `from_successor_chain`, which keeps the signed genesis economics and
  admission profile.

In both cases, resource context and economics stay the immutable e_0 values
(`handler.rs:425-438`).

`authenticate_intent(scope, mode, intent)` (`registration.rs:323`) requires:

- `intent.context == live_context`;
- `resource_context == profile.context()` and the original genesis digest;
- `registry.epoch() == live_context.epoch()`;
- Ed25519 id equal to key;
- the generic leg policy at `live_context`.

Then, by mode:

- **Admit** (a new candidate). Refuse if the id or key matches any `registry`
  entry or any `owners` entry. This set covers every genesis key and every
  verified registration, so re-registering a retired key under a new id
  stays refused.
- **Existing(anchor)** (re-verifying a genuine committed anchor). The anchor
  epoch selects the scope.
  - A `registry` id or key match refuses, as today.
  - An `owners` entry with the same id, key and provenance (anchor epoch,
    intent digest and initial row digest, all recomputed from this anchor) is
    the identity itself.
  - Any other id or key match is reuse and refuses.
  - An anchor at the live epoch that is not yet in `owners` is reconciled
    the same way, so a same-epoch registration still refuses as
    `AlreadyRegistered` from its valid anchor.

`verify_chain` (`handler.rs:71`) takes `(scope, Existing(anchor))`, and its
`anchor.context` check compares against `live_context`. The public
`verify_registered_bond_chain` stays as is: genesis scope, Existing mode.

Public routes for SDK and hosts, all in the same handler:

```rust
pub fn verify_signed_bond_registration_successor(root: &VerifiedGenesisRoot,
    authority: &VerifiedSuccessorAuthority, bytes: &[u8],
) -> Result<SignedBondRegistrationIntent, BondRegistrationError>; // Admit, authority epoch
```

`prepare_bond_registration_successor` (Section 7) uses the same scope.
Projection and the chain registry build use `for_epoch` with Existing mode.
Completion keeps every other existing check under the gate: receipt
reconciliation, ordered admission, `fence_verified_admission_profile`,
`fence_current_epoch`, current-set exclusion, `require_pristine`, economics
row equality and nonce reservation. It also replaces
`ObjectMinimum::for_profile` (`handler.rs:483`) with the gate generation
scope.

Next-epoch eligibility is real: the handler writes `lifecycle_epoch = e_k`
and `slashable_from = e_k + 1` (`handler.rs:551-576`), and
`check_next_set_eligibility` at e_k accepts `slashable_from <= e_k + 1` and
`lifecycle_epoch <= e_k` (`epoch_transition.rs:393-398`). A registration
committed before the e_k Freeze is therefore eligible for the certified
e_{k+1} set.

**Bond owner authority** (`policy.rs:568`):

- A current e_k member resolves from its set entry, unchanged.
- For Unbond and Withdraw only, a non-member resolves from
  `VerifiedOwnerRegistry`: the genesis bond key or the cryptographically
  verified signed registration, never the latest committee membership. A
  registered sender that never voted can exit its own bond.
- A registration committed in e_k after the cut is not yet in the registry.
  Its pure key is the id bytes, since registration forces id == key. Preflight
  and the handler then require that id’s committed `bond-registration/`
  anchor to pass `verify_chain(for_policy, Existing)`, with its reads folded
  into the CAS set. The id bytes alone are never authority.
- The handler still verifies the signature with the committed bond row key
  (`bond_lifecycle.rs:989`), checks row identity, generation, previous digest
  and state, and for Withdraw requires absence from the live set. Deposit,
  Replace and Reactivate stay members-only.

**Unlock.** `Unbond` writes unlock = (epoch of the committing Unbond) +
resource `unbonding_epochs` with a checked add (`bond_lifecycle.rs:1909`).
`Withdraw` requires current epoch >= unlock (`:1982`) and absence from the
live set (`:1990`). With the unchanged fixture value 7, an Unbond committed at
e_u unlocks exactly at e_{u+7}.

**Historical committees.** `predecessor_certificates` (`policy.rs:258`)
becomes a crate-private `Option<Arc<VerifiedCommitteeHistory>>`, set only by
`from_successor_chain`; one link yields today’s single entry.
`certificate_set(epoch)` answers the policy epoch or any verified earlier
epoch. Warrant and replay `predecessor_certificate_anchor` return that
epoch’s typed digest. `load_successor_predecessor_set_fenced`
(`equivocation.rs:660`) drops its adjacency test. Instead it requires the
live epoch record to equal the warrant record (already a deciding read),
`certificate_epoch` below the live epoch and present in the history, and the
imported `fastpath_validator_set_key(ctx@certificate_epoch)` row to hash to
the verified digest. Both reads are fenced.

## 7. Additive entry points

`verify_successor_authority`, `activate_successor`, `resolve_live_authority`,
`derive_source_business_cut`, `verify_saved_business_import`,
`retain_conditional_readiness`, `prepare_bond_registration` and
`verify_signed_bond_registration` keep their signatures and existing supported
single-link operations. The new controls in Section 6 are expressly added by
this contract. The first three use the same one-link verifier and chain owner
with budget 1; no legacy-only authority branch or caller Boolean preserves an
obsolete unsupported-feature refusal.

```rust
pub fn verify_successor_chain_authority(plan: BusinessReconstructionPlan<'_>,
    links: &[SuccessorLinkPins], budget: SuccessorChainBudget,
    artifacts: &mut dyn SuccessorChainArtifacts,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError>;
pub fn activate_successor_chain<S, B>(plan: BusinessReconstructionPlan<'_>,
    links: &[SuccessorLinkPins], budget: SuccessorChainBudget,
    artifacts: &mut dyn SuccessorChainArtifacts, destination: &S, destination_blobs: &B,
    operation: &DurableOperationContext, signer: &ReadinessSigningKey, now_unix_millis: u64,
) -> Result<SuccessorActivationOutcome, SuccessorActivationError>
where S: StructuredDurableDomainStateStore + InactiveImportRepository, B: PortableBlobRepository;
pub fn resolve_live_authority_chain<'inv, S: StructuredDurableDomainStateStore>(
    store: &'inv S, context: &'inv DurableOperationContext, domain: AtomicityDomainId,
    plan: BusinessReconstructionPlan<'_>, links: &[SuccessorLinkPins],
    budget: SuccessorChainBudget, artifacts: &mut dyn SuccessorChainArtifacts,
    signer_public_key: [u8; 32],
) -> Result<LiveAuthority<'inv>, ServingAuthorityError>;
pub fn derive_successor_source_business_cut<S, B>(plan: BusinessReconstructionPlan<'_>,
    warrant: &LiveWarrant<'_>, source: &S, source_blobs: &B,
    ordered: &[OrderedHistoryHeightMaterial],
) -> Result<VerifiedBusinessCut, BusinessCutError>
where S: DurablePortableSnapshotRepository + StructuredStateReader + ?Sized,
      B: PortableBlobRepository + ?Sized;
pub fn verify_saved_business_import_chain(plan: BusinessReconstructionPlan<'_>,
    authority: &VerifiedSuccessorAuthority, cut_identity: &OrderedHistoryIdentity,
    saved: &SavedBusinessCut,
) -> Result<VerifiedImportPlan, BusinessImportError>;
pub fn retain_conditional_readiness_chain<S, B>(plan: BusinessReconstructionPlan<'_>,
    authority: &VerifiedSuccessorAuthority, cut_identity: &OrderedHistoryIdentity,
    saved: &SavedBusinessCut, destination: &S, blobs: &B, operation: &DurableOperationContext,
    next_members: &[FastPathValidatorEntry], signer: &ReadinessSigningKey,
) -> Result<ReadinessVote, ConditionalReadinessError>
where S: ReadinessRetentionRepository, B: PortableBlobRepository;
pub fn prepare_bond_registration_successor(root: &VerifiedGenesisRoot,
    authority: &VerifiedSuccessorAuthority, request: BondRegistrationPreparationRequest,
) -> Result<PreparedBondRegistration, BondRegistrationError>;
```

- **Plan role.** Each chain function checks plan root digest and domain
  against the authority or warrant. The plan supplies only root, engines,
  resolver history and operation context.
- **Evidence.** `VerifiedSuccessorAuthority`, `ActivationWarrant` and
  `LiveWarrant` hold a `VerifiedSuccessorChain` privately. Existing
  accessors report the last link, and `link_count() -> u32` is added. None is
  `Clone`, `Default` or serializable, and none can be built from rows, flags,
  readers or decoded records.
- **e_n imports.** The import and readiness chain variants build the e_n base
  from an authority over links 0..n-1, then verify the e_n saved cut against
  a pin carrying e_n and A_n. Readiness keeps its Serving refusal
  (`conditional_readiness.rs:220`); its destination is the new Inactive
  N_{n+1}.
- **Source cut.** `derive_successor_source_business_cut` first runs
  `warrant.require_reader(source)`, then takes the base from the warrant’s
  chain. The private Seal-signing and live-closure cut variants
  (`cut.rs:255,332`) take their base from the admission gate, so
  `OrderedSealComposition` is unchanged.

**Before any successor signature or control** (Freeze, frontier vote,
DrainSet, Seal, ordered or FastVote vote), all must pass: a fresh
`resolve_live_authority_chain` (full chain rerun); namespace validator ==
local signer, a member of C_n (`require_local_signer`); barrier Unsealed;
the deciding warrant reads (e_n set and three policy rows, carried-forward
e_{n-1} fee policy, exact epoch record); and the existing per-control checks,
unchanged. `refuse_successor_serving` at `frontier.rs:270`,
`drain_publication.rs:550` and `engine.rs:1048` becomes the gate: `Original`
as today, `Successor` after issuer and signer checks, `Replay` refuses to
sign. Legacy `epoch_transition.rs:648,812` stays refused.

### Historical material export is not live authority

After its own Seal, a successor cannot obtain a fresh `LiveWarrant`. It may
still expose immutable ordered-history material through the existing bounded
summary, descriptor and chunk owners. No historical signing warrant, new
verification engine or relaxation of the live gate is needed.

The thin imported-source composition freshly verifies the independently pinned
chain through activation of the source epoch, derives the policy from that
authority and checks the explicit epoch/domain/physical validator namespace
and exact completed import binding. It reads the current fence and uses a
bounded operation context without advancing the fence, installing or repairing
state. Original-only `ExistingSqliteSource` remains unchanged. Historical
SQLite open permits imported/Sealed consumption but is not an OS-enforced
read-only connection; this composition invokes only read methods.

Freeze one target identity, reuse the existing material/export format and
verify the complete fixed prefix before marking export complete. A post-Seal
export also observes `Sealed` at the expected epoch and compares the terminal
Seal height, block digest and request to that barrier. Corruption, missing
material, changed target, expiry or fencing refuse. Public materials prove
ordering/material consistency only, not business effects, accepted Seal,
readiness or activation. Those claims remain with reconstruction and the full
chain verifier. If mounted over HTTP, only the three history-query routes use
this read composition; no signer, control or mutation route bypasses its fresh
live authority check.

## 8. Seal retirement of N_k (runtime/store)

Two methods join the existing opt-in `SuccessorServingRepository`
(`runtime/src/successor_serving.rs:254`). They are the same atomic Seal-owner
capability of the same store: not a provider choice, a parallel engine, or a
widening of `OutgoingSealRepository`, which stays Ordinary-only.

```rust
fn commit_successor_seal_retention(&self, context: &DurableOperationContext,
    observation: &SuccessorServingObservation, token: &PortableSnapshotToken,
    transaction: AtomicStateTransaction) -> DurableCommitOutcome;
fn commit_successor_seal_completion(&self, context: &DurableOperationContext,
    observation: &SuccessorServingObservation, token: &PortableSnapshotToken,
    transaction: DurableInvocationTransaction, sealed: SealBarrier) -> DurableCommitOutcome;
```

Implementers: the memory successor store and the shared SQL engine (SQLite).
No schema change.

- **Both, in one lock or transaction:** writer fence and deadline; domain;
  lifecycle `CompleteInactive` with binding and progress equal to the
  observation; slot `Serving` with record byte-equal to `observation.record`;
  the physical namespace validator equals the record's local validator;
  barrier `Unsealed`; `token.check(namespace, domain, fence, current
  sequence)`; empty Seal outbox; every read assertion, including folded
  warrant reads.
- **Completion also:** receipt id equals `sealed.request`; no object reads or
  mutations; outbox absent or empty; no existing receipt, outbox or delivery
  for the request; encodable `SealBarrier`; the checked successor epoch
  `binding.context.epoch + 1` equals `sealed.outgoing_epoch`. This structural
  check is in the same storage transaction and supplements, not substitutes
  for, core verification of the current epoch and exact Seal request.
- **Then atomically:** apply state; on completion insert the receipt and
  install `Sealed(sealed)` (`transition_history` Virgin, as this is the
  namespace’s first Seal); advance the sequence once. A pre-commit failure is
  a definite no-write rejection; `Indeterminate` keeps the existing
  reconciliation boundary.

**Core routing: one issuer-bound Seal port.**

```rust
pub(crate) enum SealPort<'s> {                      // private; Copy
    Original(&'s dyn OutgoingSealRepository),
    Successor { port: &'s dyn SuccessorServingRepository, warrant: &'s LiveWarrant<'s> },
}
impl ServingGate<'_> {
    pub(crate) fn seal_port<'s, S: StructuredDurableDomainStateStore + ?Sized>(
        self, store: &'s S) -> Result<SealPort<'s>, NodeCoreError>;
}
// SealPort methods:
//   reader() -> &dyn DurablePortableSnapshotRepository
//   commit_retention(context, token, tx)
//   commit_completion(context, token, tx, sealed)
```

How `seal_port` resolves:

| Gate | Port |
| --- | --- |
| `Original` | `store.outgoing_seal_repository()`, exactly as today |
| `Successor` | `warrant.require_issuer(store)`, then the store’s own successor port; reads go through its `InactiveImportRepository: DurablePortableSnapshotRepository` supertrait |
| `Replay` | Refused |

Every current Seal consumer moves to this one value:

- signing history reads and identity (`engine.rs:1591-1618`);
- the Seal signing capability check (`engine.rs:3423`), which becomes
  `env.seal.is_some() && gate.seal_port(store).is_ok()`;
- the completion preparation argument (`engine.rs:3033`), which becomes
  `Option<SealPort>`;
- the vote retention confirmation (`engine.rs:4011` into
  `confirm_seal_retention`, `:2722`), which takes `SealPort`;
- retention commits at `engine.rs:2735,3597`;
- completion at `completion.rs:54`.

Successor commits fold the warrant reads.

The token comes only from `reader().begin_portable_snapshot` of that same
store; core never calls `PortableSnapshotToken::new`. Before dispatch, core
checks `sealed.outgoing_epoch == e_n` and that the request is the verified
Seal request.

**After completion.** `resolve_live_authority(_chain)` on N_n sees `Sealed`
and refuses, so N_n creates no further vote, QC, FastVote signature or
control. Export and receipt replay use the existing historical open. e_n
votes and QCs are refused at e_{n+1} because context and anchor differ. The
unchanged `commit_successor_activation` activates N_{n+1}; its must-CAS epoch
record equals link n-1’s record exactly: `{e_n, Some(e_{n-1}),
digest(C_n), h_{n-1}}`.

## 9. Encoding

SealIntent field 3 = 2 (`SEAL_PREDECESSOR_TAG_SUCCESSOR`); field 4 = the
0xD054 digest of the link that activated the sealing epoch. The intent and
0xD051 target encoders (`seal.rs:107,198`) accept {1, 2}; 0 and 3..=u16::MAX
refuse. New independent stable vectors cover the tag-2 SealIntent, the 0xD051
target and the 0xD052 request id (high bit set). Every tag-1 vector is
unchanged. The existing negative test that treats tag 2 as unknown
(`seal.rs:776`) moves to tags 3 and u16::MAX: a test change, not a byte
change. CLI and SDK pins are repeated, ordered, all-or-none references to
existing archive directories; there is no new file frame.

## 10. Bounds and cost

Pin count is checked against the budget first. Each link keeps the existing
bounds: 2 KiB subject and manifest, 1 MiB certificate, history, proof and
activation-transaction bounds, plan row and blob counts. Registry and
committee entries are bounded by verified plan rows and certificate members.
Per-request cost is the sum over links of cut re-execution plus history; it
grows linearly with epochs, stated rather than hidden. A bounded-cost
successor needs its own reviewed decision; no checkpoint is trusted here.

## 11. Ownership and coherent PRs

| PR | Owner | Content | Acceptance inside the PR |
| --- | --- | --- | --- |
| 1 | Core and runtime/store | Chain/base/replay, the memory-only import-batch fixture constructor, scoped reconstruction, RegistrationScope with Admit/Existing modes, historical owners/committees, current source controls, SealPort for every Seal consumer, the same two atomic Seal methods, tag 2 and vectors | Genuine file-backed recurrence plus actual callers of the ports; all in-lock refusals, reply-loss/reopen, ABCD to ABCE, later registration, e_0 escrow claim at e_2 and the negatives below. A declaration-only store PR is not this feature |
| 2 | Host, SDK, CLI and real acceptance | The same owners through shipped routes and binaries; ordered link pins and explicit budget, no cloned lifecycle engine | Real process recurrence and Section 12 including the unchanged configured unlock epoch. Missing final acceptance remains open; an ignored skeleton does not complete it |

Core and process negatives:

- tag 1 at S_k; tag 2 at Chain or with a wrong digest;
- a skipped, reordered or duplicated link; budget exceeded with zero
  artifact calls;
- a planted S_{k+1} or unknown-scope row in plan, capture and projection; an
  altered earlier-scope row or receipt; a different closure QC variant;
- Seal against a stale observation; signing after the namespace’s own Seal;
- registration replay across epochs; re-registration of a retired genesis
  key;
- Withdraw before unlock or while a member; non-member Deposit;
- an e_0 QC at e_2.

A reduced-delay helper may exist only as a labeled non-acceptance test.

## 12. Exact callable acceptance

One real process run: an independently stored SQLite host for every member of
each live committee, operator binaries and
the CLI over TCP, and the original signed fixture (`unbonding_epochs = 7`)
unchanged.

1. **e_0 ABCD.** E registers and deposits (as PR267). Genuine Freeze,
   DrainSet, cut, readiness and Seal (tag 1) follow, then activation of four
   fresh targets: e_1 is ABCE.
2. **e_1 Unbonds.** D, retired and no longer a voter, Unbonds its own bond. G
   registers, is never selected, and Unbonds. The run reads U_D and U_G from
   the committed rows and asserts each equals its committing epoch plus the
   delay read from the installed economics row. No epoch number is
   hard-coded.
3. **Every e_k with k >= 1.** Genuine Freeze, DrainSet and cut on N_k through
   the chain producer, readiness on new targets, Seal tag 2, and activation of
   N_{k+1} from pins for links 0..k.
4. **Later registration.** F registers at e_2 before Freeze and is certified
   into e_3 (ABCEF).
   - From e_3 on, every namespace runs five independently stored SQLite
     hosts.
   - Membership evidence is real: the e_3 readiness certificate and the
     ordered QCs and FastVote certificates carry F’s signature from F’s own
     host.
   - That host’s namespace validator and Active bond key equal F’s verified
     registration.
5. **Older fee claim.** An e_0 escrow share is claimed at e_2 or later.
6. **Paid contracts and receipts, every epoch.** FastVote-certified paid
   Publish, Instantiate and Call, including Calls on e_0 instances. Later
   hosts replay e_0 receipts, earlier-epoch receipts and every Seal receipt
   byte for byte.
7. **Withdraw at the computed unlock.** Withdraw by D and by G is refused at
   every live epoch below its U and accepted at e_U on that epoch’s hosts. The
   run continues to `max(U_D, U_G)`, which is 8 when both Unbonds commit at
   e_1.
8. **Faults.** Restart and refence a host mid-epoch. A stale writer is
   refused. An import/activation inventory race is refused. A live commit
   racing Seal completion is rejected by the token. Activation and
   Seal-completion reply loss are reconciled.
9. **Sealed namespaces.** Every Sealed N_k refuses live controls, ordered
   votes, FastVote signatures and paid admission; e_{k-1} votes and QCs are
   refused at e_{k+1}.

Gate: `npm ci --prefix adapters/cloudflare-workers` and
`./scripts/check-all.sh`. The complete PG suite applies only if PG code
changes, which this contract forbids.

## 13. Selected boundaries for independent review

- **Bootstrap mechanism.** Use exactly the runtime
  `new_bound_from_import_batches` constructor, the shared activation
  mutations and the `raw_rows` postcondition of Section 3. No other port,
  restore path or serving slot is added.
- **Same-epoch registrant exit.** Use exactly the Section 6
  `verify_chain(for_policy, Existing)` path, with folded reads and the
  committed bond key. The id bytes alone are never owner authority.
- **Budget.** No default value; operators configure it explicitly. Linear
  per-request cost remains until a separately reviewed bounded-cost design.
- **Policy strictness.** Link 0 uses the same owning verification in both entry
  paths. Later policies are derived privately from verified activation facts.
- **Artifact provenance.** Link artifacts must be the source host’s own
  activation artifacts: an operator procedure enforced only by byte-equal
  refusal. The operator must preserve that exact lineage; substituting an
  independently valid QC variant is not a repair.
