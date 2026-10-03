# First successor target-local activation and authenticated serving

This is the closed proposed contract of
[DR-0189](decisions/0189-first-successor-serving.md). It depends on the
already-accepted [verified inactive import](verified-inactive-import.md)
([DR-0176](decisions/0176-verified-inactive-business-import.md)),
[conditional readiness](conditional-readiness-seal.md)
([DR-0178](decisions/0178-conditional-readiness-wire-and-retention.md)) and
[first-epoch ordered Seal](ordered-seal.md)
([DR-0187](decisions/0187-first-epoch-ordered-seal.md)) contracts and closes
the successor-activation gap those records and
[epoch-handoff.md](epoch-handoff.md)'s aspirational "Recovery and serving
authority" section deliberately leave open. Current status belongs only in
[TODO.md](../../TODO.md). This is a design document, not an implementation
approval: no wire identifier, key, migration or serving capability described
here exists until a reviewed implementation lands.

## 1. Authority chain and the evidence/warrant separation

Authority for the first successor's e+1 serving composes, in order:

1. The immutable, privately constructed `VerifiedGenesisRoot`
   ([genesis trust](genesis-trust.md); DR-0182), unchanged.
2. The outgoing epoch-e committee, verified through the same root.
3. Source-free [authenticated ordered history](ordered-history.md) from
   height 1 through the committed [Seal](ordered-seal.md) at height h.
4. The committed Seal's own target, proof, outcome and original receipt
   (DR-0187, frames 0xD050-0xD053).
5. The [conditional readiness](conditional-readiness-seal.md) certificate
   for the exact Seal cut and the eligible e+1 set (DR-0178).
6. The resulting checked-eligible e+1 validator set.

Every outgoing signature this chain relies on was created before Seal
acceptance under DR-0187; nothing here creates or exposes a new outgoing
signature, and relaying an already-formed QC or certificate remains legal
historical reconciliation, not a fresh signature.

Two authorities stay structurally separate, matching [verified inactive
import](verified-inactive-import.md)'s existing binding/plan/destination
split:

- **Source-free verified evidence.** Steps 1-6 above depend only on the
  locally pinned genesis root, schedule and domain plus publicly
  transportable material (history pages, the Seal's companions, the
  readiness certificate). A private core function reconstructs and verifies
  this evidence without reading any destination row; its result is opaque
  and carries no constructor from decoded bytes, a caller's equality report
  or a "ready" flag. The Rust SDK consumes exactly this evidence, never a
  destination's self-reported state.
- **Destination activation warrant.** A separate, private, destination-bound
  check (Section 6) calls the target's own already-existing
  `VerifiedImportPlan::observe_complete` in full -- every raw row, every
  bounded immutable body, exact `ImportBinding`/`ImportProgress` identity and
  a freshly observed writer token -- never a looser identity-only compare.
  Only this second check may read destination rows or the destination's own
  installed signing key, and only its result may authorize a destination
  write.

No function or type spans both roles. The source-free verifier of Section 3
never takes a destination store, lifecycle, token or local key as input. A
decoded `0x64D5` row (Section 7) is never a constructor for the source-free
evidence type, and the source-free evidence type has no field or method that
reads or infers a destination row.

## 2. Closed public frames

All frames use canonical encoding version 1 unless stated, closed fields,
exact decode/re-encode and checked lengths before copies. A workspace sweep
on base `aa0f664` found no allocation of `0xD054`-`0xD05F`,
`0x64D5`-`0x64DF`, `0x6441` v3, `durable_successor_serving`,
`successor_activation`, `successor_host`, or an
`epoch-state/`/`epoch-applied-height/` key infix.

| Frame | Fields in canonical order | Bound |
| --- | --- | --- |
| 0xD054 SuccessorActivationSubject (source-free, hash-only) | 1 chain, 2 protocol u32, 3 outgoing epoch u64, 4 genesis Digest32, 5 domain, 6 Seal target Digest32 (0xD051), 7 Seal request 32B (the Seal candidate's own exact `request_id`, already carrying `request_id[0] \|= 0x80` from its own 0xD052 derivation; verification requires the bit already set and never sets it), 8 Seal height u64, 9 Seal block Digest32, 10 successor epoch u64 (checked = outgoing epoch + 1), 11 successor-set Digest32 (= verified `ReadinessSubject.next_set_digest`), 12 complete-schedule Digest32 (= same subject's `schedule_digest`), 13 semantic-cut Digest32 (= same subject's `cut_digest`) | 2 KiB |
| 0xD055 SuccessorActivationManifest (source-free, exact package reference) | 1 subject frame, 2 readiness certificate Digest32, 3 certificate length u32, 4 extended `OrderedHistoryIdentity` frame (through = h), 5 Seal 0xD017 commit-proof Digest32 (via the existing `ordered_history_component_digest`, `crates/node-core/src/ordered_economics/ordered_history.rs:170`), 6 proof length u32, 7 exact saved-cut package Digest32 (= `ImportBinding.package_digest`), 8 exact raw-plan Digest32 (= `ImportBinding.plan_digest`) | 2 KiB |
| 0x6441 v3 successor consensus anchor preimage | fields 1-9 identical in meaning to v2 (label replaced by `se/ordered-economics/anchor/v3-successor`; field 2 context at e+1; field 4 the **original, unchanged** pinned genesis digest; field 5 the e+1 `ValidatorSet` digest; fields 6-8 `ConsensusParameters::genesis()` as today; field 9 the **same, unchanged** signed `minimum_freeze_block_height` from the original root), plus field 10 the 0xD054 subject Digest32 | hash only, never persisted |
| 0x64D5 SuccessorServingRecord (destination warrant, protected) | 1 subject Digest32, 2 manifest Digest32, 3 exact `encode_import_binding` bytes (0x64C0, `crates/runtime/src/inactive_import.rs:318`), 4 exact `encode_import_progress` bytes (0x64C1, `:409`), 5 exact 0x64D2 creation-observation frame over the fresh token (`encode_readiness_creation_token`, `crates/runtime/src/conditional_readiness.rs:142`; immutable once written), 6 v3 anchor Digest32, 7 local validator id, 8 actual installed Ed25519 public key (32B) | 16 KiB |
| 0x64D6 SuccessorServingSlot (protected) | 1 phase u16 (1 Inactive, empty field 2; 2 Serving, one 0x64D5 record in field 2), 2 bytes | 17 KiB |

Digests: the subject and manifest use `NodeEvent` at the **outgoing** epoch
e, exactly like the Seal target/request preimages (0xD051/0xD052) they
embed. The v3 anchor uses `ProtocolConfig` at **e+1**, exactly like the
existing v1/v2 anchor (`ordered_economics_authority_anchor`,
`crates/node-core/src/ordered_economics/policy.rs:72`). The certificate
digest reference in field 2 of 0xD055 uses `Certificate` at outgoing epoch
e, exactly like the SealIntent's own certificate reference (0xD050 field 5).
No frame above carries a filesystem path, directory handle or other
local-only value; Section 6 covers how retained files reach the verifier.

No new signing label, signature purpose or hash suite is introduced. Unknown
phases, tags or frame versions stop. Existing transport bounds are
unchanged: 16 KiB descriptors, 1 MiB chunks, the 1 MiB / 256-vote readiness
certificate, and the 32 MiB canonical 0xD017 proof cap. Legal
ordered-history length stays unbounded; the verifier in Section 3 is linear in it,
not constant.

## 3. Source-free verification (writer-free, no destination read)

One private core function, `verify_successor_activation(root, local_schedule,
domain, saved_cut, history_pages, certificate_blob) -> VerifiedSuccessorActivation`,
decides the entirety of Section 1's evidence chain. It takes **no**
destination store, lifecycle, token or local key; the result type has a
crate-private constructor, is not `Clone` and has no constructor from decoded
rows. Every step below is re-executed on every invocation that needs this
evidence -- activation, startup and reconciliation alike -- and none of it
is cached or memoized across invocations, matching DR-0178's own "explicit
linear cost, not a constant-memory or constant-time claim."

1. Reconstruct a `VerifiedImportPlan` through the existing
   `verify_saved_business_import` path
   (`crates/node-core/src/business_reconstruction/inactive_import.rs:393`),
   yielding the cut identity C at height T, its private rows/bodies and its
   authenticated `generation_floor` (Section 4) -- all source-derived, with
   no destination parameter.
2. Check `seal_cut_identity_digest(intent.cut) == intent.subject.cut_digest
   == plan.binding().cut_digest` and require `created_checkpoint == T`
   (`crates/node-core/src/ordered_economics/seal.rs:337`). `plan.binding()`
   is the freshly reconstructed, source-derived binding, never a destination
   row.
3. Run `OrderedHistoryVerifier::new`
   (`crates/node-core/src/ordered_economics/ordered_history.rs:414`) over
   the exported material for heights 1..h under the root-derived outgoing
   policy: the block at T must equal C's ordered-history identity; heights
   T+1..h-1 must be empty; h must contain exactly one Seal candidate,
   authenticated by the existing Seal pure-authentication path; re-derive
   the 0xD051/0xD052 preimages and require the predecessor tag to be 1
   (original genesis) and equal the locally pinned genesis digest; the
   Seal's 0xD017 commit proof must be h's own `CommittedBlockProof`
   component, with empty child and grandchild, through the existing
   `verified_committed_block` (`ordered_history.rs:196`). A required
   extension to the verifier/`verify_material` (`ordered_history.rs:232`):
   accept a Seal candidate only as the **terminal** height of the exported
   material; any height committed after it stops verification.
4. Re-read the certificate blob in bounded chunks, check its digest and
   length; reconstruct the `ReadinessSubject` from the plan's own fields
   (chain/protocol/epoch, genesis digest, domain,
   `plan.binding().validator_set_digest`, `plan.binding().cut_digest`, next
   epoch, the candidate next set's `ValidatorSet::digest`,
   `readiness_schedule_digest`), require every field to equal the
   corresponding 0xD054 field (3-5, 10-13), and run
   `ReadinessCertifier::verify_certificate`
   (`crates/consensus/src/readiness.rs:456`) against it. The certificate
   blob and schedule are supplied inputs, not destination reads.
5. Re-derive eligibility with `check_next_set_eligibility`
   (`crates/node-core/src/epoch_transition.rs:359`) against a new
   crate-private `PlanStateReader<'_>` implementing `VersionedStateReader`
   (`crates/runtime/src/state_read.rs:29`) as a read-only lookup over the
   plan's own private `ImportRow::State` rows -- **never** a destination.
   These are the same bond/resource rows `verify_saved_business_import`
   already installed into the plan from the independently reconstructed
   post-drain state, so this re-derives the same fact DR-0178's signers
   checked, from the same source material, rather than trusting their
   signatures alone. The fencing map this produces is discarded; nothing
   here commits.
6. Verify the Seal's `RetainedOutcome`, `OriginalReceipt` and
   `RequestHeader` as the verifier's own completion companions (section
   "Selected-branch verification", [ordered-seal.md](ordered-seal.md));
   these are not independently re-derived.
7. Require the plan's own rows carry no live fast-path lock or sender-
   nonce-lock row (they would strand objects across the handoff); this
   reads `self.rows`, never a destination.

`VerifiedSuccessorActivation` exposes the checked e+1 `ValidatorSet`, its
eligible members, the plan's `generation_floor`/binding and the Seal
companions -- but **no** destination-specific fact. Which local validator
id and key the activating destination claims to be is checked only in
Section 6, against this result, never inside this function.

## 4. Scoped generation floor and Logical provenance for new rows

[`LogicalProfileRecord`](logical-execution-generation.md)
(`crates/node-core/src/logical_generation.rs:178`) stays byte-identical at
its genesis context; import does not touch it (DR-0176). Its
`genesis_floor` field is the correct floor for every **Original**-namespace
derivation. It is **not** the floor for a successor: the cut's own
effective floor, `cut.identity().generation_floor`
(`crates/node-core/src/business_reconstruction/cut/derive.rs:463`), already
verified and carried unmodified as `ImportBinding.generation_floor`
(`inactive_import.rs:414`), is. Call it `effective_floor`.

This matters because `logical_generation::derive`
(`crates/node-core/src/logical_generation.rs:879`) folds every state key
already present in a transaction's CAS read-set as a logical subject unless
`is_excluded_subject` recognizes it, and `observe_state_subject`
(`logical_generation.rs:1437`) **fails closed** -- `MISSING_PROVENANCE` --
the first time any such present, non-excluded key is read without a
matching `LogicalProvenanceRecord`. The three new per-epoch policy rows this
activation installs --
`execution_policy_key_for_profile(ctx@e+1, 4)`, `paid_fee_policy_key(ctx@e+1)`,
`publication_policy_key_for_profile(ctx@e+1, 4)` -- live under
`INSTANCE_STATE_PREFIX`, which `is_excluded_subject` does **not** recognize
(unlike `FASTPATH_STATE_PREFIX`'s `validators/`, `epoch/` and `transition/`
rows, already excluded, unchanged). Installed without a provenance
companion, the first paid/local/publication call at e+1 fails closed the
instant it reads its own policy row.

Only `derive` hard-codes the floor, at `:893`
(`let floor = profile.genesis_floor;`). `provenance_mutations` (`:947`)
already takes a computed `derived: &LogicalDerivation` and writes every row
at `derived.generation`; it has **no** hard-coded floor and needs no
change. `require_application_admissible`'s `Logical` arm (`:1531`) does
hard-code `record.genesis_floor` in its regression check and needs the
same scoping as `derive`.

Close this with one crate-private scope type and two crate-private
constructors, no public or raw-value constructor:

- `GenerationScope` (private fields): `Original { floor }` |
  `Successor { floor, epoch, anchor }`.
- `GenerationScope::from_profile(profile: &LogicalProfileRecord) -> Self`
  (`Original`, `floor = profile.genesis_floor`) -- called wherever
  `fence_commitment_profile` already resolves
  `InstalledCommitmentProfile::Logical(profile)` for an `Ordinary`
  namespace. `derive(..) = derive_scoped(&GenerationScope::from_profile(profile), ..)`
  becomes a thin wrapper: byte-identical behavior for every existing
  Original-namespace call site and vector.
- `GenerationScope::from_successor(warrant: &SuccessorWarrant) -> Self`
  (`Successor`, `floor = warrant.binding().generation_floor`, `epoch`/
  `anchor` from the same already-verified warrant) -- the only non-`Original`
  constructor, exposed by both Section 6's activation-time warrant and
  Section 8's live `Successor` resolver. No constructor takes a bare
  `ExecutionGeneration`.

`logical_generation::derive_scoped(scope: &GenerationScope, store, context,
domain, resolver, profile, head_reads, nonce, reads)` is `derive`'s existing
body with `scope.floor()` in place of `profile.genesis_floor`, plus one
added check for `Successor`: the invocation's own fenced epoch-scoped
anchor (Section 5) must equal `scope.anchor()` at `scope.epoch()`, refusing
a stale or foreign scope. It folds the scope's own already-fenced reads
into the caller's `reads` before returning, so one transaction still
asserts one CAS set.

`require_application_admissible_scoped(scope, installed, derivation)`
replaces the `Logical` arm's `derivation.generation > record.genesis_floor`
with `derivation.generation > scope.floor()`; the existing unscoped
function becomes `require_application_admissible_scoped(&GenerationScope::from_profile(..), ..)`.

Every successor live path -- normal prepare/apply, ordered paid execution,
fee claims -- that currently calls `derive`/`admit_resolved`/
`admit_application`/`admit_generic_transition` is migrated to call the
`_scoped` siblings with `GenerationScope::from_successor(&warrant)` from
Section 8's resolver. The activation installer (Section 6) is not a
special case: it builds the same `GenerationScope::from_successor` from
the just-verified evidence and target warrant, then calls `derive_scoped`/
`provenance_mutations` over its own three policy writes as ordinary
`LogicalWrite`s through the same fold -- these three keys have no existing
reads to fold as dependencies, so `successor_of(effective_floor, &[])` is
what the generic fold itself produces, not a hand-written bypass of it.

`classify_fastpath_row`/`classify_ordered_row` exclusions (`validators/`,
`epoch/`, `transition/`, `state/`, `applied-height/`, `candidate/`,
`header/`, `outcome/`, `committed-proof/`) are unchanged; `provenance_mutations`
is called only for the three non-excluded policy keys above, exactly as it
would be for any other non-excluded new or changed row -- not a broad
exemption. The protected `0x64D5`/`0x64D6`/`0x64C0`/`0x64C1` rows and the
outgoing barrier read through dedicated typed ports, never through the
generic CAS path `derive_scoped` sweeps, so they need no provenance either.

`derive_scoped`, `GenerationScope` and `require_application_admissible_scoped`
are the complete, exact, private-only signature additions and their
migrated callers; there is no remaining open design question in this area.

## 5. Epoch-scoped consensus safety state

The ordered engine persists exactly two chain-only *mutable* safety
families under `ORDERED_ECONOMICS_STATE_PREFIX`: `state/` -- the
`OrderedStatus` record bundling `current_view`, `high_qc` and
`committed_height` (`crates/node-core/src/ordered_economics/engine.rs:430-460`),
the engine's entire persisted leader/vote/high-QC safety state -- and
`applied-height/` (`:484`), the business-applied prefix height. The other
chain-only families (`committed-proof/` keyed by `(chain, epoch, height)`,
and the write-once `candidate/`, `header/`, `outcome/` keyed by
digest/request id) are append-only history, already chain-wide and
untouched here. There is no third mutable safety family to namespace.

The successor needs its own counterpart for exactly these two rows, under
new, closed, distinct infixes `epoch-state/` and `epoch-applied-height/`,
keyed as `ORDERED_ECONOMICS_STATE_PREFIX || infix || encode_chain_id(chain)
|| protocol.get().to_be_bytes() || epoch.get().to_be_bytes() ||
encode_digest32(v3_anchor)`, checked against `validate_transactional_state_key`
like every other key this crate builds. Binding the anchor into the key
itself, not only into the row's content, means a different anchor is a
different key, not a content check a bug could skip. `classify_ordered_row`
gains exactly these two literal infixes in its existing `ConsensusControl`
match arms -- not a wildcard or prefix-wide exclusion -- so they need no
Logical provenance, exactly like `state/`/`applied-height/`/`candidate/`
today. No other frame id or key family is reserved by this section.

Both new rows must be read at `StateRevision::INITIAL` inside the
activation transaction (Section 6); a namespace with a non-initial
revision at either key refuses activation outright, never falling back to
"absent row means virgin." `epoch-applied-height/<chain,protocol,e+1,anchor>`
starts at 0; `epoch-state/<chain,protocol,e+1,anchor>` starts at
`engine.genesis_state()` under the same anchor. The original chain-only
`state/`/`applied-height/` rows are never written in a target and keep
carrying only the outgoing epoch's safety state for historical
reconciliation.

## 6. Atomic target activation

The operator retains the immutable bounded saved-cut package, history
export and readiness certificate the existing `ImmutableArchive` local
artifact library already handles for every other operator binary
(`apps/operator/src/immutable_archive.rs`; already used by
`business_import.rs`, `conditional_readiness.rs` and `ordered_seal.rs` via
`ImmutableArchive::open_read_only(directory).read(name, maximum)`). No new
generic archive, blob framework or PG/DO claim is introduced. `0x64D5`'s
binding to the exact package/plan/proof digests (Section 2) lets the host
verify these files are the correct ones without any filesystem path ever
entering a canonical frame. After activation the target never depends on a
live connection to the predecessor: only these locally retained files,
re-read and re-verified on every invocation (Section 8); missing or
corrupt files stop, never silently skip.

Because Section 3's verifier is cryptographic (signature/QC/proof
verification, not byte-equality of one specific signer subset), two
independently activated successors may legitimately retain different,
both valid, `CommittedBlockProof`/certificate signer subsets for the same
h and the same committed Seal -- exactly as DR-0169/DR-0178 already allow
for equivalent valid proof variants. Each host commits the exact verified
bytes *its own* Section 3 run accepted; Section 7's retry comparison is
against that same host's own previously landed record, never a
cross-host byte-equal requirement.

Before any write, a private destination check -- **this is where the
former registered-key/validator-id step now lives, never inside the
source-free verifier** -- does:

1. `import.observe_complete(destination, destination_blobs, operation)`
   (`crates/node-core/src/business_reconstruction/inactive_import.rs:326`)
   **in full**: exact `CompleteInactive` origin and complete progress
   match; every raw row and every bounded immutable body compared against
   the verified plan; the lifecycle re-read and re-compared after body
   verification to rule out a race; returns the fresh
   `(ImportProgress, PortableSnapshotToken)`. Reused exactly as written for
   DR-0176/0178's own readiness retention -- no new comparison function.
2. Read the `0x64D6` slot and require phase `Inactive` (empty record).
3. Require the destination's registered metadata validator id to be a
   member of Section 3's checked e+1 set, and require the existing
   `ReadinessSigningKey` (`crates/consensus/src/readiness.rs:38`,
   `public_key()`/`validator_id()`, reused as-is, no new adapter type) to
   report the exact installed public key the registered entry names. It
   signs nothing here. A retired validator D failing this check is refused
   **as a consensus signer** (membership), never as a ban on D's key for
   every purpose (Section 10).

A new optional capability, `SuccessorActivationRepository`, mirrors
`OutgoingSealRepository`'s shape (`crates/runtime/src/outgoing_seal.rs`):
native SQLite and explicitly domain-bound memory implement it; PostgreSQL,
Durable Object and every other facade default to unsupported, never
success.

```
commit_successor_activation(
    context, domain, subject, manifest, binding, progress,
    token: &PortableSnapshotToken, transaction: DurableInvocationTransaction,
    record: SuccessorServingRecord,
) -> DurableCommitOutcome
```

Inside one lock/transaction it checks, atomically with the write:

- namespace/domain fence and deadline;
- exact `CompleteInactive` origin matching `binding`/`progress`
  byte-for-byte;
- the token's namespace, domain, fence and sequence
  (`portable::PortableSnapshotToken`);
- outgoing barrier `Unsealed` (the destination has never itself Sealed;
  this is a fresh target, not a reused outgoing namespace);
- serving slot `Inactive`;
- the two epoch-scoped rows at `INITIAL` revision (Section 5);
- the three policy-provenance target keys and rows absent (Section 4);
- the Seal closure rows (h's archive row, header, outcome) and original
  receipt absent;
- the invocation's object-change set empty and outbox empty.

It then commits, as one `DurableInvocationTransaction`
(`crates/runtime/src/lib.rs:1918`): the two epoch-scoped safety rows; the
e+1 validator-set/execution/paid-fee/publication rows plus their three
provenance companions (Section 4); `FastPathEpochRecord` (`current = e+1`, digest =
field 11, `previous_epoch = Some(e)`, `activated_at_checkpoint = h`); the
Seal's h archive row, header, outcome and original receipt (DR-0187
closure, chain-wide, never per-epoch); the `0x64D5` record (field 5 bound
to this same `token`); the `0x64D6`
slot transitioning `Inactive -> Serving`; and the checked sequence advance.

Every existing ordinary commit port -- `commit_durable`, `commit_invocation`
for memory and shared SQL -- must additionally recheck, inside its own
existing lock, that the namespace is exactly `(Ordinary ∧ Unsealed ∧
Inactive)` **or** `(CompleteInactive ∧ Unsealed ∧ Serving)` before applying
any other mutation, exactly mirroring the existing outgoing-barrier
recheck. Import batch/finish and readiness retention continue to refuse
`Serving`, including a previously retained readiness response: Serving must
never look like a fresh importable or ready-to-sign target.

## 7. Reconciliation after Serving

Fresh reconciliation reads the `0x64D6` slot:

- **Inactive** -> rerun Section 3 and Section 6 in full, including the
  `observe_complete` comparison; an indeterminate or lost prior attempt
  left no landed evidence, so nothing is reused.
- **Serving(record)** -> verify the retained closure cryptographically:
  re-check the subject/manifest digests, the Seal closure rows, the
  original receipt and the e+1 policy/set rows **as currently installed**,
  comparing only this immutable activation evidence byte-for-byte. The
  record's own field 5 (0x64D2 creation observation) is retained immutable
  and is **never** required to equal the current invocation's fresh
  token: a token is single-use and advances every invocation by
  construction, so comparing it to the historical observation would
  always fail. Obtain a current token, validate it where Section 6 needs
  one, and return the retained record unchanged -- exactly DR-0178's own
  retry rule for its 0x64D2 observation. Never require the now-mutated
  business inventory (objects, nonces, escrows advanced by e+1 traffic) to
  equal the original raw plan again; never reset or rewrite mutable safety
  or business state on this path. Return `AlreadyActivated`.
- **A different record** -> refuse; no overwrite, no repair.

Startup re-verifies the same closure -- certificate, every QC and proof in
the Seal suffix, and the currently installed rows -- before binding any
listener (Section 9); it never trusts a cached "active" flag from a prior
process.

## 8. Per-invocation serving authority

`node_core::serving_authority::resolve_live_authority(store, context,
domain, &root, &schedule, &artifacts) -> LiveWarrant<'inv>` replaces the
`require_ordinary_namespace`/`require_ordinary_reader_namespace` gates
(`crates/node-core/src/mutation_fence.rs:60,82`; 47 call sites across 19
files) at every one of their existing call sites. `artifacts` is a
host-owned reader over the Section 6 retained `ImmutableArchive`
directories. `LiveWarrant` has a crate-private constructor, implements no
`Default`, `Clone` or serialization trait, and carries the reads it fences.

- `Ordinary ∧ Unsealed ∧ serving Inactive` -> `OriginalGenesis`, unchanged
  existing behavior.
- `CompleteInactive ∧ Unsealed ∧ Serving` -> `Successor`. The resolver
  reads the retained manifest's exact package/history/certificate
  references, **re-invokes Section 3's `verify_successor_activation` in
  full** against those retained bytes -- the complete history replay,
  Seal proof check, certificate verification and eligibility
  re-derivation, not a digest or tag recompute -- and requires the result
  to match the `0x64D5` record's subject/manifest fields exactly. It then
  re-checks Section 6's destination-specific facts (registered validator
  id and installed key) against the current metadata. No step is a
  cheaper shortcut of Section 6's original check; this is the same cost,
  repeated by design on every invocation.
- **Anything else refuses.** `Ordinary ∧ Serving` is corruption, not a
  degraded mode.

This resolver is additive. `NamespaceLifecycle::is_ordinary()` and every
other existing public raw-store permission check are **unchanged**; they
keep treating any `CompleteInactive` namespace, Serving or not, as
non-ordinary. A call site not yet migrated to `Successor` authority
therefore keeps refusing a successor store exactly as it refuses any
import-origin store today -- nothing is silently widened by adding this
resolver. FastVote env, ordered-economics env, paid/claim evaluation and
native-http's cached-signature exposure are each migrated to accept an
opaque, invocation-scoped `&LiveWarrant<'_>` (never `'static`, never
stored past the call) from the host that owns the pinned root, schedule
and artifacts reader, instead of reading `NamespaceLifecycle` or a boolean
tag directly; each gets its own narrow entry taking the warrant, while the
original wrappers stay correctly Ordinary-only. The warrant's own fenced
reads merge into whatever CAS set the eventual mutation commits, so this
full re-verification is part of the same atomic transaction as the
resulting write, not a separate, unlinked check.

This re-verification is never cached and runs on **every** invocation,
including repeated calls within one process lifetime, matching Section
3's "no memoization" rule at this layer. Original-receipt replay still
runs first, chain-wide, ahead of this resolver. Cached FastVote/ordered/
ACK/frontier exposures still require warrant epoch = message epoch; no
e-epoch cached signature can exist in a fresh target, because import
excluded live-signing rows (DR-0176).

At `Successor` authority, readiness (new and retained),
Freeze/DrainSet/Seal, initial registration, `install_ordered_genesis` and
legacy `activate` must all refuse with a typed error **before any
signing**, because a `CompleteInactive` origin never becomes a fresh-import
or outgoing-signing target. These refusals are explicit call-site changes
this contract requires, not an emergent property of the resolver alone.
Historical read-only open, export and query paths remain legal at
`Successor` authority and may relay the Seal and its QCs without signing.

## 9. Ordered and FastVote policy at e+1

`OrderedEconomicsPolicy::from_successor(&root, &SuccessorAuthority, domain)`
is a third constructor alongside the existing
`from_genesis_root`/`historical`
(`crates/node-core/src/ordered_economics/policy.rs:149,183`). It takes the
checked `ctx@e+1`, the **original** (never replaced) pinned genesis digest,
the e+1 `ValidatorSet` and the v3 anchor from Section 2, and is the only
constructor that selects an epoch-scoped engine/key family. It requires a
reviewed extension of `ordered_economics_authority_anchor` itself to accept
Section 2's v3 preimage inputs (predecessor genesis digest and signed
`minimum_freeze_block_height` unchanged, subject digest as the new field
10) rather than inventing a parallel anchor function;
genesis policies keep deriving byte-identical chain-only v1/v2 anchors and
keys unchanged. No caller-supplied epoch or a peer's `epoch-repin-required`
hint may select a policy or key family; only this constructor, fed only by
Section 3's verified evidence, may.

FastVote reuses `load_validator_set` at `ctx@e+1`
(`crates/node-core/src/fast_path.rs`) against the already-installed e+1
validator-set row. Nonce and object-lock fences already take the epoch and
need no change. The SDK gains `load_successor_authority(root, package)`,
which runs Section 3's verifier (history, Seal, certificate,
eligibility) to build the e+1 certifier and
`OrderedEconomicsPolicy::from_successor` inputs; the client authenticates
the e+1 set itself rather than trusting a destination's claim.

## 10. New-epoch business admission uses imported instances and original receipts

The successor's e+1 consensus anchor and height-zero safety namespace
(Section 5)
are not a replacement genesis manifest and do not change historical
object/code/instance provenance: `paid_execution.rs` already checks only
`chain_id` and `protocol_version` of a called instance's context against
the active admission profile
(`crates/node-core/src/paid_execution.rs:1438-1439`), **not** epoch, so a
paid `Call` against an instance created in epoch e already admits unchanged
at e+1. Fee-claim settlement already verifies at the claim's own historical
`certificate_epoch` (`crates/node-core/src/fee_claims.rs:1119`), not the
current epoch, so a claim against an imported epoch-e escrow needs no
re-signing or fee reapplication. This activation adds no new check to
either path; Section 14's acceptance tests exercise both unmodified behaviors
directly against the new e+1 authority.

A retired validator D is refused only by Section 6's **consensus-signer**
membership check and the gates Section 8 adds ahead of signing. D's ordinary
requests -- including `BondLifecycleOperation::Withdraw`
(`crates/node-core/src/bond_lifecycle.rs:218`), a signed-sender operation
authenticated like any other business intent -- are unaffected by this
design and remain a separately reviewed unlock question (Section 15), not a
refusal this contract introduces.

## 11. Storage schema

| Store | Change |
| --- | --- |
| Shared SQL | `SQL_DURABLE_SCHEMA_IDENTITY` (`crates/runtime-sql-durable/src/schema.rs:36`) v5 -> v6: mandatory `durable_successor_serving(id = 1 CHECK, serving BLOB <= 17408)`, created `Inactive` with every namespace. Read phase and length before fetching the record body. |
| Native SQLite | `STRUCTURED_SCHEMA_VERSION` (`crates/runtime-sqlite/src/structured.rs:56`) 4 -> 5. Add `open_successor_activation`/`open_successor_serving`; ordinary `open` still refuses import origin. |
| PostgreSQL | Aligned mandatory row only: `POSTGRES_SCHEMA_GENERATION` (`crates/runtime-postgres/src/lib.rs:71`) 6 -> 7, `Inactive` only, read port and ordinary-port backstop. No activation capability. Any claim or change here requires the full selected PG acceptance gate (DR-0172), not a new blanket PG requirement. |
| Durable Object / other | Shared DDL only; no capability; existing Cloudflare checks run unchanged. |

Older initialized files are unsupported: no migration, repair or reset. The
base `DurableDomainStateStore`/`StructuredStateReader` ports
(`crates/runtime/src/lib.rs:2716`) gain a required `read_successor_serving`
with **no default**, exactly matching how `get_outgoing_barrier` and
`get_namespace_lifecycle` already have none.

## 12. Executables and workflows

- `apps/operator/src/bin/successor_activation.rs` (new, alongside
  `business_import.rs`/`conditional_readiness.rs`/`ordered_seal.rs` in the
  same directory): inputs are the pinned genesis file/digest, schedule
  config, domain, saved cut package, history export, readiness certificate,
  target SQLite file and the local key file. Runs Sections 3 and 6 and
  prints the subject and manifest digests.
- `apps/operator/src/bin/successor_host.rs` (new): binds loopback only
  (`127.0.0.1`/`::1`; any other address is refused before listening).
  Independently pins genesis and schedule and owns its own writer fence.
  Serves the existing native-http ordered/FastVote/paid/claim/receipt/query
  routes over SQLite with `OrderedEconomicsPolicy::from_successor`.
- Exporting the Seal suffix reuses the existing `cli history_export`
  against a Sealed source's historical read-only open (DR-0187).
- Workflows reuse the existing `ordered_economics_network`,
  `fastvote_network` and `paid_execution` test compositions, with the
  SDK's `load_successor_authority` feeding the e+1 authority from the
  package.

## 13. Operational scope and fault model (not a blanket accepted risk)

Two hazards are explicitly out of this protocol's detection scope, with
their exact boundary stated rather than labeled "accepted":

- **Same signing key activated into two independently provisioned
  successor namespaces.** Each namespace's own virgin-`INITIAL` check
  (Section 5)
  proves only that *that* namespace never signed before; it is not, and
  cannot be, global proof that the key never signed elsewhere. Preventing
  this requires operational custody control of the key across namespaces,
  outside this design. If it happens anyway, the existing equivocation
  evidence and slashing path (`crates/node-core/src/equivocation.rs`) is
  the only detection mechanism, and only once conflicting signed messages
  are actually observed by a third party -- there is no proactive protocol
  check.
- **Whole-database rollback of an activated successor to its prior
  `Inactive`/pre-activation state.** Ordinary CAS/fencing cannot detect a
  mutually consistent rollback of the entire store without an independent
  external anchor (unchanged from DR-0178/DR-0187's own statement of this
  limit).

Both require one controlled key/namespace per outgoing predecessor and an
independent anchor as an operational precondition for the safety claims in
Sections 1-9 to hold; this contract does not claim to enforce either precondition
in software.

## 14. Acceptance unit

**Genuine flow:** PR #265's real A/B/C/D Seal over TCP -> A/B/C/E SQLite
staging with genuine E registration (DR-0179) -> `successor_activation` ×4
-> four `successor_host` processes -> existing CLI over TCP. Required
outcomes: e+1 ordered and FastVote quorum; a new paid
`Instantiate`/`Call`, including a `Call` on an instance imported from
epoch e; a fee claim against imported epoch-e escrow; byte-equal replay of
the Seal receipt and other original receipts on every successor.

**Negatives:** D's key or namespace refused for activation and votes but
not for `Withdraw`; e-epoch votes, QCs and legacy transition certificates
refused at e+1; wrong subject/manifest/certificate/history, or a
non-terminal or extra Seal; T mismatch; ineligible set; wrong key; bad pins
or schedule; a repin hint; a public "active" tag or caller-supplied
context; `Ordinary ∧ Serving`; a present e+1 policy row with no matching
provenance row (Section 4's fail-closed case, exercised deliberately).

**Durability and races:** SQLite restart and refencing; stale fence and
token; inventory race between plan comparison and commit; both reply-loss
directions; corrupt or missing serving row and blobs; tombstoned e+1 keys;
signer counters stay zero before Serving; non-loopback bind refused.

**Vectors:** independent stable vectors for every new frame and the v3
anchor. Older vectors stay unchanged. `generation_floor`-vs-`genesis_floor`
has its own dedicated vector pair.

**Gate:** `npm ci --prefix adapters/cloudflare-workers` and
`./scripts/check-all.sh`, plus the full selected PG acceptance for the
schema change (DR-0172).

## 15. Out of scope

Recurring Freeze/DrainSet/Seal and predecessor reconstruction for a second
successor; genuine `Unbond`/`Withdraw` unlock for D; PostgreSQL or Durable
Object activation production; independent security audit; Delivery 3
completion. Section 4's `GenerationScope`/`derive_scoped`/
`require_application_admissible_scoped` additions close the generation-floor
question in full; every field, phase, bound, digest purpose and allocation
in this contract is closed, with no outstanding design question.
