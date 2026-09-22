# DR-0131: FastVote validator lifecycle and mutation fencing (phase 2, slice 1)

## Status

Accepted as the Phase 2 architecture, 2026-09-22. Slice 1 is fully specified
and implemented. Slices 2-4's safety contract — in particular the key
transition safety proof below — is fixed by this DR. DR-0132 and DR-0133
implement Slices 2 and 3; [DR-0134](0134-fastvote-authorization-boundary.md)
accepts Slice 4's authorization and ingress decision. Slice 4 and Phase 2 are
implemented only when DR-0134's companion code, tests, complete gate, and fresh
reviews land.
[DR-0132](0132-fastvote-epoch-transition.md) fixes Slice 2's detailed
design (wire format, API, activation write set, reclamation rule) and
corrects seven assumptions this DR made about the transition (C1-C7 in
DR-0132; C1, C3, and C7 are blocking-severity — the restart-verify check
below and the epoch-scoped policy rows in the "Two-tier fence model" section
would otherwise brick a node on restart or leave epoch `e+1` unable to
execute anything). **Slice 2 is now implemented** (DR-0132, 2026-09-22),
making retired-validator and wrong-epoch rejection end-to-end observable
through a real outgoing-set-certified `e -> e+1` transition for the first
time. Phase 2 remains open until DR-0134's companion implementation and
reviews land. Retired-validator and wrong-epoch rejection were
enforced by Slice 1's fencing from day one, but had no observable
end-to-end effect beyond what
[DR-0130](0130-owned-object-certified-execution.md) already verified
(membership against one static genesis set) until Slice 2's transition
existed. Completing Slices 1-2 does not close the FastVote Certified
Execution Gate's Phase 2 entry in `TODO.md`. FastVote remains incomplete
until Phase 3. [DR-0133](0133-fastvote-equivocation-evidence.md) implements
Slice 3's evidence envelope, conflict keys, historical verification rule,
and persistence key.

## Context

[DR-0130](0130-owned-object-certified-execution.md) ("phase 1") implemented
local certified execution — prepare/apply, durable object and nonce locks,
byte-stable votes, and atomic certificate apply — against one static signed
genesis validator set for one frozen epoch. It deliberately left validator
lifecycle undesigned and recorded, as its own deferred scope: validator-set
changes, equivocation evidence, and multi-validator fault/restart tests
beyond its own Phase 1 evidence, with the explicit constraint that "Phase 2's
validator lifecycle design must guarantee that any recovery procedure it
introduces can never permit two conflicting certificates to apply for the
same object version."

`TODO.md`'s FastVote Certified Execution Gate names Phase 2 as "validator
lifecycle: epoch/validator-set transitions, retired/wrong-epoch rejection,
relay/event-family authorization, explicit equivocation evidence, and
multi-validator fault/restart tests." This DR fixes that architecture and
splits its implementation into four slices, for the same reason DR-0130
delivered Phase 1 as one coherent slice rather than standalone codec/
validator/witness PRs: epoch transition, equivocation evidence, and the
ingress/authorization boundary are each large enough, and each depends on
the general fencing layer below existing first, to warrant their own
implementation slice and their own review.

**"Retired validator" means only: absent from the committed current epoch's
validator set.** The only way a validator becomes absent is Slice 2's
outgoing-set-certified `e -> e+1` transition. Slice 1 defines no post-genesis,
locally mutable membership action of any kind; independently operated nodes
must never derive different active authority sets from local configuration.

## Decision

### Phase 2 slice roadmap

* **Slice 1 (this DR, implemented).** One general
  mutation authorization/fencing layer: a committed epoch record, an
  epoch-stamped object-lock record, a two-tier fencing model (every
  mutation path fences the committed epoch record; validator-authorized
  prepare/apply additionally fences the active per-epoch validator-set row),
  local signer-membership rejection against the one committed active set
  (no separate retirement action), duplicate validator public-key rejection,
  one shared external-`RequestId` validation boundary plus a distinct
  internal/system construction path for node-owned synthetic IDs, and
  closed direct object-lock branch gaps. No epoch-transition procedure
  exists yet; `FastPathEpochRecord` never changes after genesis in Slice 1.
* **Slice 2 (architecture fixed here; detailed design accepted and
  implemented in [DR-0132](0132-fastvote-epoch-transition.md)).**
  The actual epoch transition: an outgoing-set-certified strict `e -> e+1`
  transition, byte-stable transition votes, atomic next-set/epoch
  activation, and lazy stale-lock reclamation under CAS — safe only because
  of the key transition safety proof below, never a timeout. Requires
  four-independent-SQLite fault/restart evidence for the transition itself.
  Retired-validator and wrong-epoch rejection are now end-to-end observable.
  DR-0132 also corrects seven of this DR's own assumptions that would
  otherwise block Slice 2 (see Status).
* **Slice 3 (implemented in
  [DR-0133](0133-fastvote-equivocation-evidence.md)).**
  Explicit canonical equivocation evidence covering same-transaction
  conflicting-outcome, cross-transaction same-object-version, and
  epoch-transition conflicting-target misconduct, normalized so Phase 3
  slashing can consume it later. DR-0133 does add `locked_objects_digest`,
  extending `FastVote`/`FastCertificate`'s canonical v1 payload in place (no
  v2, this repository is unreleased) — the cross-transaction case cannot be
  evidenced without it. No economics (bonding, penalties, distribution)
  implemented.
* **Slice 4 (decision accepted in
  [DR-0134](0134-fastvote-authorization-boundary.md); implementation pending
  its companion code and reviews).**
  Declares which authorization class each Phase 2 mutation belongs to
  (local-operator-authorized vs. validator-authenticated vs. still-closed
  external ingress), states that the external ingress boundary remains
  closed by default, and closes the Phase 2 gate entry in `TODO.md` and this
  ADR index once Slices 1-3 are implemented and reviewed.

**Phase 2 is not complete until DR-0134's implementation gate closes**, and FastVote overall
remains incomplete until Phase 3 (bond-linked slashing execution and
deterministic transaction-fee escrow distribution to the final certificate
signer set), unaffected by this DR.

### Slice 1: general mutation authorization/fencing layer

Slice 1 does not add validator-set rotation. It adds the durable state and
the one shared fencing model that every current mutation path uses and that
Slice 2's transition serializes against, so there is one enforcement point
to extend rather than several ad hoc ones to find and fix.

1. **Committed epoch record.** A new singleton record, `FastPathEpochRecord`
   (frame `0x6426`, v1), becomes the fenced source of truth for the fast
   path's current epoch and active validator-set identity, in place of
   scattered reads of the static signed-genesis manifest. It is created
   once, atomically with genesis validator-set activation (extending
   DR-0130's existing genesis-install commit rather than adding a second
   commit), and holds only the committed lifecycle data consensus needs:
   - chain/protocol context fields, only if the frame's own domain
     separation requires them (consistent with this workspace's other
     context-bound frames).
   - `current_epoch`: the current active `Epoch`.
   - `current_validator_set_digest`: the active `ValidatorSet::digest()`,
     binding which validator set is active without embedding its contents.
   - `previous_epoch` (optional): the prior active `Epoch`, for audit/
     transition bookkeeping; absent at genesis, populated starting at
     Slice 2's first transition.
   - `activated_at_checkpoint`: the durable checkpoint/commit-sequence
     marker at which this record's current state became active, following
     the same `installed_at_checkpoint: u64` convention DR-0121's genesis
     install marker already uses.

   There is no `retired_validators` field and no invented
   `validator_set_revision` field inside this record. The record's own
   durable-store revision (the same generic CAS/version every other
   versioned record in this workspace already carries) is the fence for
   *this* record; a validator set's own identity/membership is a separate,
   already-persisted per-epoch `ValidatorSet` row (DR-0130's existing
   `fastpath_validator_set_key`, extended to be keyed by epoch under
   Slice 2), whose own durable revision validator-authorized paths
   read-assert directly (see "Two-tier fence model" below) — not a second,
   redundant revision number invented inside `FastPathEpochRecord`.

   The exact canonical field order and wire layout are an implementation
   detail pinned by their own stable Rust/JS vector, following DR-0130's own
   precedent for its staged-commit commitment frame.

2. **Epoch-stamped object lock.** `FastPathLockRecord` (frame `0x641B`,
   canonical version 1) is **redefined in place** to add `locked_epoch:
   Epoch` alongside its existing fields (owning request ID, exact
   `(ObjectId, version, digest)`). This repository is unreleased: there is
   no v1/v2 split and no obsolete layout preserved for compatibility — the
   version-1 wire layout simply changes. Every lock-acquisition site stamps
   `FastPathEpochRecord.current_epoch` as it stood at the moment of the same
   durable CAS commit that creates the lock. Apply verifies that stamp against
   its certified/current epoch; Slice 1 still performs no reclamation with it.
   The field also gives Slice 2's lazy stale-lock reclamation the data it needs
   without a later migration.

3. **Two-tier fence model.**
   - **Every mutation path** — fast-path prepare, fast-path apply, and every
     direct/non-paid mutation path that can consume/write a sender-owned
     object or a sender/epoch nonce — reads `FastPathEpochRecord` and
     CAS-fences it (asserts its durable revision unchanged) as part of the
     same commit that mutates any object lock, nonce lock, or owned object,
     and honors any `FastPathLockRecord`/sender-nonce-lock already present.
     This is the property that serializes every ordinary mutation against a
     concurrent Slice 2 transition: because both an ordinary mutation's
     commit and a transition's commit CAS-fence the identical
     `FastPathEpochRecord` row, they cannot interleave inconsistently (see
     "Key transition safety proof"). Direct, non-fast-path mutation paths
     are **not** required to read anything beyond this one record plus the
     locks they actually touch — they do not need the per-epoch
     validator-set row, since the epoch record's digest already binds
     validator-set identity for anything that later needs to check it.
   - **Validator-authorized prepare/apply additionally** reads the active
     per-epoch `ValidatorSet` row and CAS-fences it (asserts its own durable
     revision unchanged) in the same commit, and verifies
     `digest(that row) == FastPathEpochRecord.current_validator_set_digest`
     before accepting any vote, certificate, or certificate signer bound to
     it. This is strictly additive to the general fence above, not a
     replacement for it: prepare/apply fence both records in the same
     commit.

4. **Local signer membership rejection.** This is the entirety of Slice 1's
   "retired validator" concept. Prepare/apply reject a vote, certificate, or
   certificate signer whose `ValidatorId` is not a member of the currently
   committed per-epoch `ValidatorSet` row fenced in item 3. There is no
   separate, post-genesis, locally mutable retirement list, action, flag, or
   record. Because Slice 1 defines no transition procedure, this committed
   set never changes after genesis in Slice 1; the check is real and
   enforced from Slice 1's first commit, but a validator only actually
   becomes non-member — "retired" in the only sense this design recognizes
   — once Slice 2's transition commits a new per-epoch `ValidatorSet` row
   that excludes it.

5. **Duplicate validator public-key rejection.** `validator_set::
   ValidatorSet` currently rejects a duplicate `ValidatorId`
   (`ValidatorSetError::DuplicateValidator`) but not two distinct
   `ValidatorId`s sharing an identical `public_key`, which would let one
   physical signing key claim two voting-power slots or masquerade as two
   validators. Slice 1 adds this check wherever a `ValidatorSet` is
   admitted: at genesis load in Slice 1 (Slice 2's transition activation
   reuses the same check, not a second one).

6. **One shared external-request validation boundary.** DR-0130's reserved
   synthetic fast-path namespace (`FASTPATH_SYNTHETIC_REQUEST_ID_TAG`) must
   never be constructible by an externally supplied `RequestId`, on any
   event/mutation family, not only the paid-execution call site. Slice 1
   defines this as one shared validation function on the boundary every
   externally reachable event/mutation family already passes through before
   admission — not necessarily the same general-purpose constructor
   node-owned code uses internally, since that constructor is also needed
   to build the reserved synthetic IDs themselves. Concretely: a general
   `RequestId` value can be produced by either (a) the external admission
   boundary, which validates an externally supplied byte string and rejects
   any value inside the reserved namespace, shared by every event family, or
   (b) an explicitly named internal/system construction path reserved for
   node-owned callers (for example DR-0130's own synthetic prepare-receipt
   ID), which is never reachable from external input and is therefore
   exempt from the external-namespace check by construction, not by an
   ad hoc bypass. The exact function/module names are an implementation
   detail; the invariant is that no externally reachable admission path can
   ever construct or accept a `RequestId` inside the reserved namespace,
   enforced once at the shared boundary, not duplicated per family.

7. **Closed direct object-lock branch gaps.** DR-0130 exercised conflicting-
   lock rejection through the paid path's known branches. Slice 1 audits
   every direct (non-fast-path) mutation branch that can write a
   sender-owned object and routes each one through the general fence in
   item 3, with dedicated test coverage proving a fast-path lock now blocks
   a branch DR-0130's evidence did not cover.

**No epoch transition procedure exists in Slice 1.** The only way
`FastPathEpochRecord.current_epoch` or `current_validator_set_digest` could
change is Slice 2's transition procedure, which this DR does not implement.
Slice 1 introduces no post-genesis write to `FastPathEpochRecord` at all.
Wrong-epoch and non-member rejection are real, fenced checks from Slice 1's
first commit; they are simply not exercised beyond genesis state until
Slice 2 exists.

## Key transition safety proof

This is the safety contract Slice 2's implementation must satisfy; Slice 1
lays the durable groundwork (the CAS-fenced epoch record and the
epoch-stamped lock) that makes the proof possible.

1. **Three-way epoch equality at apply.** Apply requires `prepared epoch ==
   certificate epoch == current committed epoch` (`FastPathEpochRecord.
   current_epoch` read inside apply's own fenced commit). A certificate
   formed under any other epoch fails this check and is rejected without
   mutating state, exactly as DR-0130 already rejects a commitment mismatch.
2. **Shared CAS fence.** Apply and transition both CAS-fence the identical
   `FastPathEpochRecord` row: apply's commit asserts the row's durable
   revision unchanged as a precondition of its own commit; transition's
   commit is the only operation that legitimately advances that revision
   (by writing a new `current_epoch`/`current_validator_set_digest`). Two
   commits contending for the same row's CAS revision cannot both succeed —
   exactly one wins, by this workspace's existing durable-store CAS
   semantics (the same mechanism DR-0130's own atomic apply already relies
   on).
3. **Serialization, not interleaving.** Because apply and transition
   contend on the same CAS-fenced row, one of exactly two orderings holds,
   never a third: either transition commits first — in which case apply's
   epoch read already observes the new epoch, and a certificate formed
   under the old epoch fails the three-way equality check in item 1 — or
   apply commits first — in which case apply completes fully (effects, fee,
   nonce, receipt, lock release) while the row's revision is still the old
   one, and transition's own CAS-fenced commit only proceeds against that
   already-consistent post-apply state. There is no interleaving in which
   both partially apply against inconsistent epoch state, because the CAS
   fence gives exactly one global serialization point per epoch-record
   revision.
4. **Old certificates are permanently invalid, not just stale.** Once a
   transition commits, every certificate formed under the retired epoch
   fails item 1's equality check forever — there is no grace window, replay
   path, or fallback to the old epoch. This is exactly why a lock stamped
   `locked_epoch = <retired epoch>` can be lazily overwritten under CAS by a
   new, current-epoch lock attempt (Slice 2) without ever risking two
   conflicting applies for the same object version: the only certificate
   that could ever have legitimately applied against that stale lock is now
   permanently unappliable, so reclaiming the lock cannot race a still-live
   old-epoch apply. This is the same guarantee DR-0130 already requires of
   any Phase 2 recovery procedure ("can never permit two conflicting
   certificates to apply for the same object version"), restated precisely
   in terms of the CAS-fenced epoch record.
5. **No timeout anywhere.** No timeout-based or clock-based unlock exists in
   Slice 1 or in Slice 2's lazy reclamation design. Reclamation eligibility
   is derived purely from the permanent invalidity of the old epoch's
   certificates after a CAS-fenced transition commit (item 4), never from
   elapsed time.

## Safety invariants

- Every mutation path that can consume/write a sender-owned object or
  advance a sender nonce reads and CAS-fences `FastPathEpochRecord` as part
  of the same durable commit that mutates any lock or owned state (see
  "Two-tier fence model").
- Validator-authorized prepare/apply additionally read and CAS-fence the
  active per-epoch `ValidatorSet` row in the same commit, and verify its
  digest matches `FastPathEpochRecord.current_validator_set_digest`.
- A request bound to a non-current epoch, or attributed to a `ValidatorId`
  absent from the currently committed per-epoch `ValidatorSet` row, is
  rejected before any lock, execution, or mutation, on every entry point.
- No two `ValidatorInfo` entries in an admitted `ValidatorSet` may share an
  identical `public_key`.
- Every `FastPathLockRecord` commit stamps the exact
  `FastPathEpochRecord.current_epoch` active at that moment; nothing
  reinterprets or clears that stamp in Slice 1.
- No externally reachable admission path can construct or accept a
  `RequestId` inside the reserved fast-path synthetic namespace; this is
  enforced once, at one shared boundary used by every event/mutation
  family, and never duplicated per family.
- Slice 1 defines no locally mutable membership state of any kind. The
  committed per-epoch `ValidatorSet` is the single, store-wide source of
  truth for membership; no node can unilaterally narrow or widen it outside
  a CAS-fenced transition commit.
- Apply and transition are mutually exclusive per epoch-record revision (see
  "Key transition safety proof"); Slice 1 introduces no timeout/clock-based
  unlock, no lock reclamation, and no new externally reachable event family.
  Lock recovery for an intent whose certificate never forms remains exactly
  as permanent as DR-0130 left it; only Slice 2 changes that, and only via
  the CAS-fenced reclamation described above.

## Slice completion criteria

Slice 1 is complete only when all of the following hold, evidenced the same
way as prior decision records in this index (stable vectors, adversarial
tests, complete repository gate, fresh tech-lead and security review):

1. `FastPathEpochRecord` (`0x6426`/v1) exists, is created atomically with
   genesis validator-set activation, holds only `current_epoch`,
   `current_validator_set_digest`, optional `previous_epoch`, and
   `activated_at_checkpoint` (plus context fields if the frame needs them),
   and is the single fenced source of current epoch and active
   validator-set identity read by every fast-path and direct mutation path.
2. `FastPathLockRecord` (`0x641B`, canonical v1) carries `locked_epoch`,
   stamped at every lock-acquisition site; no lock is created without it.
3. Every mutation path that can consume/write a sender-owned object or a
   sender/epoch nonce CAS-fences `FastPathEpochRecord` in its own commit;
   validator-authorized prepare/apply additionally CAS-fence the active
   per-epoch `ValidatorSet` row and verify its digest against the epoch
   record, in the same commit.
4. A request bound to a non-current epoch is rejected before any lock,
   execution, or mutation, on every entry point, each with dedicated test
   coverage.
5. A vote/certificate/prepare/apply request attributed to a `ValidatorId`
   absent from the currently committed per-epoch `ValidatorSet` is rejected,
   with dedicated test coverage. No test or code path exercises a locally
   mutable retirement action, because none exists.
6. Two `ValidatorInfo` entries sharing an identical public key are rejected
   wherever a `ValidatorSet` is admitted, with test coverage distinct from
   the existing duplicate-`ValidatorId` coverage.
7. The reserved fast-path synthetic `RequestId` namespace is rejected once,
   at the shared external-request validation boundary, for every event/
   mutation family; a distinct, explicitly named internal/system
   construction path exists for node-owned synthetic IDs and is not
   reachable from external input.
8. At least one previously uncovered direct mutation branch is proven, by a
   new test, to now honor a held `FastPathLockRecord` that it did not
   consult before this slice.
9. Stable Rust hex vectors for `FastPathEpochRecord` (`0x6426`) and the
   redefined `FastPathLockRecord` (`0x641B`), each independently
   reconstructed byte-for-byte in JavaScript with no Rust encoder invoked
   (this workspace's dual Rust/JS-vector convention), wired into
   `scripts/check-all.sh`.
10. `cargo fmt --all`, the workspace tests and Clippy checks, and the
    complete `./scripts/check-all.sh` gate pass on the integrated diff, plus
    a focused security review and a fresh tech-lead review; a later code
    change invalidates those reviews and requires them to be refreshed.

Slice 1 satisfying these criteria does not by itself authorize testnet or
production activation of any new ingress, and does not close the FastVote
Certified Execution Gate's Phase 2 entry in `TODO.md` — that requires
Slices 2-4. Retired-validator and wrong-epoch rejection had no end-to-end
observable effect beyond genesis-set membership until Slice 2 shipped a
real transition ([DR-0132](0132-fastvote-epoch-transition.md), implemented).

## Consequences / Deferred

- Epoch transition (`e -> e+1`), byte-stable transition votes, atomic
  next-set/epoch activation, and lazy CAS-fenced stale-lock reclamation were
  Slice 2's own scope; their safety contract is fixed by the "Key transition
  safety proof" above and their detailed design and implementation are now
  in [DR-0132](0132-fastvote-epoch-transition.md).
- Explicit canonical equivocation evidence, including the in-place
  `FastVote`/`FastCertificate` `locked_objects_digest` extension, is
  implemented by [DR-0133](0133-fastvote-equivocation-evidence.md).
- [DR-0134](0134-fastvote-authorization-boundary.md) declares Slice 4's
  authorization classes and still-closed external boundary. Phase 2 closes
  only when its companion code and review gate land.
- Lock recovery for an intent whose certificate never forms is unchanged
  from DR-0130: permanent until apply, with no timeout or clock-based
  unlock. Slice 1 adds no recovery path; it only adds the epoch stamp
  Slice 2's CAS-fenced reclamation will read.
- Slice 1 defines no local validator retirement or other locally mutable
  membership state. A validator's absence from the active set is meaningful
  only after a CAS-fenced Slice 2 transition, which every node observes
  identically through the same committed `FastPathEpochRecord` and per-epoch
  `ValidatorSet` row.
- Bond-linked slashing execution and deterministic transaction-fee escrow
  distribution to the final certificate signer set remain Phase 3,
  unaffected by this DR.
- This DR does not change DR-0129's `crates/consensus` types, wire IDs, or
  signature domain, and does not change DR-0130's Phase 1 invariants except
  by adding the fencing/epoch-stamp layer described above.
- This repository is unreleased, so Slice 1 changed the durable canonical
  layout in place rather than adding a migration: `FastPathLockRecord`
  (`0x641B`) gained `locked_epoch` as a breaking wire-layout change to an
  existing frame, and genesis installation now atomically creates the new
  `FastPathEpochRecord` (`0x6426`) singleton alongside the existing
  DR-0130 genesis-install commit. There is no v1/v2 split, no compatibility
  shim, and no migration path from a pre-DR-0131 local database: any local
  database created before this change must be recreated (re-run genesis
  installation from scratch) before running node-core built from this DR.
  Both restart-verify and every authenticated mutation path fail closed
  against exactly that absent-singleton state, rather than silently treating
  the fast path as unfenced: `genesis::install_genesis_with_history`'s
  `VerifiedExisting` path now also byte-for-byte re-verifies the installed
  `FastPathEpochRecord`, returning `GenesisError::TamperedInstalledRecord
  ("fast-path epoch record")` when it is absent or different; and every
  authenticated mutation path's shared fence
  (`mutation_fence::fence_epoch_state`) returns
  `NodeCoreError::PersistenceInvariant("fast-path epoch record not
  installed")` when it is absent.

## Slice 1 implementation status (2026-09-22)

Slice 1 is implemented, satisfying the ten completion criteria above:

- `FastPathEpochRecord` (`0x6426/v1`) and the redefined `FastPathLockRecord`
  (`0x641B`, canonical v1, now carrying `locked_epoch`) are implemented in
  `crates/node-core/src/local_instance_state.rs`. The epoch record is
  created atomically with genesis validator-set activation in
  `crates/node-core/src/genesis.rs::install_genesis_with_history`, reusing
  the existing `installed_at_checkpoint` marker rather than a second commit,
  and is verified byte-for-byte on the existing restart-verify path.
- The shared two-tier fencing model lives in
  `crates/node-core/src/mutation_fence.rs` (`fence_current_epoch`,
  `fence_object_lock`, `fence_sender_nonce_lock`). It is called from
  `paid_execution::build_paid_admission` (shared by the direct paid path and
  both fast-path entry points), `local_execution::handle_local_execution`,
  `publication::handle_local_publication_with_history`, and the shared durable
  boundary for every authenticated `SubmitTransaction` path that advances a
  nonce (object-read-only, owned-effects, and preinstalled WASM).
  Validator-authorized prepare/apply additionally
  fence the active per-epoch `ValidatorSet` row and check its digest against
  the epoch record in `fast_path::load_validator_set`.
- Local publication's own `policy.context.epoch()` is a historical
  code/policy-version selector, not a claim about which epoch is currently
  committed (DR-0121's pre-existing historical-epoch publication support
  predates and is orthogonal to fast-path lifecycle); Slice 1 therefore
  CAS-fences the epoch record and honors its sender/epoch nonce lock, but uses
  `fence_epoch_state` rather than reinterpreting that historical selector as a
  current-transaction epoch claim. Every other mutation path's declared epoch
  is rejected when it disagrees with the committed epoch record.
- Local signer/certificate-signer membership rejection required no new
  check: `consensus::FastPathCertifier::cast_vote`/`verify_vote`/
  `verify_certificate` already reject an unknown `ValidatorId` via their own
  bound `ValidatorSet` lookup; Slice 1's contribution is binding that
  `ValidatorSet` to the CAS-fenced, digest-verified committed row.
- Duplicate validator public-key rejection is
  `validator_set::ValidatorSetError::DuplicatePublicKey`, enforced in
  `ValidatorSet::new` and therefore automatically covering both fast-path
  installation and genesis installation.
- The one shared external-request validation boundary is
  `local_instance_state::reject_reserved_request_id`, called from
  `paid_execution::authenticate_and_identify`,
  `local_execution::handle_local_execution`,
  `publication::handle_local_publication_with_history`, and
  `authenticate_submit_transaction_event` (the single construction point for
  every `SubmitTransaction`-family `AuthenticatedSubmitTransaction`). The
  distinct internal/system construction path,
  `local_instance_state::fastpath_synthetic_prepare_request_id`, is
  unreachable from external input.
- The previously uncovered direct mutation branch gap is closed in
  `local_execution::handle_local_execution` (`Write`/`Consume` inputs) and
  once at the shared `SubmitTransaction` durable boundary, covering the
  object-read-only nonce, owned-effects, and preinstalled-WASM branches.
- Dedicated adversarial test evidence (`cargo test -p node-core`, 381
  tests passing) includes: `fast_path::tests::
  prepare_rejects_a_request_bound_to_a_non_current_epoch`,
  `apply_rejects_a_request_bound_to_a_non_current_epoch`,
  `paid_execution::tests::
  direct_commit_rejects_a_request_bound_to_a_non_current_epoch`,
  `local_execution::tests::
  a_wrong_current_epoch_is_rejected_before_any_engine_call_or_nonce_advance`,
  `tests::authenticated_read_only_submit_rejects_a_wrong_current_epoch`,
  `tests::authenticated_owned_write_rejects_a_wrong_current_epoch`,
  `tests::
  preinstalled_wasm_rejects_a_wrong_current_epoch_before_any_execution_or_mutation`,
  `prepare_rejects_a_validator_set_digest_mismatch_with_the_committed_epoch_record`,
  `prepare_rejects_a_signer_absent_from_the_committed_validator_set`,
  `apply_rejects_a_certificate_signed_by_validators_absent_from_the_committed_set`,
  `a_racing_epoch_record_write_conflicts_the_apply_commit` (a real
  optimistic-concurrency CAS-fence proof, not just a unit-level check);
  `validator_set::tests::duplicate_public_key_across_distinct_validator_ids_is_rejected`
  and `genesis::tests::duplicate_validator_public_keys_are_rejected_at_genesis_install`;
  `local_execution::tests::
  a_fastpath_object_lock_blocks_local_execution_write_from_a_different_sender`
  (a different sender than the locking one, so the sender/epoch nonce-lock
  cannot be masking the object-lock rejection) and
  `tests::authenticated_owned_write_is_blocked_by_a_held_fastpath_object_lock`;
  `tests::authenticated_read_only_submit_honors_fastpath_nonce_lock`;
  and reserved-request-id rejection tests in each of the four event
  families (`fast_path::tests::
  reserved_request_id_prefix_is_rejected_by_direct_commit_and_prepare`,
  `local_execution::tests::reserved_request_id_prefix_is_rejected_before_any_admission`,
  `publication::tests::reserved_request_id_is_rejected_before_any_state_read`,
  `tests::authenticate_submit_transaction_event_rejects_reserved_request_id`).
- Independent stable Rust/JS vectors for `0x6426` and the redefined `0x641B`
  are pinned by `crates/node-core/src/fast_path/tests.rs` and independently
  reconstructed byte-for-byte by `scripts/fast-path-vectors.mjs` (no Rust
  encoder invoked), wired into `scripts/check-all.sh`.
- `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features
  -- -D warnings`, and `cargo test --workspace --all-targets --all-features`
  all pass on the integrated diff. This implementation status is evidence of
  Slice 1 alone; it does not by itself constitute the fresh security and
  tech-lead review this index's other entries record separately, and a later
  code change invalidates it.

Consistent with the DR's own scope: this does not implement epoch
transition, lock recovery, equivocation evidence, or authorization-class
declaration (Slices 2-4), does not close the FastVote Certified Execution
Gate's Phase 2 entry in `TODO.md`, and does not make retired-validator or
wrong-epoch rejection end-to-end observable beyond genesis-set membership.
