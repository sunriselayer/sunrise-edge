# DR-0132: FastVote epoch transition detailed design (phase 2, slice 2)

## Status

Accepted as the detailed design for FastVote Phase 2 Slice 2, 2026-09-22,
and **implemented the same day.** This DR fixes and implements the wire
format, the API, the activation write set, and the reclamation rule for the
outgoing-set-certified `e -> e+1` transition that
[DR-0131](0131-fastvote-validator-lifecycle.md) named but left pending its
own decision record. It also corrects seven assumptions in DR-0131 that were
wrong and would either brick a node on restart or leave the paid path dead
after the first transition (see "Corrections to DR-0131" below); those
corrections are part of this DR's implemented design. The "Slice 2
design-acceptance criteria" section below is satisfied: the consensus and
node-core codecs, `propose_and_vote`/`activate`, C1's restart-verify chain,
lazy stale-lock/prepared-record reclamation, the headline four-independent-
SQLite test and its supporting adversarial evidence, and independent
Rust/JS vectors are all implemented and passing, and `cargo fmt`, `cargo
clippy -D warnings`, `cargo test --workspace`, and `./scripts/check-all.sh`
all pass on the integrated diff. **Slice 2 is implemented.** FastVote Phase 2
subsequently closed when [DR-0134](0134-fastvote-authorization-boundary.md)'s
companion Slice 4 code and review gate landed in PR #180.
Nothing in this DR authorizes testnet or production activation of any new
ingress. Retired-validator and wrong-epoch rejection are now end-to-end
observable through a real transition (see the adversarial evidence in
`crates/node-core/src/epoch_transition/tests.rs`), for the first time since
DR-0131's Slice 1 fencing had nothing to enforce it against.

**Revision (2026-09-22, same day, pre-implementation review):** review found
two blocking underspecifications in the design below, both corrected in this
text, still design-only: (1) C1's restart-verify rule, as first written,
described only chain contiguity (`to_epoch == next.from_epoch`) and did not
say the chain must be cryptographically re-verified at restart; §7 now
specifies the exact per-step decode/load/verify/bind algorithm and its exact
fail-closed behavior. (2) `activate`'s already-activated branch, as first
written, compared only `activation_digest`; §3.C.3 now compares the full
transition identity (`from_epoch`, `to_epoch`,
`previous_validator_set_digest`, `next_validator_set_digest`,
`activation_digest`), because `activation_digest` alone does not bind the
outgoing epoch or either validator-set digest (see §2's field list).

**Revision (2026-09-22, same day, implementation review):** implementation
review found a semantic flaw in `propose_and_vote`'s "already exists" check,
corrected in this text: `propose_and_vote` always derives `next_epoch` from
the fenced live `current_epoch`, and `activate` only ever installs a
`FastPathEpochTransitionRecord` at `next_epoch` in the exact same atomic
`commit_durable` that advances the live `FastPathEpochRecord` to it (§3.C.8).
Those two facts together mean `propose_and_vote` can never legitimately
observe a transition record already present at `current_epoch + 1` while the
live epoch record still reads `current_epoch` -- there is no interleaving of
a concurrent `activate` that produces that combination, because the two
writes are the same commit. A record present under that combination is
therefore always partial or corrupt prior state (for example, a write that
should never exist outside that one atomic commit, or on-disk tampering),
never a legitimate race. §1.2 and §3.B below now have `propose_and_vote`
fail closed with `Invalid` in that case instead of returning an
`AlreadyActivated` value, and `propose_and_vote` now returns
`EpochTransitionVote` (§1.1) directly instead of a `TransitionProposalOutcome`
wrapper enum whose second variant was never actually reachable through
legitimate use. `activate`'s
own already-activated branch (§3.C.3) is unaffected: it is reached by
re-running `activate` itself, whose atomicity makes that branch, unlike
this one, genuinely reachable.

**Revision (2026-09-22, same day, adversarial-evidence review):** writing
the stale-prepared-record-supersession test (C5, §3.D) surfaced a second
implementation bug, now fixed, not a design flaw in the text above:
`local_instance_state::fastpath_synthetic_prepare_request_id`'s preimage did
not mix the epoch in directly, relying solely on
`HashSuiteResolver::hash_for_purpose`'s own epoch-indexed suite selection to
vary the digest. A resolver whose schedule does not change suite across the
transition -- the common case, and true of every fixture this DR's own test
suite otherwise uses -- selects the identical suite for both epochs, so the
same original request id reused at `e+1` produced the identical synthetic
prepare-receipt id as its `e`-epoch prepare, and the durable receipt layer
rejected the second `commit_invocation` as a conflicting duplicate before
C5's own record-level supersession logic ever mattered. The preimage now
also includes the epoch's raw bytes, so the two epochs' synthetic ids always
differ regardless of suite schedule.

**Revision (2026-09-22, same day, concurrency/canonicalization review):**
further review found three more issues, all fixed, none a change to the
safety contract:

1. The implementation-review revision above overstated its own claim:
   `propose_and_vote`'s epoch fence (step 1) and its transition-record read
   (step 4) are two separate reads, not one atomic operation, even though
   `activate` itself installs the live epoch record and the transition row
   together in one commit. A concurrent `activate` *can* commit in the
   window between those two reads, and when it does, `propose_and_vote`
   observes a transition row at `current_epoch + 1` alongside its own
   now-stale fenced `current_epoch` -- a real, benign race, not corrupt
   state. `propose_and_vote` now re-reads the live epoch record at that
   point and returns the retryable `NodeCoreError::StateConflict` if it has
   advanced beyond `current_epoch`, reserving `Invalid` for the case the live epoch
   record still reads `current_epoch` (§3.B step 4, §6).
2. `derive_activation_set` did not canonicalize `next_validators` before
   encoding the `FastPathValidatorSetRecord` it embeds in the activation
   set. `ValidatorSet::new` already canonicalizes its own `ValidatorInfo`
   list, so `next_validator_set_digest` was always order-invariant, but the
   committed `0x641F` bytes and therefore `activation_digest` were not:
   independent callers supplying the identical operator-authorized set in a
   different order would disagree on `activation_digest` and never form a
   quorum. `next_validators` is now sorted by `ValidatorId` before anything
   is validated or encoded (§3.A step 2).
3. Added `activate_rejects_a_certificate_bound_to_a_different_outgoing_validator_set_digest`:
   a cryptographically valid outgoing-set quorum certificate whose
   `current_validator_set_digest` field itself differs from the committed
   `FastPathEpochRecord`'s, reaching `activate`'s not-yet-activated
   verify-then-bind check (§3.C step 5) rather than the already-activated
   identity comparison the existing tests already covered.

## Context

[DR-0131](0131-fastvote-validator-lifecycle.md) accepted the Phase 2
architecture and implemented Slice 1: a CAS-fenced singleton
`FastPathEpochRecord` (`0x6426`), an epoch-stamped `FastPathLockRecord`
(`0x641B`), and a shared two-tier fencing model
(`crates/node-core/src/mutation_fence.rs`) that every mutation path commits
through. Slice 1 deliberately introduced no post-genesis write to the epoch
record, so wrong-epoch and retired-validator rejection are real, fenced
checks but unreachable in practice: nothing can yet change the active set.

Slice 2 is the transition itself. Its safety contract is already fixed by
DR-0131's "Key transition safety proof"; what this DR fixes is the wire
format, the API, the activation write set, and the reclamation rule. Design
review of the Slice 1 code against DR-0131's own text turned up seven
corrections, three of them blocking: a naive Slice 2 built on DR-0131's
literal wording would either fail every restart after the first transition,
leave epoch `e+1` unable to execute anything, or make a transition
certificate structurally indistinguishable from a transaction certificate.

## Corrections to DR-0131

**C1 (blocking) — genesis restart-verify fails after the first transition.**
`genesis::install_genesis_with_history`
(`crates/node-core/src/genesis.rs:1034-1041`) re-verifies
`FastPathEpochRecord` byte-for-byte against a freshly recomputed *genesis*
record on every restart. After a transition the live record is
`{current_epoch: e+1, previous_epoch: Some(e), ...}`, so every restart would
return `GenesisError::TamperedInstalledRecord("fast-path epoch record")`.
DR-0131 assumed the record never changes; Slice 2 changes it by design, so
this check must change too.

Replacement rule (keeps Slice 1's tamper evidence, permits lawful advance):
decode the installed record and require `current_epoch >= manifest epoch`;
if equal, require byte-equality with the freshly recomputed genesis record
(unchanged Slice 1 behavior); if greater, require `previous_epoch ==
Some(current_epoch - 1)` and an installed `FastPathEpochTransitionRecord`
for every step from the manifest epoch to `current_epoch`. Chain
*contiguity* alone (`to_epoch == next.from_epoch`) is **not** the rule: a
chain that merely links up without being cryptographically re-verified would
accept a record whose embedded certificate never verified, a historical
validator-set row swapped after the fact, or an activation-set/policy row
edited on disk post-activation. The audit chain must instead be
re-decoded, re-verified, and re-bound to the live singleton at every restart
— the exact per-step algorithm and its exact fail-closed behavior are
specified in full in §7 below. The genesis-epoch `FastPathValidatorSetRecord`
row is unaffected (its key is epoch-scoped), so its existing byte-equality
check is unchanged.

**C2 — `fastpath_validator_set_key` is already epoch-keyed.** DR-0131 says
it must be "extended to be keyed by epoch under Slice 2." It already is:
`fastpath_validator_set_key(context: &PublicationContext)`
(`local_instance_state.rs:172`) encodes chain, protocol version, and epoch.
Slice 2 needs no key change; the transition writes a new row at `ctx@e+1` and
never mutates `ctx@e`'s row, which stays readable for audit.

**C3 (blocking) — epoch-scoped policy rows must be carried forward, or
`e+1` is dead.** `build_paid_admission` (`paid_execution.rs:569-590`)
requires exact installed bytes at
`execution_policy_key_for_profile(base_policy.context(), 4)` and
`paid_fee_policy_key(&fee_policy.context)`, and
`execution::paid_execution::quote_paid_intent:1050` requires
`intent.context == fee_policy.context == *base_policy.context()`. All three
keys embed the epoch, and genesis installs them only at the genesis epoch.
The instant `current_epoch` becomes `e+1`, epoch-`e` intents are rejected by
`fence_current_epoch` and epoch-`e+1` intents fail `"paid fee policy absent
or different"` — the paid path, and therefore the whole fast path, stops.
The transition must atomically install the `e+1` rows, and because they are
digest-bound they must be re-derived, not copied byte-for-byte.

**C4 — stale nonce locks need no reclamation.**
`fastpath_nonce_lock_key(chain, sender, epoch)` and
`PersistenceLayout::sender_nonce_key(sender, epoch)` are already
epoch-disjoint. An epoch-`e` nonce lock is unreachable from any `e+1` path.
Reclaiming it would be storage hygiene, not a safety or liveness
requirement. This narrows DR-0131's and `TODO.md`'s "stale object/nonce lock
reclamation" wording: only `fastpath_lock_key(chain, object_id)` is
epoch-independent and needs CAS reclamation.

**C5 — stale prepared records also need reclamation.**
`fastpath_prepared_record_key(chain, request_id)` is epoch-independent. A
user re-signing the same request id at `e+1` would hit `"conflicting
fast-path prepared record"` (`fast_path.rs:437`) forever without an explicit
supersession rule. Slice 2 applies the same CAS supersession rule to
prepared records as to object locks.

**C6 — the transition needs its own signature domain and frame family.**
Overloading `FastVote`'s `tx_hash`/`execution_effects_hash` slots would make
a transition certificate structurally indistinguishable from a transaction
certificate under `"fast-path-vote-v1"`. Slice 2 allocates a distinct
signature domain, `"fast-path-epoch-transition-v1"`, and distinct frame IDs
(§1 below).

**C7 — `expected: &PublicationContext` must follow the committed record.**
`authenticate_paid_intent` pins `intent.context == expected`, and today
`expected` comes from static operator config (`native-http/src/lib.rs:2622,
3218`). Once Slice 2 exists, config-supplied epoch is no longer
authoritative: the committed `FastPathEpochRecord` is. Slice 2 adds a
read-only `query::query_committed_epoch_state` so callers can read the
authoritative current epoch instead of trusting static config; rewiring
`native-http` to use it is Slice 4's ingress-boundary work, specified by
[DR-0134](0134-fastvote-authorization-boundary.md), not Slice 2's.

## Decision

### 1. Records, APIs, frame IDs, signature domains

Next free ids verified by sweep: node-core fast path `0x6427+`, consensus
`0xD009+`.

#### 1.1 `crates/consensus/src/epoch_transition.rs` (new module)

| Frame | Type | Shape |
|---|---|---|
| `0xD009/v1` | `EpochTransitionVotePayload` | signable, no signature |
| `0xD00A/v1` | `EpochTransitionVote` | `{1: payload, 2: signature}` |
| `0xD00B/v1` | `EpochTransitionCertificate` | `{1-7: header, 8: u32 count, 9+i: vote}` |

Payload fields (mirrors `encode_fast_vote_payload`'s shape so the codec and
strict-redecode discipline carry over verbatim):

1. `chain_id: str`
2. `protocol_version: u32`
3. `epoch: u64` — the **outgoing** epoch `e`; the replay boundary and the
   signing set's own epoch
4. `next_epoch: u64` — must equal `e + 1` at construction and at decode
5. `current_validator_set_digest: Digest32` — binds *which* outgoing set
   authorized this, not merely an equal-epoch set
6. `next_validator_set_digest: Digest32` — `ValidatorSet::digest(resolver)`
   of the `e+1` set, computed at epoch `e+1`
7. `activation_digest: Digest32` — one digest over the complete byte-exact
   activation write set (§2). This is what makes the vote byte-stable: two
   validators that would install different bytes produce different digests
   and can never form a quorum.
8. `validator: [u8;32]`
9. `signature_scheme: u16`

Signature domain: `SignatureDomain { chain_id, protocol_version, epoch: e,
message_type: "fast-path-epoch-transition-v1", signature_scheme_id }`.

`EpochTransitionCertifier` is a structural mirror of `FastPathCertifier`
(`fast_vote.rs:101`), bound to `(chain, protocol_version, outgoing_epoch,
outgoing_validator_set)`, with `cast_vote` / `verify_vote` /
`try_form_certificate` / `verify_certificate`. It reuses the identical
quorum rule, canonical `ValidatorId` order, duplicate rejection, smallest-
signature tie-break, and the same explicit exclusion policy
(`Authenticator` errors propagate; `UnknownValidator`/
`SignatureSchemeMismatch`/`InvalidSignatureLength`/`InvalidSignature`/
`ContextMismatch` exclude), and reuses `validate_signature_length`. One new
`ConsensusError` variant is added: `NonSuccessiveEpoch { current: Epoch,
next: Epoch }`.

#### 1.2 `crates/node-core/src/epoch_transition.rs` (new module)

| Frame | Type | Key |
|---|---|---|
| `0x6427/v1` | `FastPathEpochTransitionRecord` | `fastpath_epoch_transition_key(chain, next_epoch)` = `se/instances/v1/fastpath/transition/<chain><be_u64 next_epoch>` |
| `0x6428/v1` | `FastPathEpochActivationSet` | digest preimage only, never stored |

`FastPathEpochTransitionRecord` fields: `from_epoch`, `to_epoch`,
`previous_validator_set_digest`, `next_validator_set_digest`,
`activation_digest`, `certificate: Vec<u8>` (exact verified bytes, kept as a
permanent audit trail — C1's restart chain and Phase 3 slashing both read
it), `activated_at_checkpoint: u64`.

Public API, all in-process, validator-authorized, no ingress:

```rust
pub fn propose_and_vote(..., next_validators: Vec<FastPathValidatorEntry>,
                        signer: &C) -> Result<EpochTransitionVote, EpochTransitionError>;
pub fn activate(..., next_validators: Vec<FastPathValidatorEntry>,
                certificate_bytes: &[u8], checkpoint: u64)
                -> Result<EpochActivationOutcome, EpochTransitionError>;
```

plus a read-only `query::query_committed_epoch_state` (C7).

`propose_and_vote` returns the fresh (or byte-identical replayed) vote
directly. If it observes a transition record already present at
`current_epoch + 1`, it re-reads the live epoch record to distinguish a
benign concurrent `activate` sequence (live epoch is now greater than
`current_epoch`: fails
closed with the retryable `NodeCoreError::StateConflict`, no vote cast) from
genuinely partial or corrupt prior state (live epoch still reads
`current_epoch`: fails closed with `Invalid`, no vote cast) -- see the
concurrency-review revision above and §3.B step 4.
`EpochActivationOutcome ∈ { Activated(FastPathEpochTransitionRecord),
AlreadyActivated(FastPathEpochTransitionRecord) }`.

### 2. `FastPathEpochActivationSet` (`0x6428`) — the activation write set

1. `next_context: PublicationContext` (`ctx@e+1`)
2. `validator_set_record: bytes` — `0x641F` at `ctx@e+1`
3. `execution_policy: bytes` — `LocalExecutionPolicy::generic_object_results(ctx@e+1).encode()`
4. `paid_fee_policy: bytes` — the committed `ctx@e` `PaidFeePolicy` with
   `context = ctx@e+1` and `base_policy_digest` recomputed
5. `publication_policy: bytes` —
   `LocalPublicationPolicy::object_results(ctx@e+1,
   execution::local_execution::generic_object_result_semantics(resolver, &ctx@e+1)).encode()`

`activation_digest = resolver.hash_for_purpose(next_epoch,
HashPurpose::NodeEvent, encode_fastpath_epoch_activation_set(&set))`.

The epoch record itself is deliberately excluded from this digest: it is
fully determined by `(next_epoch, next_validator_set_digest, previous_epoch
= e)`, all already signed in the payload, plus `activated_at_checkpoint`,
which is a local per-node value (the same convention as genesis's
`installed_at_checkpoint`) and must never enter a cross-validator digest.
`activated_at_checkpoint` therefore diverges across validators by design;
this DR records that as an accepted consequence, not a defect.

Only field 4 needs the committed `ctx@e` row; fields 3 and 5 are pure
functions of the context (`genesis.rs:773-774, 810-811, 921`).

**Consequence:** `paid_fee_policy_digest` changes at every epoch boundary,
so clients must re-fetch it and sign `intent.fee_policy_digest` against the
new epoch's policy. This is correct and intended — the epoch is a replay
boundary — but the implementation must add a test and a release note for it.

### 3. Invariants and algorithms

#### A. Deriving the activation set (deterministic, identical on every node)

1. `next_context = PublicationContext::new(chain, protocol_version, e+1)`;
   require the protocol version **unchanged** — an epoch transition is not a
   protocol upgrade; §21 of `core-protocol.md` owns that path.
2. **Canonicalize `next_validators` by `ValidatorId` (ascending) before
   anything else touches it** — before validation, before building the
   `FastPathValidatorSetRecord`, and before computing any digest.
   `next_validators` is an ordinary `Vec` an operator supplies; independent
   callers/nodes deriving the identical set have no other way to agree on
   its input order. `ValidatorSet::new` already sorts its own `ValidatorInfo`
   list internally, so `next_validator_set_digest` was always
   order-invariant on its own — but `FastPathEpochActivationSet.
   validator_set_record` is the caller-supplied list re-encoded, and
   `activation_digest` is hashed over the whole activation set including
   that record. Sorting once up front, before either the validation loop or
   the record encoding, makes both the committed `0x641F` bytes and
   `activation_digest` byte-identical across any permutation of the same
   input set, not merely `next_validator_set_digest`.
3. Validate the next set through `ValidatorSet::new(e+1, info)` (now
   operating on the already-canonical order), which gives
   `Empty`/`TooManyValidators`/`ZeroVotingPower`/`EmptyPublicKey`/
   `PublicKeyTooLarge`/`DuplicateValidator`/`DuplicatePublicKey` for free
   (reusing the same check DR-0131 item 5 already added, not a second one),
   and require every member to be Ed25519, matching
   `fast_path::load_validator_set`.
4. Read the committed `ctx@e` `PaidFeePolicy` under the fence; re-derive
   fields 3/4/5 at `next_context`; compute `activation_digest`.

#### B. `propose_and_vote`

1. `mutation_fence::fence_epoch_state` (not `fence_current_epoch` — there is
   no request epoch) → `epoch_record`.
2. `fast_path::load_validator_set` (promoted to `pub(crate)`) → outgoing
   set, CAS-fenced with its digest checked against the epoch record. Reuses
   Slice 1's two-tier fence verbatim.
3. `next_epoch = current_epoch.checked_add(1)` — `u64::MAX` fails closed.
4. If `FastPathEpochTransitionRecord` at `next_epoch` already exists,
   re-read the live `FastPathEpochRecord` before deciding what this means
   (see the concurrency-review revision above). Steps 1 and this step are
   *not* atomic with each other -- a concurrent `activate` can commit
   between them, even though `activate` itself installs the live epoch
   record and the transition row atomically in one commit. Two outcomes:
   * the live epoch has advanced beyond `current_epoch` — one or more
     concurrent `activate` calls produced this row and may already have
     advanced farther; fail closed with the retryable
     `NodeCoreError::StateConflict` and cast no vote, so the caller
     re-proposes against the new epoch;
   * the live epoch still reads `current_epoch` (or regressed) — the
     row cannot correspond to any real activation; fail closed with
     `Invalid` ("partial or corrupt prior state") and cast no vote.
5. Derive the activation set (A); `certifier.cast_vote(...)`.
6. Persist nothing. A transition vote reserves no resource, so there is
   nothing to make idempotent; byte-stability comes from determinism of the
   derivation plus Ed25519 determinism, not from a durable record. This is a
   deliberate, stated departure from `fast_path::prepare`.

#### C. `activate`

1. Decode the certificate (pure) → `next_epoch`, `epoch`.
2. `fence_epoch_state` → `epoch_record`.
3. **Already-activated branch:** if `epoch_record.current_epoch ==
   certificate.next_epoch`, load the stored transition record and compare
   the **full transition identity**, not `activation_digest` alone:
   `record.from_epoch == certificate.epoch`, `record.to_epoch ==
   certificate.next_epoch`, `record.previous_validator_set_digest ==
   certificate.current_validator_set_digest`,
   `record.next_validator_set_digest ==
   certificate.next_validator_set_digest`, **and**
   `record.activation_digest == certificate.activation_digest`. All five
   equal → `AlreadyActivated` (this also covers an alternate quorum subset
   presenting the identical payload under a different signer subset,
   consistent with `verify_certificate`'s documented non-minimality — the
   header fields compared here never depend on which subset of the quorum
   signed). Any of the five differing → `Invalid("conflicting epoch
   transition already activated")`. No mutation either way.

   `activation_digest` alone is not sufficient: §2 defines it over the
   activation write set's *result* (the `e+1` context and its four
   installed rows) and does not include `from_epoch`,
   `previous_validator_set_digest`, or `next_validator_set_digest` in its
   preimage. A certificate whose header disagrees with the stored record on
   any of those fields could still carry a matching `activation_digest` —
   for example, one claiming a different outgoing epoch or a different
   outgoing/incoming validator-set digest, while resolving to the same
   `e+1` activation rows. This branch must never treat a
   digest-only match as proof it is the identical, already-verified
   transition, because no certificate is cryptographically re-verified on
   this branch (that only happens on the not-yet-activated path, step 5
   below); the branch must instead be indifferent to which digest a
   forged/mismatched certificate happens to carry, by comparing every field
   the stored record actually attests to.
4. Else require `epoch_record.current_epoch == certificate.epoch`, else
   `NodeCoreError::EpochMismatch`.
5. `load_validator_set` → outgoing set; build the certifier at `(chain, pv,
   e, outgoing_set)`; `verify_certificate`; additionally require
   `certificate.current_validator_set_digest ==
   epoch_record.current_validator_set_digest`.
6. Re-derive the activation set (A) locally and require
   `derived.activation_digest == certificate.activation_digest` and
   `derived.next_validator_set_digest ==
   certificate.next_validator_set_digest`. This mirrors apply's
   `fresh_commitment != prepared.commitment` check: a node never installs
   bytes it did not itself derive.
7. CAS-assert absence of all five target rows (`validator_set@e+1`,
   `execution_policy@e+1`, `paid_fee_policy@e+1`, `publication_policy@e+1`,
   `transition@e+1`); any present → fail closed, mirroring genesis's
   `PartialPriorState` discipline.
8. One `commit_durable(AtomicStateTransaction)`: reads = {epoch record at
   its fenced revision, outgoing validator-set row at its fenced revision,
   five target keys at `INITIAL`}; mutations = {five `Put`s + the rewritten
   `FastPathEpochRecord`}. Outcome mapping is copied from
   `fast_path::install_validator_set:350-362`.

No `DurableRequestReceipt` and no `RequestId` are involved, so the reserved
synthetic-namespace boundary does not apply and no synthetic id is minted.

#### D. Lazy stale-lock reclamation — CAS only, no timeout

`mutation_fence::fence_object_lock` takes the fenced `current_epoch` and
returns `ObjectLockState { Absent, Reclaimable, OwnedByThisRequest }`:

| mode | observed | result |
|---|---|---|
| `Fresh` | absent | `Absent` |
| `Fresh` | `locked_epoch == current` | `Err("object locked by a pending fast-path certificate")` (unchanged) |
| `Fresh` | `locked_epoch < current` | `Reclaimable` |
| `Fresh` | `locked_epoch > current` | `Err("fast-path lock stamped a future epoch")` |
| `OwnedByRequest` | any | exact-match check unchanged, including `lock.locked_epoch != expected_epoch` |

Write behavior: `fast_path::prepare` already emits a `Put` per locked
object, so it overwrites a `Reclaimable` row under the revision the fence
recorded — no new write site. Object-bearing direct paths
(`paid_execution`, `local_execution`, and the shared `SubmitTransaction`
boundary) emit a `StateMutation::Delete` for each `Reclaimable` row they
observed, so no lock survives the next mutation touching its object.
`publication` has no existing-object input and therefore never reads an
object-lock row; its sender nonce lock is epoch-disjoint (C4).

Prepared records (C5): `fast_path::prepare`'s replay branch treats
`existing.context.epoch() < epoch_record.current_epoch` as absent and lets
the normal `Put` supersede it under CAS. `apply` needs no change — its
`prepared.context != intent_context` check already rejects a stale record.

**Why safe (DR-0131's proof, instantiated):** the only certificate that
could legitimately consume a lock stamped `e_old` carries `certificate.epoch
== e_old`; `apply` requires `intent_context.epoch() == current_epoch` (leg
3) and `certificate.epoch == intent_context.epoch()` (leg 2), so after the
transition that apply is rejected before reading any lock. The stale lock
protects nothing, and reclamation cannot race a still-live old-epoch apply.
Eligibility derives purely from the CAS-fenced transition commit, never from
elapsed time.

### 4. Authorization boundary

No new externally reachable event family. `propose_and_vote`/`activate` are
in-process node-core functions in the same authorization class as
`fast_path::prepare`/`apply`: local-operator-invoked, validator-authenticated
by the signer's membership in the fenced outgoing set. `native-http` gains
nothing from this DR. DR-0134 declares the complete two-axis authorization
and closed-ingress boundary.

`next_validators` is supplied by the operator invoking `propose_and_vote`/
`activate`; its only source of authority is the outgoing-set quorum
certificate formed over it, never the operator's local configuration alone.
A quorum of the outgoing set must independently derive and sign the same
`activation_digest` before `activate` will install anything — an operator
acting alone cannot change the active set. This is deliberately not a
governance mechanism (see "Unresolved risks" item 1).

### 5. Failure / restart / indeterminate

- **Pre-commit failure or crash:** nothing durable changed; re-run
  `activate`.
- **Post-commit crash:** re-run takes branch C.3 → `AlreadyActivated`.
- **Indeterminate commit:** `activate` is safely retryable without
  request-id reconciliation, because it writes no receipt and is idempotent
  on committed state — a retry either observes the activation (branch C.3)
  or re-attempts the identical CAS. This is the explicit answer to
  DR-0130/DR-0131's indeterminate-commit discipline, and it differs from
  `apply`, which must reconcile by request id.
- **Restart after transition:** `install_genesis_with_history` must return
  `VerifiedExisting` via C1's full per-step decode/load/verify/bind
  algorithm (§7) — chain contiguity alone is not the rule; every historical
  certificate, validator-set row, and activation/policy row is
  re-decoded and re-verified, and the live singleton is bound to the last
  verified step.
- **Node offline across two transitions:** it must `activate` `e→e+1` then
  `e+1→e+2` in order, supplying both certificates; there is no fetch
  mechanism, because there is no ingress (Unresolved risks item 4).

### 6. Replay / conflict matrix (exact)

| Situation | Behavior |
|---|---|
| `propose_and_vote` re-run, same state + same `next_validators` | byte-identical vote, no durable write |
| `propose_and_vote` after activation | proposes the *new* current epoch's own successor transition normally (no special case: the fenced `current_epoch` already reflects the activated epoch) |
| `propose_and_vote` observes a transition record at `current_epoch + 1`, and a live re-read of the epoch record still reads `current_epoch` | `Invalid` (genuinely partial or corrupt prior state), no vote |
| `propose_and_vote` observes a transition record at `current_epoch + 1`, but one or more concurrent `activate` calls committed after its epoch fence and the live epoch record is now greater than `current_epoch` | `NodeCoreError::StateConflict` (retryable; benign interleaving, not corrupt state), no vote |
| two validators propose different `next_validators` | both valid votes, different `activation_digest`, no quorum — an ordinary two-validator disagreement, not equivocation (only the *same* validator signing two such votes is; see [DR-0133](0133-fastvote-equivocation-evidence.md)) |
| `next_validators` supplied in a different order but the same set | byte-identical `FastPathValidatorSetRecord` and `activation_digest` (canonicalized by `ValidatorId`, §3.A step 2) — never a spurious quorum split |
| identical certificate applied twice | `AlreadyActivated`, no mutation |
| alternate quorum subset, identical `(epoch, next_epoch, current_validator_set_digest, next_validator_set_digest, activation_digest)` | `AlreadyActivated` |
| same `next_epoch`, but `epoch`, `current_validator_set_digest`, `next_validator_set_digest`, or `activation_digest` differs from the stored record | `Invalid("conflicting epoch transition already activated")` |
| same `next_epoch` and same `activation_digest`, but `epoch` or a validator-set digest differs from the stored record | `Invalid("conflicting epoch transition already activated")` — proves digest-only comparison would have been insufficient |
| certificate `epoch != current_epoch` | `EpochMismatch`, no mutation |
| certificate not yet activated (`epoch_record.current_epoch == certificate.epoch`), cryptographically valid outgoing-set quorum, but `current_validator_set_digest` ≠ the committed epoch record's | `Invalid("epoch transition certificate outgoing validator-set digest does not match the committed epoch record")`, no mutation — reached only after `verify_certificate` succeeds under the real outgoing set, distinct from the already-activated identity-mismatch rows above |
| locally derived digest ≠ certificate's | `Invalid`, no mutation |
| certificate signed by the incoming set | `UnknownValidator` / `InsufficientQuorum` |
| `next_epoch != e+1` (incl. overflow) | `NonSuccessiveEpoch` |
| `activate` races `fast_path::apply` | same CAS-fenced epoch-record row; exactly one commits |
| `activate` races `activate` | one commits; loser gets `StateConflict`, retry → `AlreadyActivated` |
| epoch-`e` certificate at `apply` after activation | `EpochMismatch` before any lock read; permanent |
| epoch-`e` object lock at `e+1` | reclaimed under CAS by the next mutation touching that object |
| epoch-`e` prepared record, same request id, at `e+1` | superseded under CAS |
| epoch-`e` nonce lock at `e+1` | inert (key is epoch-disjoint); no reclamation |

### 7. Restart-verification algorithm (C1, detailed)

This replaces the byte-for-byte `FastPathEpochRecord` re-verification
DR-0131 specified, for any node whose committed `current_epoch` is past the
manifest (genesis) epoch. It runs inside
`genesis::install_genesis_with_history`'s `VerifiedExisting` path, and must
complete before the node is considered started.

Let `g` be the manifest (genesis) epoch and `c` be the live
`FastPathEpochRecord.current_epoch`.

1. If `c == g`: unchanged Slice 1 behavior — byte-equality against the
   freshly recomputed genesis `FastPathEpochRecord` and genesis
   `FastPathValidatorSetRecord`. There is no transition chain to walk.
2. If `c < g`: fail closed immediately. `current_epoch` can never regress
   below the manifest epoch.
3. If `c > g`: require `previous_epoch == Some(c - 1)`, then walk every step
   `i` from `g` to `c - 1` in increasing order, performing all of the
   following for step `i` before advancing to step `i + 1`:
   a. **Decode the stored `FastPathEpochTransitionRecord`** at
      `fastpath_epoch_transition_key(chain, i + 1)`. Absent or undecodable
      → fail closed: a gap in the chain, or a record the wire codec itself
      rejects, can never be a lawful step.
   b. **Decode the record's embedded `certificate: Vec<u8>`** as an
      `EpochTransitionCertificate` (`0xD00B`). Undecodable → fail closed.
   c. **Load the historical outgoing `ValidatorSet` row** at
      `fastpath_validator_set_key(ctx@i)`. Absent or undecodable → fail
      closed. For `i == g` this is the genesis-installed row; for `i > g`
      it is the row this same algorithm installed while verifying step
      `i - 1`.
   d. **Verify that row's digest against the chain, never against a fresh
      guess:** for `i == g`, require `ValidatorSet::digest(row) ==` the
      freshly recomputed genesis validator-set digest; for `i > g`, require
      it `==` step `i - 1`'s `next_validator_set_digest`. Mismatch → fail
      closed. This is what stops a historical validator-set row from being
      silently swapped after the fact.
   e. **Cryptographically verify the certificate itself:** build an
      `EpochTransitionCertifier` bound to `(chain, protocol_version, i,`
      the row loaded in (c)`)` and call `verify_certificate` on the
      certificate decoded in (b), under the
      `"fast-path-epoch-transition-v1"` signature domain. This checks real
      signatures against real public keys and a real quorum threshold, not
      a header-field comparison. Any `ConsensusError` (bad signature,
      unknown validator, insufficient quorum, wrong domain, non-successive
      epoch) → fail closed.
   f. **Require the record's fields to match the certificate's payload
      exactly:** `record.from_epoch == certificate.epoch == i`,
      `record.to_epoch == certificate.next_epoch == i + 1`,
      `record.previous_validator_set_digest ==
      certificate.current_validator_set_digest`, and
      `record.next_validator_set_digest ==
      certificate.next_validator_set_digest`. A verified certificate whose
      payload disagrees with the record that claims to carry it is exactly
      as tampered as an unverifiable one. Mismatch → fail closed.
   g. **Re-read the activated validator/policy rows this step installed** —
      `validator_set_record`, `execution_policy`, `paid_fee_policy`, and
      `publication_policy` at `ctx@(i + 1)` — and recompute
      `activation_digest` over them via
      `encode_fastpath_epoch_activation_set`. Require it equals both
      `record.activation_digest` and `certificate.activation_digest`.
      Mismatch, including a decode failure on any of the four rows, → fail
      closed. This is what stops any of the five installed rows from being
      edited on disk after activation without also forging a matching
      certificate. (This is a read-and-rehash check against already
      installed bytes, the same restart-time posture genesis's own
      byte-equality check uses — it does not redo the original
      derivation in §3.A, which additionally needs the committed `ctx@e`
      `PaidFeePolicy` and only applies at activation time.)
4. **Bind the live singleton to the last verified step.** After step 3's
   loop completes for `i = c - 1` without failure, require
   `epoch_record.current_validator_set_digest ==` step `c - 1`'s
   `next_validator_set_digest`, and separately load the live per-epoch
   `ValidatorSet` row at `ctx@c` and require its digest equals the same
   value. This is what stops the live `FastPathEpochRecord` — the row every
   fast-path mutation actually fences against — from diverging from a
   chain that, taken alone, verifies perfectly: a chain no path in the
   system trusts unless it terminates at the exact record everything else
   reads.

**Fail-closed behavior, exact:** any single failure in 3(a)-(g) or 4 —
decode failure, missing row, digest mismatch, certificate verification
failure, or record/certificate field disagreement, at any step — aborts the
entire restart-verify with `GenesisError::TamperedInstalledRecord` (one
message per failure category, for diagnosability) instead of returning
`VerifiedExisting`. There is no partial acceptance: the loop never skips a
bad step and continues, never falls back to trusting the live record alone,
and never truncates the chain at the last good step and proceeds anyway. A
single tampered byte anywhere in the chain — the live record, any
transition record, any stored certificate, any historical validator-set
row, or any activation-set/policy row — makes the entire node refuse to
start. Dedicated tests must cover each tampering surface independently:

- `restart_verify_rejects_a_tampered_live_epoch_record_after_a_transition`
- `restart_verify_rejects_a_tampered_stored_transition_record_field`
- `restart_verify_rejects_a_stored_certificate_with_an_invalid_signature`
- `restart_verify_rejects_a_stored_certificate_whose_payload_disagrees_with_its_own_record`
- `restart_verify_rejects_a_tampered_historical_validator_set_row`
- `restart_verify_rejects_a_tampered_activation_set_or_policy_row_after_activation`
- `restart_verify_rejects_a_missing_step_in_the_transition_chain`
- `restart_verify_accepts_a_two_step_chain_and_binds_the_live_record_to_the_last_step`
  (the only positive case; exercises the `i > g` branches of 3(c)-(d), which
  a single-transition test cannot reach)

## Slice 2 design-acceptance criteria

**All of the following are now satisfied** by the implementation in
`crates/consensus/src/epoch_transition.rs`,
`crates/node-core/src/epoch_transition.rs`,
`crates/node-core/src/epoch_transition/tests.rs`, and the modifications this
DR's "Consequences / Deferred" section lists, evidenced the same way as this
index's other implemented entries (stable vectors, adversarial tests,
complete repository gate, fresh tech-lead and security review):

1. `crates/consensus/src/epoch_transition.rs` implements `0xD009`-`0xD00B`
   exactly as specified in §1.1, including `NonSuccessiveEpoch`, with a
   codec test suite mirroring `0xD006`-`0xD008` (wrong type id, wrong
   version, extra/missing field, non-canonical order, duplicate validator,
   declared-count mismatch, over-bound count, strict re-encode).
2. `crates/node-core/src/epoch_transition.rs` implements `propose_and_vote`
   and `activate` exactly as specified in §3.B-C, including the
   already-activated branch's full-identity comparison (`from_epoch`,
   `to_epoch`, `previous_validator_set_digest`, `next_validator_set_digest`,
   `activation_digest` — not `activation_digest` alone), the
   conflicting-identity, non-successive-epoch, and partial-prior-state
   fail-closed branches.
3. `query::query_committed_epoch_state` exists and is read-only (C7).
4. C1's replacement restart-verify rule (§7) is implemented in
   `genesis::install_genesis_with_history` exactly as specified — per-step
   decode, historical validator-set load and digest chaining, certificate
   decode and cryptographic verification, record/certificate field
   agreement, activation/policy row re-hash, and the final live-singleton
   binding — and proven by the restart tests listed in §7's fail-closed
   paragraph, including a two-step chain and each independent tampering
   surface (record, certificate, historical validator set, activation/
   policy row, missing step).
5. C3's activation write set (§2) is implemented and installs all five rows
   atomically with the epoch record in one `commit_durable`; a fresh
   prepare/apply cycle succeeds at `e+1` with a freshly signed intent (new
   fee-policy digest, restarted nonce domain).
6. C5's stale prepared-record supersession is implemented in
   `fast_path::prepare`'s replay branch.
7. Lazy CAS-only object-lock reclamation (§3.D) is implemented at every
   object-bearing direct mutation path (`paid_execution`, `local_execution`,
   the shared `SubmitTransaction` boundary) and at `fast_path::prepare`,
   with a negative control proving a current-epoch lock still blocks every
   applicable path. `publication` has no existing-object input and therefore
   cannot observe or reclaim an object lock; it retains its epoch fence and
   epoch-disjoint sender-nonce behavior.
8. The headline four-independent-SQLite test
   (`four_validator_sqlite_epoch_transition_activates_and_certified_execution_continues_at_the_next_epoch`,
   §"Test and evidence plan" below) passes, along with the supporting tests
   listed there.
9. Independent stable Rust/JS vectors for `0x6427`/`0x6428`
   (`scripts/fast-path-vectors.mjs`) and `0xD009`-`0xD00B`
   (`scripts/fast-vote-vectors.mjs`) are wired into `scripts/check-all.sh`.
10. `cargo fmt --all`, `cargo clippy --workspace --all-targets
    --all-features -- -D warnings`, `cargo test --workspace --all-targets
    --all-features`, and `./scripts/check-all.sh` all pass on the
    integrated diff, plus a focused security review and a fresh tech-lead
    review.

Satisfying these criteria implemented Slice 2 but did not by itself close
FastVote Phase 2; DR-0134's companion Slice 4 implementation and reviews later
landed in PR #180 and closed Phase 2.
It does not authorize testnet or production activation of any new ingress.

## Test and evidence plan (for the implementation this DR specifies)

**Headline** (four independent file-backed SQLite stores, reusing
`ValidatorFiles` at `fast_path/tests.rs:660`):
`four_validator_sqlite_epoch_transition_activates_and_certified_execution_continues_at_the_next_epoch`

1. genesis on four independent stores; `current_epoch == e`.
2. a full DR-0130 prepare/apply cycle at `e` (baseline).
3. all four independently derive and cast transition votes; assert
   identical `activation_digest` and identical payload bytes modulo signer.
4. form a 3-of-4 certificate; forward and reversed arrival produce
   byte-identical certificate bytes.
5. close/reopen all four; re-derive votes; byte-identical to step 3.
6. `activate` on all four; assert `current_epoch == e+1`, `previous_epoch ==
   Some(e)`, transition record present, and all five activation rows
   byte-identical across all four stores.
7. close/reopen; `install_genesis_with_history` → `VerifiedExisting`, via
   §7's full per-step algorithm, not mere chain contiguity (C1).
8. a new prepare/apply cycle at `e+1` with a freshly signed intent (new
   fee-policy digest, nonce domain restarts) — this is the test that proves
   C3 was actually solved.

**Supporting** (memory store unless noted):
- `derive_activation_set_is_invariant_to_next_validator_input_order`
  (canonicalization by `ValidatorId`, §3.A step 2: byte-identical
  `FastPathEpochActivationSet` across permutations of the same set)
- `propose_and_vote_fails_closed_on_partial_prior_state_when_a_transition_record_exists_without_the_epoch_having_advanced`
  and its benign counterpart
  `propose_and_vote_returns_state_conflict_when_activation_lands_between_its_own_reads`
  (§3.B step 4, §6: the same observed combination is `Invalid` if the live
  epoch record still reads `current_epoch`, `StateConflict` if a concurrent
  `activate` has already advanced it to `next_epoch`)
- `an_epoch_e_certificate_is_permanently_rejected_after_activation`
- `a_stale_object_lock_is_reclaimed_by_a_fresh_prepare_at_the_next_epoch`
- `a_stale_object_lock_is_deleted_by_a_direct_commit_at_the_next_epoch`,
  and the same by local execution and by the `SubmitTransaction` boundary
- `a_current_epoch_lock_still_blocks_every_path` (negative control per family)
- `a_lock_stamped_a_future_epoch_fails_closed`
- `a_stale_prepared_record_is_superseded_at_the_next_epoch_under_the_same_request_id`
- `activate_and_apply_contend_on_the_same_epoch_record_and_exactly_one_commits`
- `activate_is_idempotent_for_the_identical_certificate` and for an
  alternate quorum subset presenting the identical
  `(epoch, next_epoch, current_validator_set_digest,
  next_validator_set_digest, activation_digest)` tuple
- `activate_rejects_a_conflicting_transition_identity_for_an_already_activated_epoch`
  (differs in `epoch`, `current_validator_set_digest`, or
  `next_validator_set_digest`, independent of `activation_digest`)
- `activate_rejects_an_already_activated_epoch_when_activation_digest_matches_but_epoch_or_a_validator_set_digest_does_not`
  (the test that proves `activation_digest`-only comparison would have been
  insufficient)
- `activate_rejects_a_certificate_signed_by_the_incoming_set`
- `activate_rejects_a_non_successive_next_epoch` (`e+2`, `e`, `e-1`, overflow)
- `activate_rejects_a_certificate_bound_to_a_different_outgoing_validator_set_digest`
- `activate_rejects_a_next_set_with_a_duplicate_public_key` / zero power / empty
- `activate_rejects_a_locally_derived_activation_set_that_differs_from_the_certificate`
- `activate_rejects_partial_prior_state_at_the_next_epoch_context`
- `activate_is_retry_safe_after_an_indeterminate_commit`
  (reuse `IndeterminateOnceApplyStore`)
- `a_retired_validator_can_neither_vote_nor_sign_a_certificate_at_the_next_epoch`
- `a_transition_signature_cannot_be_replayed_into_the_fast_path_vote_domain`
  and the converse
- a consensus codec suite mirroring `0xD006`-`0xD008` (see criterion 1 above)
- restart-verify tamper-surface tests (record, certificate, historical
  validator set, activation/policy row, missing step) plus the two-step
  positive case: see §7's fail-closed paragraph for the exact test list

**Restart-verify requires at least two chained transitions in one test run**
(not just the headline test's single transition) to exercise §7 step 3's
`i > g` branches — chaining a historical validator-set row and an
activation/policy row against the *previous* step's digest, rather than
against the genesis digest — and to exercise a tamper injected at the
earlier step surviving detection at restart after the later step commits.

**Vectors:** `0x6427`/`0x6428` into `scripts/fast-path-vectors.mjs`;
`0xD009`/`0xD00A`/`0xD00B` into `scripts/fast-vote-vectors.mjs`. Each pinned
by co-located Rust hex and independently reconstructed in JS with no Rust
encoder, per this workspace's dual Rust/JS-vector convention. Both scripts
are already invoked by `scripts/check-all.sh:31-32`.

**Gate:** `cargo fmt --all`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, `cargo test --workspace --all-targets
--all-features`, `./scripts/check-all.sh`, plus fresh security and
tech-lead review.

## Unresolved risks

1. **Where `next_validators` comes from.** This design makes it an
   operator-supplied input whose only authority is the outgoing quorum —
   safe, but not governance: operators must agree out of band.
   `governance::GovernanceAction`/`ApplyValidatorSetChange` is the eventual
   answer, and `core-protocol.md` §14 already calls it "still-deferred."
2. **Hash-suite activation landing on the transition epoch.** A
   `HashSuiteSchedule` activating at `e+1` means `next_validator_set_digest`
   and `activation_digest` are computed under the new suite while the vote
   is framed at `e`. This is deterministic under the design above, but it
   is untested. The implementation must add a test for this case rather
   than forbid it.
3. **Protocol upgrades.** This design pins the protocol version across the
   transition. A `ProtocolUpgrade` activating at `e+1` is undesigned, and
   node-core does not currently read protocol-upgrade state. The
   implementation must state this constraint and assert it, not silently
   allow it.
4. **Multi-step catch-up** requires operators to supply every intermediate
   certificate in order (risk 1's sibling; there is no ingress to fetch
   them automatically).
5. **`activated_at_checkpoint` semantics** diverge across validators by
   design (C1 no longer byte-compares it; §2 excludes it from the digest).
   Kept for audit, excluded from the digest — this DR treats that as
   acceptable, but the security review that gates implementation should
   confirm it.

## Consequences / Deferred

- This DR fixes and implements Slice 2's design in
  `crates/consensus/src/epoch_transition.rs`,
  `crates/node-core/src/epoch_transition.rs`, and
  `crates/node-core/src/epoch_transition/tests.rs`; **modified:**
  `crates/consensus/src/lib.rs` (module + `NonSuccessiveEpoch`),
  `crates/node-core/src/local_instance_state.rs` (new key builder, and the
  `fastpath_synthetic_prepare_request_id` epoch-mixing fix below),
  `crates/node-core/src/mutation_fence.rs` (`ObjectLockState`),
  `crates/node-core/src/fast_path.rs` (`load_validator_set` visibility,
  stale prepared-record supersession), `crates/node-core/src/genesis.rs`
  (C1 restart-verify), `crates/node-core/src/query.rs`
  (`query_committed_epoch_state`),
  `crates/node-core/src/{paid_execution,local_execution,lib}.rs` (emit
  `Delete` for reclaimable locks; `publication.rs` needed no change, since it
  never holds a fast-path *object* lock — only the epoch-disjoint sender
  nonce lock C4 already covers), `scripts/fast-path-vectors.mjs`,
  `scripts/fast-vote-vectors.mjs`, `docs/architecture/core-protocol.md`
  §11/§14/§20, `TODO.md`'s Slice 2 entry, and DR-0131's Status and
  Consequences sections (referencing this DR's C1-C7 corrections rather
  than restating them).
- Reused, not reinvented: `mutation_fence::{fence_epoch_state,
  fence_object_lock, fence_sender_nonce_lock}`, `fast_path::load_validator_set`,
  `validator_set::ValidatorSet::new`/`digest`,
  `crypto::frame_signature_message`, `canonical_encoding::CanonicalStruct`,
  `fast_path::install_validator_set`'s commit-outcome mapping,
  `fast_path::tests::ValidatorFiles` and `four_validators()`,
  `IndeterminateOnceApplyStore`'s and `EpochRacingEngine`'s patterns
  (mirrored, not reused directly, as
  `IndeterminateOnceActivateStore`/`RacingActivateEngine` and a real-thread
  `BarrierGatedActivateStore`, since `activate` intercepts `commit_durable`
  rather than `commit_invocation` and has no pluggable engine to hook).
- Four latent bugs were found and fixed by this slice's own adversarial
  evidence, not by design review: (1) `propose_and_vote`'s "already exists"
  check, as first implemented, treated a transition record present at
  `current_epoch + 1` as an `AlreadyActivated` outcome; since `activate`
  installs the live epoch record and that row atomically in the same commit,
  a *literal replay* of the same combination is partial or corrupt prior
  state, not `AlreadyActivated` — see the "implementation review" revision
  above. (2) `fastpath_synthetic_prepare_request_id`'s preimage did
  not mix in the epoch directly, relying solely on
  `resolver.hash_for_purpose`'s own epoch-indexed suite selection; a
  resolver whose schedule does not change suite across the transition (the
  common case) therefore produced the identical synthetic prepare-receipt id
  for the same original request id reused at the next epoch, silently
  breaking C5's own stale-prepared-record supersession the first time it was
  exercised end-to-end. The epoch is now mixed directly into the preimage
  bytes. (3) The implementation-review fix for (1) itself overstated its own
  claim: `propose_and_vote`'s epoch fence and its transition-record read are
  two separate reads, so a concurrent `activate` really can commit between
  them, producing exactly that combination as a benign race, not corrupt
  state; `propose_and_vote` now re-reads the live epoch record at that point
  and returns the retryable `StateConflict` for that case, reserving
  `Invalid` for a live epoch record that still reads `current_epoch` — see
  the "concurrency/canonicalization review" revision above. (4)
  `derive_activation_set` encoded `next_validators` in caller-supplied
  order; `ValidatorSet::new` already canonicalizes its own digest
  internally, but the committed `FastPathValidatorSetRecord` bytes and
  `activation_digest` were not order-invariant, so independently derived
  permutations of the identical operator-authorized set could disagree on
  `activation_digest` and never quorum. `next_validators` is now sorted by
  `ValidatorId` before anything is validated or encoded — see the same
  revision.
- Explicit canonical equivocation evidence is implemented by
  [DR-0133](0133-fastvote-equivocation-evidence.md), including the exact
  `EpochTransitionVote` conflict key (same outgoing validator, same outgoing
  epoch, differing target tuple). DR-0134 specifies Slice 4's authorization
  boundary; its companion code and reviews remain the Phase 2 closure gate.
- Bond-linked slashing execution and deterministic transaction-fee escrow
  distribution to the final certificate signer set remain Phase 3,
  unaffected by this DR.
- This DR does not change DR-0129's `crates/consensus` types, wire IDs, or
  signature domain, and does not change DR-0130's or DR-0131's Phase 1/
  Slice 1 invariants; it only adds the new frame families and node-core
  module described above.
- **Slice 2 is implemented; Phase 2 later closed in PR #180.** This DR closes
  Slice 2 but did not by itself close the FastVote Certified Execution Gate's
  Phase 2 entry in `TODO.md`; DR-0134's companion implementation owns that closure.
  Retired-validator and wrong-epoch rejection are now end-to-end observable through a real
  transition. FastVote is not complete until Phase 3.
