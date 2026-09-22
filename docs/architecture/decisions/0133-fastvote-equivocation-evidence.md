# DR-0133: FastVote equivocation evidence detailed design (phase 2, slice 3)

## Status

Accepted as the detailed design for FastVote Phase 2 Slice 3, 2026-09-22,
**revised the same day** after review found that the original text
incorrectly deferred cross-transaction same-object-version conflicts (see
"Revision" below). This DR fixes the wire format, canonical codec, frame
IDs, in-process node-core APIs, persistence key/record, idempotency and
atomic compare-and-swap behavior, historical-validator-set verification
rule, and restart/tamper posture for explicit canonical equivocation
evidence that [DR-0131](0131-fastvote-validator-lifecycle.md) named but left
pending its own decision record.

**Implemented and locally validated, 2026-09-22.** Canonical frames
`0xD006`/`0xD008` have been revised in place with `locked_objects_digest`;
`0xD00C` (`LockedObjectSetPreimage`), `0xD00D` (`FastVoteEquivocationEvidence`),
`0xD00E` (`FastVoteObjectConflictEvidence`), `0xD00F` (`EpochTransitionEquivocationEvidence`),
and node-core `0x6429` (`FastPathEquivocationEvidenceRecord`) are implemented
with strict rechecks on exact prepare replay and before certificate apply,
normalized signature-excluding evidence identity, restart-verified transition-chain
anchored historical validator resolution, deterministic transactional store/query
with `AlreadyRecorded`, comprehensive unit/adversarial tests across `consensus`
and `node-core`, and independent JS vectors. Completing this slice did not by
itself close the FastVote Certified Execution Gate's Phase 2 entry in
`TODO.md`; [DR-0134](0134-fastvote-authorization-boundary.md)'s companion
Slice 4 code and review gate later landed in PR #180 and closed Phase 2.
This DR implements no bonding, slashing, penalty,
reward, or external ingress. FastVote overall remains incomplete until Phase 3.

**Revision (2026-09-22, same day, review correction).** The original text
found that `FastVote`'s existing `tx_hash`-scoped conflict key made a
`locked_objects_digest` field unnecessary, and left cross-transaction
same-object-version conflicts as a structurally-prevented, out-of-scope
failure mode. That reasoning was **wrong**: it covered only misconduct where
an honest validator's own lock logic would already have blocked a second
`cast_vote` — but it did not evidence the case where a validator's lock logic
*was* bypassed (bug or modified binary) and it doubly voted for two
*different* transactions over the identical `(ObjectId, version)`. That case
is exactly what equivocation evidence must be able to prove; deferring it
left Slice 3 unable to evidence a real, named FastVote safety violation. This
revision adds `locked_objects_digest` to `FastVote`/`FastCertificate`'s
canonical v1 payload **in place** (this repository is unreleased: no v2, no
compatibility layer — see "In-place revision" below) and covers both
misconduct classes with distinct canonical evidence shapes. It also corrects
six further review findings, folded into the relevant sections below rather
than narrated separately: normalized (signature-excluding) evidence
identity, `HashSuiteResolver`/context binding, historical validator-row
trust anchoring against the restart-verified transition chain, real
`DurableCommitOutcome`/`DurableCommitRejection` mapping, query-side
cross-checking, and `StateKeyScanner`-based future enumeration.

**Revision (2026-09-22, same day, second review pass).** Folded into the
relevant sections rather than narrated separately: class (b) submission now
explicitly hashes each attached preimage and requires it match its vote's
signed `locked_objects_digest`, fail-closed, before either preimage is
trusted for anything else (§8 step 4); `fast_path::prepare`/`apply` extend
their existing commitment-style independent-binding checks to
`locked_objects_digest` (§2); `0xD00E` decode/verify now require the claimed
`conflicting_object_id`/`conflicting_version` be the *smallest* shared pair,
not merely a present one, and require each preimage's own context echo
against its attached vote (§5); `load_historical_validator_set` takes
`protocol_version` as an explicit parameter (§7); a new unresolved risk
names the inherent limit that a signer can sign a false
`locked_objects_digest`, with honest certificate formation/application as
the compensating control (Unresolved risks item 6); and §9's restart/tamper
wording is tightened so structural decode is never credited with detecting
a well-formed corrupted signature.

## Context

[DR-0130](0130-owned-object-certified-execution.md) (Phase 1) implemented
local certified execution against one static signed genesis validator set.
[DR-0131](0131-fastvote-validator-lifecycle.md) (Phase 2 Slice 1) added the
CAS-fenced `FastPathEpochRecord`, the epoch-stamped `FastPathLockRecord`, and
the shared two-tier mutation-fencing model. [DR-0132](0132-fastvote-epoch-transition.md)
(Phase 2 Slice 2) implemented the outgoing-set-certified `e -> e+1` epoch
transition, `EpochTransitionVote`/`EpochTransitionCertificate`
(`0xD009`-`0xD00B`), and the permanent per-`next_epoch`
`FastPathEpochTransitionRecord` (`0x6427`) audit chain that
`install_genesis_with_history`'s restart-verify (DR-0132 §7) re-decodes,
re-loads, and cryptographically re-verifies in full on every node startup.
This DR's historical-validator-set trust rule (§6) relies on, but does not
repeat, that chain.

DR-0132's own replay/conflict matrix originally described "two validators
propose different `next_validators`" as "a canonical conflicting-statement
pair for Slice 3." That was a **correction target**, not a stable citation:
it conflated two *different* validators disagreeing (ordinary failure to
reach quorum, not misbehavior by either) with the *same* validator
equivocating. DR-0132 has been corrected to say so explicitly ("an ordinary
two-validator disagreement, not equivocation... only the *same* validator
signing two such votes is"); this DR's own conflict keys (§1) are built on
the corrected reading; DR-0132's own text now points here.

Two independent signable statement families exist in the owned-object fast
path: `consensus::FastVote`/`FastCertificate` (`0xD006`-`0xD008`, revised in
place by this DR) and `consensus::EpochTransitionVote`/
`EpochTransitionCertificate` (`0xD009`-`0xD00B`, unchanged by this DR — no
owned object is ever locked by an epoch transition). Both are stateless,
epoch-scoped, Ed25519-signed canonical frames verified by a structurally
mirrored `*Certifier` bound to one immutable `ValidatorSet` snapshot. This DR
defines how conflicting statements are recognized, normalized into canonical
evidence envelopes, cryptographically re-verified against the *historical*
validator set for the epoch they claim, and durably, idempotently persisted
— without touching either family's signature domain, and without any new
signing operation (evidence submission verifies; it never signs).

## Decision

### 1. Misconduct classes and conflict keys

Three independent conflicting-statement classes exist. Each requires an
**equal** subset of fields (the conflict context) and a **differing** rest
(what makes the pair contradictory), and none accepts byte-identical
signable payloads (differing only in signature encoding) as evidence — see
"Identical statements are not evidence" below.

**(a) FastVote, same transaction, conflicting outcome.**

* Equal: `chain_id`, `protocol_version`, `epoch`, `validator`, `tx_hash`.
* Differ: the signable payload as a whole — in practice
  `execution_effects_hash` and/or `locked_objects_digest` (§2), since every
  other payload field is already pinned by the equal set.

[DR-0130](0130-owned-object-certified-execution.md)'s prepare step is
exact-replay-reconciled and byte-stable: re-preparing the identical signed
intent, already locked, returns the identical previously-signed `FastVote`
rather than signing a new one. An honest validator can therefore only ever
produce one payload for one `tx_hash`, permanently. Two valid, differently
signed `FastVote`s for the identical `tx_hash` with a differing payload is
unambiguous proof of a double statement about the identical transaction.

**(b) FastVote, different transactions, overlapping locked object version.**

* Equal: `chain_id`, `protocol_version`, `epoch`, `validator`.
* Differ (required): `tx_hash`.
* Additionally required: the two votes' `locked_objects_digest`-committed
  object sets (§2, §3) share at least one identical `(ObjectId, version)`
  pair — the validator signed two different transactions each claiming the
  identical locked object version. The two matched entries' digests are
  **not** required to agree: equal digests still prove the same-version
  double claim (the ordinary case, since a version's content is immutable);
  differing digests are an even stronger contradictory-state claim and must
  not evade evidence by being excluded (§5).

This is the case the original text wrongly deferred: DR-0130's exclusive
per-object-version lock (acquired *before* `cast_vote`) prevents an *honest*
validator's own prepare path from ever reaching a second `cast_vote` over a
conflicting `(ObjectId, version)`. A validator that signed one anyway did so
by bypassing that lock logic — a real, evidenceable safety violation, not a
structurally-impossible case, and Slice 3 must be able to prove it.

**(c) EpochTransitionVote, same outgoing epoch, conflicting activation target.**

* Equal: `chain_id`, `protocol_version`, `epoch` (the outgoing epoch),
  `validator`.
* Differ: the signable payload as a whole — in practice
  `current_validator_set_digest`, `next_validator_set_digest`, or
  `activation_digest` (`next_epoch` is forced to `epoch + 1` by
  `decode_epoch_transition_vote` itself, so it can never legitimately
  differ). One outgoing validator supports at most one activation target per
  outgoing epoch by construction (DR-0132 §3.B), so `(chain_id,
  protocol_version, epoch, validator)` alone is already the complete
  conflict context — no `tx_hash`-equivalent sub-key exists for this family.

**Identical statements are not evidence.** A pair whose signable payloads
are byte-identical — even with differing signature bytes, which can happen
for a scheme admitting multiple valid representations of one payload
(already modeled in this crate:
`try_form_certificate_selects_duplicate_valid_signatures_independent_of_arrival_order`)
— is not equivocation: both statements attest to the identical fact. This is
enforced on payload bytes, never full statement bytes, and is also why
persisted-evidence identity is normalized to exclude signatures (§5).

**Why cross-epoch pairs are never evidence, for any class.** A lock
stamped `locked_epoch = e` is either consumed by an epoch-`e` apply or
becomes CAS-reclaimable once the live epoch advances past `e` (DR-0132 §3.D)
— reclamation is safe precisely because every epoch-`e` certificate becomes
permanently unappliable the instant the epoch record advances (DR-0131 "Key
transition safety proof," item 4). So a validator voting at epoch `e` and
again at `e+1` for a different transaction touching the identical object
version is not a conflict: it is exactly what honestly re-locking a
reclaimed object at the new epoch looks like, not a simultaneous double
claim. This is why every class above requires `epoch` equal, not merely
`(chain_id, protocol_version)` equal.

### 2. In-place revision of `FastVote`/`FastCertificate` v1

Class (b) requires the exact locked object set a `FastVote` attests to be
independently, cryptographically recoverable from the vote itself — it
cannot be inferred from `execution_effects_hash` alone, since that value is
opaque outside the validator that computed it. This repository is unreleased
and prohibits compatibility clutter for discarded intermediate designs, so
`FastVote`/`FastCertificate`'s **existing** canonical v1 payload (`0xD006`,
`0xD008`; DR-0129/DR-0130) is revised in place — same type ids, same version
1, no `0xD006v2` or parallel legacy decoder. Any FastVote/FastCertificate
bytes encoded before this revision no longer decode; this DR's own stable
vectors must be regenerated from scratch, exactly as DR-0131 redefined
`0x641B` in place.

**New field:** `locked_objects_digest: Digest32` — the digest of a
`LockedObjectSetPreimage` (§3) over the bounded, canonical, validator-
independent ordered set of exact `(ObjectId, version, digest)` references
the vote's transaction locks (DR-0130's existing `PaidAdmissionOutput::
locked_objects: Vec<ObjectRef>`, sorted ascending by `ObjectId` before
hashing — that field is already populated at `crates/node-core/src/fast_path.rs:511-550`'s
`cast_vote` call site; it is not new node-core state, only a new digest over
already-existing data). Hashed under `HashPurpose::ExecutionEffects` (the
same purpose the staged-commit commitment already uses — no `HashSuite`/
genesis vector widening needed, matching DR-0130's own precedent).

**`FastVote` payload (`0xD006/v1`) field layout — pure append, fields 1-7
unchanged:**

| Field | Was | Now |
|---|---|---|
| 1-5 | chain_id, protocol_version, epoch, tx_hash, execution_effects_hash | unchanged |
| 6 | validator | unchanged |
| 7 | signature_scheme | unchanged |
| 8 | *(absent)* | **`locked_objects_digest: bytes32` (new)** |

**`FastCertificate` (`0xD008/v1`) header — renumbered** (field 6 was
already `count: u32`, so a pure append would collide with the vote list's
dynamic field range `7..=6+count`, up to `7..=10006` at
`MAX_FAST_CERTIFICATE_VOTES`):

| Field | Was | Now |
|---|---|---|
| 1-5 | chain_id, protocol_version, epoch, tx_hash, execution_effects_hash | unchanged |
| 6 | count: u32 | **`locked_objects_digest: bytes32` (new)** |
| 7 | *(vote 0 started here)* | **count: u32 (moved)** |
| 8+i | — | vote `i` (formula changes from `index+7` to `index+8`) |

`decode_fast_certificate`'s `expected_field_count` becomes
`count.checked_add(7)` (was `+6`); the vote-field loop becomes
`u16::try_from(index + 8)` (was `+7`).

**API changes, threaded through exactly like `execution_effects_hash`
already is (no other behavior changes):**

* `FastPathCertifier::cast_vote(tx_hash, execution_effects_hash,
  locked_objects_digest, signer)`.
* `try_form_certificate(tx_hash, execution_effects_hash,
  locked_objects_digest, votes, verifier)`: the target is now a triple; the
  match/exclusion-policy header check additionally requires
  `vote.locked_objects_digest == locked_objects_digest`.
* `verify_certificate`: the per-vote consistency check additionally requires
  `vote.locked_objects_digest == certificate.locked_objects_digest`.
* `FastCertificate` gains a `locked_objects_digest: Digest32` field.

`EpochTransitionVote`/`EpochTransitionCertificate` (`0xD009`-`0xD00B`) are
**unchanged** — no owned object is ever locked by an epoch transition.

**`fast_path::prepare`/`apply` must extend their existing independent-binding
checks to `locked_objects_digest`, not only accept it as an inert extra
field.** DR-0130 already applies this "recompute and compare, never merely
trust the stored value" discipline to `execution_effects_hash`/commitment at
two points; `locked_objects_digest` needs the identical treatment at the
same two points, or the new field only decorates the wire format without
actually closing the gap class (b) exists to evidence:

* **Prepare's exact-replay stored-vote check** (`fast_path.rs:453-463`)
  currently requires, among other fields,
  `vote.execution_effects_hash == existing.commitment` before returning the
  replayed vote. It must additionally require
  `vote.locked_objects_digest` equals the digest re-derived from
  `existing.locked_objects` (the same sort-then-hash procedure §2 already
  specifies at the `cast_vote` call site) — else `"fast-path prepared
  replay vote mismatch"`, the same fail-closed outcome the existing checks
  on that line already produce. Without this, a stored vote whose
  `locked_objects_digest` disagreed with the record it was replayed
  alongside would be silently returned as if consistent.
* **Apply's independent re-derivation** (`fast_path.rs:807-823`) already
  recomputes `fresh_commitment` from the freshly re-admitted
  `admission.*` fields and requires `fresh_commitment == prepared.commitment`
  before proceeding, independently of the earlier `admission.locked_objects
  != prepared.locked_objects` structural check at line 788. It must
  additionally recompute a `fresh_locked_objects_digest` from
  `admission.locked_objects` (same procedure) and require
  `fresh_locked_objects_digest == certificate.locked_objects_digest` —
  else `"fast-path re-derived locked-object digest no longer matches the
  certificate"`, placed alongside the existing `fresh_commitment` check.
  This is deliberately independent of, not redundant with,
  `verify_certificate`'s own internal per-vote `locked_objects_digest`
  consistency check (§ above): that check only proves the certificate's
  *votes* agree with the certificate's *header*; it says nothing about
  whether the header agrees with what a fresh, independent re-admission of
  the same request actually locked. Without this, a certificate whose
  header carried a *self-consistent but wrong* `locked_objects_digest`
  (every vote agreeing with a header that was never actually re-verified
  against reality) could apply undetected — the exact same class of gap
  `fresh_commitment` was already introduced to close for the commitment
  field, now closed for this one too.

### 3. `LockedObjectSetPreimage` (new frame, `0xD00C/v1`)

Unlike DR-0132's `0x6428` (a true digest-only preimage, never serialized
anywhere), this preimage **is** transmitted and durably stored — class (b)
evidence must carry it so a verifier can recompute the digest without
re-deriving the original admission. It therefore needs a real, independently
decodable frame, not the length-prefixed ad hoc framing
`crates/node-core/src/fast_path/commitment.rs` uses for its own
never-decoded-back envelope.

| Field | Type |
|---|---|
| 1 | chain_id str |
| 2 | protocol_version u32 |
| 3 | epoch u64 |
| 4 | count u32 |
| 5+i | `objects::encode_object_ref(entry_i)` bytes, `i` in `0..count` |

The producer takes fields 1-3 from the same authenticated intent context
whose admission produced the locked-object set; they are never caller-
invented metadata independent of the vote context.

Entries are strictly ascending by `ObjectId` bytes (`ObjectId: Ord` already;
`ObjectRef` gains no new derive, sorting is by `.id`), no duplicates —
decode rejects a wrong order or a duplicate `ObjectId` with the new
`NonCanonicalLockedObjectOrder` error, the same discipline
`decode_fast_certificate` already applies to its own vote list. Bounded at
`MAX_LOCKED_OBJECT_SET_ENTRIES: usize = 4_096`, matching (without a new
crate dependency — `consensus` does not depend on `runtime`)
`runtime::MAX_DURABLE_OBJECT_MUTATIONS`, the existing ceiling on how many
`Write`/`Consume` objects one admitted request can ever declare — a
request's locked-object set can never exceed the mutation bound it already
respects. `consensus` gains a new dependency on the `objects` crate (already
dependency-cycle-free: `objects` depends only on `canonical-encoding`,
`protocol-types`, `protocol-upgrades`) for `ObjectId`/`ObjectRef` and their
existing `encode_object_ref`/`decode_object_ref`.

Decode requires, beyond the shared guarantees: exact type/version/field set,
`count` bounded and matching the declared field count, strict ascending
`ObjectId` order with no duplicate, and byte-exact re-encoding.

### 4. Why this lives partly in `crates/consensus`

Unchanged from the original design: `crates/consensus` holds pure, stateless
canonical types, codecs, and signature verification bound to a
caller-supplied `ValidatorSet`; `crates/node-core` holds durable persistence,
`HashSuiteResolver`-driven digest computation, and the historical-state
lookup a snapshot comes from. Consensus never calls a resolver — exactly as
it never re-derives `execution_effects_hash`, it never re-derives
`locked_objects_digest` from a `LockedObjectSetPreimage` either; hashing a
preimage and comparing it to a vote's signed digest is node-core's job
(§6, §7). No new signing operation exists anywhere in this design: evidence
submission only re-verifies already-signed statements.

### 5. Canonical evidence envelopes (`crates/consensus/src/equivocation.rs`, new module)

Next free consensus type ids verified by sweep: `0xD00C`-`0xD00F`
(`0xD001`-`0xD00B` already allocated).

| Frame | Type | Shape |
|---|---|---|
| `0xD00C/v1` | `LockedObjectSetPreimage` | §3 |
| `0xD00D/v1` | `FastVoteEquivocationEvidence` (class a) | `{1: chain_id, 2: protocol_version, 3: epoch, 4: tx_hash, 5: validator, 6: low (nested `0xD007`), 7: high (nested `0xD007`)}` |
| `0xD00E/v1` | `FastVoteObjectConflictEvidence` (class b) | `{1: chain_id, 2: protocol_version, 3: epoch, 4: validator, 5: conflicting_object_id bytes32, 6: conflicting_version u64, 7: low (nested `0xD007`), 8: low_preimage (nested `0xD00C`), 9: high (nested `0xD007`), 10: high_preimage (nested `0xD00C`)}` |
| `0xD00F/v1` | `EpochTransitionEquivocationEvidence` (class c) | `{1: chain_id, 2: protocol_version, 3: epoch, 4: validator, 5: low (nested `0xD00A`), 6: high (nested `0xD00A`)}` |

Seven new additive `ConsensusError` variants (each serving exactly one new
build/decode path, mirroring DR-0129's precedent):

* `EquivocationEvidenceConflictKeyMismatch` — required-equal fields differ
  (classes a/b/c).
* `EquivocationEvidenceStatementsIdentical` — byte-identical payloads
  (classes a/c; structurally unreachable for class b, which already
  requires `tx_hash` to differ).
* `NonCanonicalEquivocationEvidenceOrder` — `low`/`high` not in canonical
  order (all three classes; distinct from `NonCanonicalCertificateVotes`
  because it names a different nested shape).
* `NonCanonicalLockedObjectOrder` — `LockedObjectSetPreimage` entries
  misordered or duplicated (§3).
* `ObjectConflictRequiresDistinctTransactions` — class (b) build called with
  `tx_hash` equal (use class (a) instead).
* `ObjectConflictNotFound` — class (b) build found no shared `(ObjectId,
  version)` entry between the two preimages, regardless of whether their
  digests agree.
* `ObjectConflictNotProvenByPreimages` — class (b) decode/verify: the
  claimed `conflicting_object_id`/`conflicting_version` either does not
  have an entry in **both** attached preimages (digest agreement between
  the two entries is not required — see §5), **or** does, but is not the
  smallest `(ObjectId, version)` pair the two preimages actually share —
  the header must name exactly what a canonical `build_*` would have
  produced from these preimages, never merely *an* overlap.

These are distinct from the existing, unrelated
`ConsensusError::Equivocation { validator, view, first, second }`, which is
`ChainedHotStuff`'s own in-memory same-view double-vote rejection (shared-
object consensus, no persisted evidence, different family) — untouched by
this DR.

**Canonical ordering.** Classes (a)/(c): ascending lexicographic comparison
of `low`/`high`'s own signable payload bytes. Class (b): ascending
comparison of `low.tx_hash`/`high.tx_hash` (payload bytes always differ
since `tx_hash` is part of the payload and is required unequal, but ordering
by the one field that is *guaranteed* to differ is simpler and equally
canonical). All three: total, independent of caller argument order or
observation order — `(A, B)` and `(B, A)` always produce the identical
envelope.

**Build algorithms (pure, no I/O, no resolver):**

`build_fast_vote_equivocation_evidence(a, b)` (class a) and
`build_epoch_transition_equivocation_evidence(a, b)` (class c): require the
equal-field set, require payload divergence
(`EquivocationEvidenceStatementsIdentical` otherwise), order into
`(low, high)`, return the envelope. Unchanged in shape from the original
design; class (a)'s payload comparison now naturally also catches a
`locked_objects_digest`-only divergence, with no code change needed since it
already compares whole-payload bytes.

`build_fast_vote_object_conflict_evidence(a, b, a_preimage, b_preimage)`
(class b — operates on **already-decoded, already-structurally-valid**
`FastVote`/`LockedObjectSetPreimage` values, exactly like class (a) operates
on already-decoded votes):

1. Require the equal-field set (chain/protocol/epoch/validator); else
   `EquivocationEvidenceConflictKeyMismatch`.
2. Require `a.tx_hash != b.tx_hash`; else
   `ObjectConflictRequiresDistinctTransactions`.
3. Require `a_preimage`'s/`b_preimage`'s own `(chain_id, protocol_version,
   epoch)` equal `a`'s/`b`'s respective fields (structural echo check).
4. Find every `(ObjectId, version)` pair present in **both**
   `a_preimage.entries` and `b_preimage.entries` — matched on `id` and
   `version` **only**. Digest agreement between the two matched entries is
   **not** required and is never checked here: equal digests still prove the
   validator claimed the identical object version for two different
   transactions (the ordinary case, since a version's content is
   immutable); differing digests are an *even stronger* contradictory-state
   claim (the validator attested to two different exact contents for what
   it also claimed was the identical version) and must not evade evidence
   by being excluded from the intersection. Both complete `ObjectRef`
   entries (each carrying its own preimage's signed digest) stay in
   `a_preimage`/`b_preimage` exactly as decoded, so either signed digest
   remains independently re-verifiable later (§7) — this step never drops,
   merges, or picks between them. If no `(ObjectId, version)` pair is
   shared, `ObjectConflictNotFound`.
5. If one or more pairs are shared, this DR's canonical evidence identity
   names exactly **one**: the pair ordered smallest by `(ObjectId, version)`
   ascending (`ObjectId` alone already disambiguates in practice, since
   each preimage carries at most one entry per `ObjectId` — DR-0130's
   existing duplicate-object rejection at admission — but the comparator is
   defined on the full `(ObjectId, version)` pair for totality). Every
   shared pair, not only the canonical one, remains visible to any reader of
   the attached preimages; naming only the smallest is solely what makes
   one vote pair's evidence identity deterministic and single-valued (§8),
   not a claim that other overlaps are undetected or require separate
   evidence — see "Unresolved risks."
6. Order `(low, high)` by ascending `tx_hash`, moving each statement's own
   preimage with that statement during the swap; return the envelope with
   `conflicting_object_id`/`conflicting_version` from step 5.

**Verify algorithms (pure given a caller-supplied `ValidatorSet`; no
resolver — hashing a preimage against `locked_objects_digest` is node-core's
job, §6/§7):**

Classes (a)/(c): unchanged from the original design —
`FastPathCertifier::verify_vote`/`EpochTransitionCertifier::verify_vote` on
both `low` and `high`.

Class (b): `FastPathCertifier::verify_vote` on both `low` and `high`
(now over the extended payload, so this already implicitly checks nothing
about the preimages — signature validity only), **plus** an independent
re-derivation of build steps 3-5 in full, not merely a presence check. Each
preimage's `(chain_id, protocol_version, epoch)` must first echo its attached
vote, then verification must
recompute the **complete** set of `(ObjectId, version)` pairs shared by
`evidence.low_preimage.entries` and `evidence.high_preimage.entries`
(matched on `(ObjectId, version)` only, never requiring the two entries'
digests to agree, exactly as build defines the match), require it
non-empty, and require `(evidence.conflicting_object_id,
evidence.conflicting_version)` equals the **smallest** pair in that set by
`(ObjectId, version)` ascending order — not merely *a* member of it. A
forged envelope naming a real-but-non-canonical overlap (when a smaller one
also exists between the same two preimages) is rejected exactly as one
naming a pair absent from either preimage entirely: both are
`ObjectConflictNotProvenByPreimages`, since both mean the header does not
name what build would have deterministically produced from these exact
preimages.

**Decode** (all three classes), beyond the shared guarantees: exact
type/version/field set; every nested frame decodes under its own strict
decoder; outer header fields equal both nested statements' corresponding
fields (`CertificateVoteMismatch` otherwise, reusing `FastCertificate`'s
existing pattern); canonical `low`/`high` order
(`NonCanonicalEquivocationEvidenceOrder` otherwise); class (b) additionally
requires `low.tx_hash != high.tx_hash`, requires
`evidence.low_preimage`'s own `(chain_id, protocol_version, epoch)` equal
`evidence.low`'s respective fields and `evidence.high_preimage`'s equal
`evidence.high`'s (the same structural echo check build step 3 performs,
`CertificateVoteMismatch` on disagreement — decode must not skip a check
build already requires just because the input arrived over the wire instead
of through `build_*`), and re-derives the canonical-minimum intersection
proof exactly as `verify_*` does above
(`ObjectConflictNotProvenByPreimages` on mismatch, covering both "absent
from one or both preimages" and "present but not the smallest shared pair")
— **decode proves the envelope is internally self-consistent; it does not,
and cannot, prove the attached preimages are the ones the validator actually
signed for.** That authenticity binding is `hash(preimage) ==
vote.locked_objects_digest`, which requires a resolver and is therefore
node-core's responsibility (§8 step 4), never decode's. Byte-exact
re-encoding closes every decoder, as usual.

### 6. Node-core durable record, key, and APIs (`crates/node-core/src/equivocation.rs`, new module)

Next free node-core fast-path frame id, **unaffected by the consensus-side
additions above and still correct:** `0x6429` (`0x6416`-`0x6428` already
allocated).

| Frame | Type | Key |
|---|---|---|
| `0x6429/v1` | `FastPathEquivocationEvidenceRecord` | `fastpath_equivocation_evidence_key(chain, evidence_epoch, validator, conflict_digest)` = `se/instances/v1/fastpath/equivocation/` + `encode_chain_id(chain)` + `be_u64(evidence_epoch)` + `validator[32]` + `conflict_digest[32]` |

Fields: `evidence_bytes: Vec<u8>` (the exact encoded `0xD00D`/`0xD00E`/
`0xD00F` frame; self-describing via its own nested type id, no separate
family field), `recorded_at_checkpoint: u64` (local-per-node, excluded from
`conflict_digest`, same convention as `FastPathEpochTransitionRecord.
activated_at_checkpoint`).

**Normalized identity, not full-byte identity, is what determines the key**
(review correction: the original design hashed the *full* `evidence_bytes*,
including signatures, into the key. Two valid signature encodings of the
identical logical conflict — the same modeled case §1 already excludes from
"is this evidence at all" — would then hash to two *different* keys and
create duplicate rows instead of collapsing to `AlreadyRecorded`). Each
class defines a small, deterministic, length-prefixed
(`commitment.rs`-style, not a `CanonicalStruct` — this preimage is hashed
only, never itself decoded back) normalized-identity preimage that excludes
every signature:

* Class (a): domain tag `"fastvote-equivocation-identity-v1"` ||
  `chain_id` || `protocol_version` || `epoch` || `validator` || `tx_hash` ||
  length-prefixed `encode_fast_vote_payload(low)` || length-prefixed
  `encode_fast_vote_payload(high)`.
* Class (b): domain tag `"fastvote-object-conflict-identity-v1"` ||
  `chain_id` || `protocol_version` || `epoch` || `validator` ||
  `conflicting_object_id` || `conflicting_version` || length-prefixed
  `encode_fast_vote_payload(low)` || length-prefixed
  `encode_fast_vote_payload(high)` (preimage bytes themselves are
  **excluded**: `locked_objects_digest` is already inside each payload, so
  the identity is already anchored to the signed claim without duplicating
  the, possibly large, raw object list).
* Class (c): domain tag `"epoch-transition-equivocation-identity-v1"` ||
  `chain_id` || `protocol_version` || `epoch` || `validator` ||
  length-prefixed `encode_epoch_transition_vote_payload(low)` ||
  length-prefixed `encode_epoch_transition_vote_payload(high)`.

`conflict_digest = resolver.hash_for_purpose(evidence.epoch,
HashPurpose::NodeEvent, &normalized_identity_bytes)`.

**What the key's digest protects, precisely.** Because signatures are
excluded, the key's digest is a content-self-consistency check over the
*claim* (who, what epoch, which two payloads, which conflict), not a
cryptographic integrity check over the *stored signature bytes*. A row whose
decoded normalized identity disagrees with the digest its own key embeds is
tampered/corrupt content and is rejected (§8). A row whose stored signature
bytes were corrupted at rest, without changing the payload, is **not**
caught by this key check — that is caught only by an explicit re-`verify_*`
call, which any consumer (including the restart/tamper test, §9) can and
should make; the idempotent submission path deliberately does not
re-verify signatures on replay (§8), matching `activate`'s own
already-activated precedent (DR-0132 §3.C.3).

**Public API, all in-process, no ingress:**

```rust
pub fn submit_fast_vote_equivocation_evidence<S: StructuredDurableDomainStateStore>(
    store: &S, context: &DurableOperationContext, domain: AtomicityDomainId,
    resolver: &HashSuiteResolver, chain: &ChainId, protocol_version: ProtocolVersion,
    statement_a: &[u8], statement_b: &[u8], checkpoint: u64,
) -> Result<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>, EquivocationEvidenceError>;

pub fn submit_fast_vote_object_conflict_evidence<S: StructuredDurableDomainStateStore>(
    store: &S, context: &DurableOperationContext, domain: AtomicityDomainId,
    resolver: &HashSuiteResolver, chain: &ChainId, protocol_version: ProtocolVersion,
    statement_a: &[u8], statement_b: &[u8],
    preimage_a: &[u8], preimage_b: &[u8], checkpoint: u64,
) -> Result<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>, EquivocationEvidenceError>;

pub fn submit_epoch_transition_equivocation_evidence<S: StructuredDurableDomainStateStore>(
    store: &S, context: &DurableOperationContext, domain: AtomicityDomainId,
    resolver: &HashSuiteResolver, chain: &ChainId, protocol_version: ProtocolVersion,
    statement_a: &[u8], statement_b: &[u8], checkpoint: u64,
) -> Result<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>, EquivocationEvidenceError>;

pub enum EquivocationEvidenceOutcome<T> { Recorded(T), AlreadyRecorded(T) }
```

plus a read-only point lookup:

```rust
pub fn query_fastpath_equivocation_evidence<S: StructuredDurableDomainStateStore>(
    store: &S, context: &DurableOperationContext, domain: AtomicityDomainId,
    chain: &ChainId, evidence_epoch: Epoch, validator: [u8; 32], conflict_digest: Digest32,
) -> Result<Option<FastPathEquivocationEvidenceRecord>, NodeCoreError>;
```

**Query cross-checking (review correction).** `query_fastpath_equivocation_evidence`
must not return whatever decodes at the key without question: after
decoding, it recomputes the record's own normalized-identity digest (per
whichever of the three classes the nested type id dispatches to) and
requires it equal the caller-supplied `conflict_digest`, and requires the
decoded chain/epoch/validator equal the caller-supplied `chain`/
`evidence_epoch`/`validator` selectors. Any disagreement is
`NodeCoreError::PersistenceInvariant`, not a silent wrong-answer return — a
caller must be able to trust that a returned record actually answers the
exact selector it asked for, not merely "something happened to be stored at
that key."

`EquivocationEvidenceError` **carries the factored decoder's real errors**
(review correction: the original design silently converted everything to
`Invalid(&'static str)`): `Node(NodeCoreError)`, `Consensus(ConsensusError)`,
`FastPath(fast_path::FastPathError)` (from the shared validator-row decoder,
§7), `Publication(PublicationError)` (`PublicationContext::new`),
`Invalid(&'static str)` (this module's own semantic checks only).

**`HashSuiteResolver`/context binding (review correction).** Every entry
point (`submit_*`) first requires `resolver.chain_id() == chain &&
resolver.protocol_version() == protocol_version`, else
`Invalid("resolver does not match declared chain/protocol context")` —
the same check `authenticated_object_effects.rs`, `object_snapshots.rs`, and
`local_execution.rs` already make before trusting a caller-supplied
resolver. The two input statements' own `chain_id`/`protocol_version` are
then required equal to these now-verified parameters before any historical
lookup is built from them.

### 7. Historical validator-set verification rule

Evidence must verify against the committed validator set for the epoch it
claims, never the currently committed epoch — this is what makes evidence
for a since-retired validator or epoch remain verifiable forever.

**Trust anchor (review correction).** The original design loaded the
historical `FastPathValidatorSetRecord` row and used it **unverified against
anything** — a real gap: on-disk tampering of a historical row would have
been silently trusted, since historical rows are (correctly) never
CAS-fenced against the live epoch record. The fix relies on, without
repeating, DR-0132 §7's restart-verify chain, which has already
cryptographically re-verified every historical validator-set row and every
`FastPathEpochTransitionRecord` through the live epoch before this node was
considered started:

```rust
pub(crate) fn load_historical_validator_set<S: StructuredDurableDomainStateStore>(
    store: &S, context: &DurableOperationContext, domain: AtomicityDomainId,
    resolver: &HashSuiteResolver, chain: &ChainId, protocol_version: ProtocolVersion,
    evidence_epoch: Epoch,
) -> Result<ValidatorSet, EquivocationEvidenceError>;
```

`protocol_version` is an **explicit parameter**, not inferred from
`resolver.protocol_version()`: the resolver is already required equal to the
caller's declared `protocol_version` at the `submit_*` entry point (§6's
`HashSuiteResolver`/context-binding check), but `load_historical_validator_set`
is a `pub(crate)` boundary of its own and must not silently assume a caller
threading a resolver through without also passing the value it addresses
`PublicationContext::new` with — leaving it implicit would make the function
signature lie about what determines which historical row it reads.

1. Read the live `FastPathEpochRecord` (plain read, no CAS precondition —
   this call mutates nothing).
2. If `evidence_epoch == live.current_epoch`: trusted anchor =
   `live.current_validator_set_digest`.
3. If `evidence_epoch < live.current_epoch`: read
   `FastPathEpochTransitionRecord` at `fastpath_epoch_transition_key(chain,
   evidence_epoch + 1)`; require `record.from_epoch == evidence_epoch`;
   trusted anchor = `record.previous_validator_set_digest`. Absent record →
   `Invalid("no transition record for the evidence epoch")`, fail closed —
   there is no fallback to an unanchored read.
4. If `evidence_epoch > live.current_epoch`: `Invalid("evidence epoch is not
   yet committed")`, fail closed.
5. Load the row at `fastpath_validator_set_key(PublicationContext::new(chain,
   protocol_version, evidence_epoch))` (the explicit parameter, not the
   resolver) via the shared decoder factored out of
   `fast_path::load_validator_set` (§ below) — this already includes the
   existing `record.context == validator_context` check
   (`fast_path.rs:244`), inherited, not re-specified. Absent → `Invalid("no
   committed validator set for the evidence epoch")`.
6. Require `ValidatorSet::digest(resolver) == trusted anchor` from step 2/3;
   else `Invalid("historical validator set does not match the
   restart-verified transition chain")` — this is the tamper check the
   original design lacked.

**Reused, not reinvented:** the per-row decode/validate logic (decode
`FastPathValidatorSetRecord`, reject non-`Ed25519`, `ValidatorSet::new`,
context check) is factored out of `fast_path::load_validator_set` into a
shared `pub(crate) fn decode_validator_set_row(bytes, validator_context) ->
FastPathResult<ValidatorSet>`; `load_validator_set` becomes "fence + shared
decoder + compare digest against the *live* epoch record,"
`load_historical_validator_set` becomes "read (unfenced) + shared decoder +
compare digest against the *chain-anchored* value from steps 2/3." This is
why `EquivocationEvidenceError::FastPath` exists (§6): the shared decoder's
errors propagate through unchanged.

**Deliberate non-fencing of the live epoch record.** `submit_*` calls
neither `fence_epoch_state` nor `fence_current_epoch`. The only durable row
either function writes is the evidence row itself, uniquely keyed per
conflicting pair; no other path reads, writes, or fences it, and evidence
submission reads the live epoch record only as a plain, unfenced comparison
target in step 1 above — there is no shared mutable state to serialize
against.

### 8. Idempotency and atomic compare-and-swap

```
submit_fast_vote_equivocation_evidence(..., statement_a, statement_b, checkpoint):
  1. require resolver.chain_id() == chain && resolver.protocol_version() == protocol_version
  2. a = decode_fast_vote(statement_a)?; b = decode_fast_vote(statement_b)?
     require a.chain_id == *chain && a.protocol_version == protocol_version
  3. evidence = consensus::build_fast_vote_equivocation_evidence(&a, &b)?
  4. identity_bytes = fast_vote_evidence_normalized_identity(&evidence)   // §6, excludes signatures
     conflict_digest = resolver.hash_for_purpose(evidence.epoch, HashPurpose::NodeEvent, &identity_bytes)?
     key = fastpath_equivocation_evidence_key(chain, evidence.epoch, evidence.validator.as_bytes(), &conflict_digest)?
  5. observed = store.get_versioned_durable(context, domain, &key)?
  6. match observed.value():
       Some(existing_bytes) =>
         existing = decode_fastpath_equivocation_evidence_record(existing_bytes)?
         existing_evidence = decode_fast_vote_equivocation_evidence(&existing.evidence_bytes)?
         existing_identity_digest = resolver.hash_for_purpose(existing_evidence.epoch,
             HashPurpose::NodeEvent, &fast_vote_evidence_normalized_identity(&existing_evidence))?
         if existing_identity_digest == conflict_digest {
             return Ok(AlreadyRecorded(existing))   // same logical fact; no re-verification (§6)
         }
         return Err(Node(PersistenceInvariant("evidence record does not match its own key digest")))
       None =>
         evidence_bytes = consensus::encode_fast_vote_equivocation_evidence(&evidence)?
         validator_set = load_historical_validator_set(..., chain, protocol_version, evidence.epoch)?      // §7
         consensus::verify_fast_vote_equivocation_evidence(&evidence, validator_set, &FastPathEd25519Verifier)?
         record = FastPathEquivocationEvidenceRecord { evidence_bytes, recorded_at_checkpoint: checkpoint }
         transaction = AtomicStateTransaction::new(domain,
             AtomicStateReadSet::new(vec![StateReadAssertion::new(key.clone(), observed.revision())?])?,
             AtomicStateMutationSet::new(vec![StateMutationEntry::new(
                 key.clone(), StateMutation::Put(encode_fastpath_equivocation_evidence_record(&record)?))?])?)?
         match store.commit_durable(context, transaction) {
             DurableCommitOutcome::Committed => Ok(Recorded(record)),
             DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict { key: conflicting, .. })
                 if conflicting == key =>
               // The only legitimate writer of this exact key always writes
               // byte-identical content (§6); re-read once and resolve via
               // the `Some` branch above, rather than surfacing a raw
               // conflict for a benign same-content race.
               re_read_and_resolve_as_already_recorded_or_tampered(...)
             DurableCommitOutcome::Rejected(reason) =>
               Err(Node(NodeCoreError::DurableCommitRejected(reason)))   // real variant, not a test helper's mapping
             DurableCommitOutcome::Indeterminate(reason) =>
               Err(Node(NodeCoreError::DurableCommitIndeterminate(reason)))   // safe to retry; see below
         }
```

This mirrors `epoch_transition::activate`'s own real `DurableCommitOutcome`/
`DurableCommitRejection` mapping (review correction: the original design
pointed at the test-only `fast_path::install_validator_set` helper instead).

**`submit_fast_vote_object_conflict_evidence` (class b) is the same
algorithm with one mandatory extra step the other two classes have no
equivalent of**, inserted between build (step 3) and encoding/key
derivation (step 4) — steps renumbered here for this class only:

```
submit_fast_vote_object_conflict_evidence(..., statement_a, statement_b, preimage_a, preimage_b, checkpoint):
  1. require resolver.chain_id() == chain && resolver.protocol_version() == protocol_version
  2. a = decode_fast_vote(statement_a)?; b = decode_fast_vote(statement_b)?
     a_preimage = decode_locked_object_set_preimage(preimage_a)?
     b_preimage = decode_locked_object_set_preimage(preimage_b)?
     require a.chain_id == *chain && a.protocol_version == protocol_version
  3. evidence = consensus::build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage)?
  4. // MANDATORY, fail-closed, before evidence is treated as persistable at all:
     // the attached preimages are untrusted bytes until each one is proven to
     // hash to the exact digest its own vote signed. Skipping this would let
     // a submitter pair a genuinely conflicting pair of votes with fabricated
     // preimages that merely *claim* an intersection §5's structural checks
     // alone cannot rule out (they only prove internal self-consistency of
     // the envelope, never authenticity against the signed digest — §5's own
     // decode discussion already says so).
     require resolver.hash_for_purpose(evidence.low.epoch, HashPurpose::ExecutionEffects,
         encode_locked_object_set_preimage(&evidence.low_preimage)) == evidence.low.locked_objects_digest
       else Invalid("attached preimage does not hash to its FastVote locked_objects_digest")
     require resolver.hash_for_purpose(evidence.high.epoch, HashPurpose::ExecutionEffects,
         encode_locked_object_set_preimage(&evidence.high_preimage)) == evidence.high.locked_objects_digest
       else Invalid("attached preimage does not hash to its FastVote locked_objects_digest")
  5. identity_bytes = fast_vote_object_conflict_normalized_identity(&evidence)   // §6, excludes signatures and raw preimage bytes
     conflict_digest = resolver.hash_for_purpose(evidence.epoch, HashPurpose::NodeEvent, &identity_bytes)?
     key = fastpath_equivocation_evidence_key(chain, evidence.epoch, evidence.validator.as_bytes(), &conflict_digest)?
  6. observed = store.get_versioned_durable(context, domain, &key)?
     match observed.value():
       Some(...) => // identical to class (a)'s already-recorded/tamper resolution, §8 above
       None =>
         evidence_bytes = consensus::encode_fast_vote_object_conflict_evidence(&evidence)?
         validator_set = load_historical_validator_set(..., chain, protocol_version, evidence.epoch)?      // §7
         consensus::verify_fast_vote_object_conflict_evidence(&evidence, validator_set, &FastPathEd25519Verifier)?
         // ... record construction and atomic CAS write, identical to class (a), §8 above
```

Step 4's check is independent of, and strictly prior to, `consensus::
verify_fast_vote_object_conflict_evidence` in step 6 — that call verifies
signatures and re-derives the *structural* intersection claim (§5), but has
no resolver and therefore cannot itself bind the preimages to their vote's
signed digest. Step 4 is the only place in this entire design that
authenticity binding happens, and it must happen before the row is ever
considered a candidate for persistence.

`submit_epoch_transition_equivocation_evidence` (class c) has no preimage
step and is otherwise the identical algorithm to class (a), substituting its
own build/verify/encode functions and normalized-identity preimage (§6).

**Build-before-verification is a local information-disclosure caveat, never
a persistence gap.** In every class, the `Some`/already-recorded branch (§8
step 6/step 6 above) is reached *before* `verify_*` is ever called — an
in-process caller need only supply two statements that satisfy `build_*`'s
purely structural conflict-key/payload-divergence rules (§5), which requires
no genuine signature at all (garbage signature bytes of the right length
satisfy `decode_fast_vote`/`decode_epoch_transition_vote`/
`decode_locked_object_set_preimage` just as well as real ones), to learn
whether that exact normalized identity is already recorded. This lets a
caller who already has local access to call `submit_*` at all (§10:
local-operator-invoked, no external ingress) probe for the *existence* of
previously recorded evidence about a specific claimed conflict without
needing real signatures to do so. This is a local disclosure property only
— it never causes unverified evidence to be persisted (a `None` result
still requires step 4's preimage-hash check, where applicable, and full
signature verification before any write), and it discloses nothing to a
party who could not already call this in-process function.

**Indeterminate commit is always safely retryable, propagated, not
swallowed.** The write's only side effect is one idempotent, content-
addressed `Put` under a normalized-identity key. A retry after
`DurableCommitIndeterminate` either observes the row present (→
`AlreadyRecorded`, no re-verification) or still absent (→ safely re-attempts
from step 6's `None` branch); there is no partial-application state this
key's CAS discipline cannot already resolve, matching DR-0132 §5's identical
argument for `activate`.

### 9. Restart and tamper posture

Evidence rows are permanent, append-only, and deliberately **excluded**
from `install_genesis_with_history`'s restart-verify chain — that chain
binds the *live* singleton and *active* validator set every mutation path
fences against; evidence never fences against anything (§7), so folding an
unbounded, ever-growing evidence set into a chain re-walked on every restart
would add startup cost for no safety benefit.

Two properties give evidence its guarantees, and they cover strictly
different failure modes — neither substitutes for the other:

**(1) Structural decode catches malformed bytes, never a well-formed wrong
signature.** Byte-exact strict decode at every nesting level (outer
`0x6429`, `0xD00D`/`0xD00E`/`0xD00F`, and their own doubly-nested
`FastVote`/`EpochTransitionVote`/`LockedObjectSetPreimage`) requires exact
type/version/field sets and byte-exact re-encoding, so it reliably catches a
truncated frame, a corrupted length prefix, a wrong field count, or any
other change that breaks the canonical shape. It has **no opinion on
signature validity**: a signature field has no structural invariant beyond
its declared length, so a bit-flipped-but-still-correctly-sized signature —
"well-formed" in every structural sense decode checks — decodes exactly as
cleanly as the genuine one and is not, and cannot be, detected by decode
alone. **(2)** Because the stored `evidence_bytes` is exactly what
`verify_*_equivocation_evidence` operates on, any reader — after a restart,
or on a different node — can **re-run the identical cryptographic
verification** against a freshly re-loaded historical validator set (§7) at
any later time; this is the *only* mechanism in this design that would
catch a well-formed-but-wrong signature, and it must be invoked explicitly.
As §6 states precisely, this re-verification is *available*, not
*automatic* on every replay — a consumer that must be sure of live
cryptographic validity (Phase 3 slashing, in particular) must call
`verify_*` itself; the record is designed to make that possible, not to
have already done it.

A dedicated test closes the loop: persist evidence on a real file-backed
store, close and reopen it, decode the row, and re-run
`verify_*_equivocation_evidence` against a freshly re-loaded historical
validator set.

### 10. Authorization boundary

No new externally reachable event family. All `submit_*` functions are
in-process node-core functions, the same authorization class as
`fast_path::prepare`/`apply` and `epoch_transition::propose_and_vote`/
`activate`: local-operator-invoked, with cryptographic validity against the
historical validator set serving as the only authorization needed —
exactly as an untrusted relay may hand `FastPathCertifier::try_form_certificate`
arbitrary candidate votes and rely entirely on its own verification.
`native-http` gains nothing from this DR. DR-0134 declares the formal
authorization classes and closed external boundary; its companion
implementation owns Phase 2 gate closure.

## Invariants

- Evidence is persisted only after every nested statement independently
  passes its family's `verify_vote`, and — for class (b) — after both
  preimages independently hash to their vote's own signed
  `locked_objects_digest`, against the validator set for the evidence's own
  claimed epoch, loaded via a chain-anchored historical lookup (§7), never
  the currently committed epoch.
- Two statements sharing an equal conflict key but an identical signable
  payload are never evidence, regardless of signature encoding.
- A conflicting pair normalizes into a byte-identical canonical envelope
  regardless of observation or argument order.
- The persisted evidence key is a deterministic function of the
  **normalized, signature-excluding** identity (§6); the identical logical
  conflict, submitted any number of times, in any signature encoding, by any
  caller, in any order, resolves to exactly one durable row.
- A stored row whose decoded content does not hash back to its own key's
  digest is tampered/corrupt and rejected outright; stored-signature-byte
  integrity is a property a consumer re-establishes by calling `verify_*`,
  not a property the idempotent submission path re-checks on every replay.
- No signature domain, canonical byte layout (beyond the explicit in-place
  `FastVote`/`FastCertificate` revision, §2), or verification rule of either
  family's certificate/vote types is otherwise changed.
- Class (b)'s conflict test is `(ObjectId, version)` equality only; the two
  matched entries' digests are never compared and never required equal —
  agreement and disagreement are both evidence, and neither is dropped from
  the retained preimages.
- One vote pair yields exactly one class (b) evidence record regardless of
  how many `(ObjectId, version)` pairs the two preimages overlap on; the
  header names only the smallest such pair for deterministic identity (§5),
  never one record per overlapping object — and both decode and verify
  reject a real-but-non-canonical overlap, not merely an absent one.
- `fast_path::prepare`'s exact-replay check and `fast_path::apply`'s
  independent re-derivation both bind `locked_objects_digest` against
  freshly observed `locked_objects`, exactly as they already bind
  `execution_effects_hash`/commitment (§2); a vote or certificate whose
  `locked_objects_digest` was never actually checked against real admission
  output can neither be replayed nor applied.
- A validator's `locked_objects_digest` is only as trustworthy as its own
  signature: this design proves a `FastVote` faithfully carries whatever
  digest its signer chose, never that the digest describes the validator's
  true locked set. A false digest cannot survive honest certificate
  formation or application, both of which independently re-derive the
  digest from real admission output rather than trusting a vote's claim
  (Unresolved risks item 6); it is not a claim of complete proof.
- Evidence submission performs no signing, fences no live mutable state,
  adds no lock, advances no nonce, and mutates no application or fee-escrow
  state. Its build-before-verification ordering discloses, to an
  already-privileged in-process caller only, whether a specific normalized
  identity is already recorded, but never persists anything unverified.

## Slice 3 design-acceptance criteria

1. `crates/consensus/src/fast_vote.rs` implements §2's in-place `0xD006`/
   `0xD008` revision exactly, including the renumbered `FastCertificate`
   fields and the threaded `locked_objects_digest` parameter through
   `cast_vote`/`try_form_certificate`/`verify_certificate`; every existing
   test/vector is regenerated (old bytes no longer decode).
2. `crates/consensus/src/equivocation.rs` implements `0xD00C`-`0xD00F`
   exactly as specified in §3/§5, including all seven new `ConsensusError`
   variants and real-Ed25519 build/verify tests for all three classes.
3. `crates/node-core/src/fast_path.rs`'s `cast_vote` call site (§2) computes
   and passes `locked_objects_digest`, sorting `admission.locked_objects` by
   `ObjectId` before encoding; prepare's exact-replay stored-vote check
   (`fast_path.rs:453-463`) additionally compares `vote.locked_objects_digest`
   against the digest re-derived from `existing.locked_objects`; apply's
   independent re-derivation (`fast_path.rs:807-823`) additionally computes
   `fresh_locked_objects_digest` from `admission.locked_objects` and requires
   it equal `certificate.locked_objects_digest` before proceeding — all per
   §2's "prepare/apply must extend their existing independent-binding
   checks" subsection.
4. `crates/node-core/src/equivocation.rs` implements all three `submit_*`
   functions exactly as specified in §§6-8, including normalized-identity
   dedup, the resolver/context binding check (with `protocol_version`
   passed explicitly to `load_historical_validator_set`, never inferred),
   the chain-anchored historical lookup, class (b)'s mandatory
   preimage-hashes-to-signed-digest check (§8, before either preimage is
   trusted for anything else, fail-closed on mismatch), and the real
   `DurableCommitOutcome`/`DurableCommitRejection` mapping.
5. `fast_path::load_validator_set`'s per-row decoder is factored into
   `decode_validator_set_row`, reused (not duplicated) by
   `load_historical_validator_set`.
6. `query::query_fastpath_equivocation_evidence` cross-checks decoded
   chain/epoch/validator/normalized-identity against its own selectors.
7. `0xD00E` decode/verify reject a `conflicting_object_id`/
   `conflicting_version` that is present in both preimages but is not the
   smallest shared `(ObjectId, version)` pair, and reject a preimage whose
   own `(chain_id, protocol_version, epoch)` disagrees with its attached
   vote's (§5).
8. The headline test proves class (b) evidence for a pre-transition epoch
   `e` still verifies, by historical key, after a real DR-0132 `e -> e+1`
   transition retires the offending validator.
9. `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features
   -- -D warnings`, `cargo test --workspace --all-targets --all-features`,
   and `./scripts/check-all.sh` all pass, plus a focused security review and
   a fresh tech-lead review.

Satisfying these did not by itself close the Phase 2 gate (DR-0134's
companion implementation later landed in PR #180) and does not authorize
testnet/production activation, bonding, slashing, or reward distribution.

## Test and evidence plan

**Headline** (real file-backed SQLite, `fast_path::tests::ValidatorFiles`/
`four_validators()`):
`class_b_object_conflict_evidence_for_a_retired_validator_still_verifies_by_historical_key_after_a_real_transition`

1. Genesis at epoch `e`. 2. One validator signs two `FastVote`s for two
*different* `tx_hash`es whose `locked_objects` share one identical
`(ObjectId, version)` pair, with equal digests at that pair (the ordinary
case; `build_*_matches_on_object_id_and_version_even_when_the_two_entries_digests_differ`
covers the differing-digest case separately) (direct
`FastPathCertifier::cast_vote` calls, since honest `fast_path::prepare`
cannot produce either). 3. Submit as class
(b) evidence with both preimages: `Recorded`. 4. Real `e -> e+1` transition
excluding the validator; close/reopen; restart-verify → `VerifiedExisting`.
5. `query_fastpath_equivocation_evidence`, decode, re-run
`verify_fast_vote_object_conflict_evidence` against the historical epoch-`e`
set (via `load_historical_validator_set`, not the live `e+1` set) —
succeeds. 6. Negative control: the same re-verification against the live
`e+1` set fails `UnknownValidator`.

**Supporting** (memory store unless noted): per-class `build_*`
conflict-key-mismatch and canonical-order-independence tests; class (b)
`build_*_rejects_equal_tx_hash`, `build_*_rejects_no_intersection`,
`build_*_matches_on_object_id_and_version_even_when_the_two_entries_digests_differ`,
`build_*_picks_the_smallest_object_id_version_pair_as_the_canonical_evidence_when_multiple_pairs_overlap_and_all_overlaps_remain_visible_in_the_preimages`;
class (a)/(c) `build_*_rejects_identical_payloads_with_different_signature_bytes`;
`decode_*_rejects_a_header_that_disagrees_with_a_nested_statement` per
class; `decode_fast_vote_object_conflict_evidence_rejects_an_unproven_intersection_claim`;
`decode_and_verify_fast_vote_object_conflict_evidence_reject_a_real_but_non_canonical_overlap_when_a_smaller_shared_pair_also_exists`
(the item-4 canonical-minimum test: two preimages sharing two or more
`(ObjectId, version)` pairs, header names a real but non-smallest one);
`decode_fast_vote_object_conflict_evidence_rejects_a_preimage_whose_own_context_disagrees_with_its_attached_vote`;
`submit_fast_vote_object_conflict_evidence_fails_closed_when_a_preimage_does_not_hash_to_its_votes_signed_locked_objects_digest`
(the item-1 negative test: a structurally valid, otherwise-conflicting pair
with one preimage swapped for an unrelated-but-well-formed one; must fail
at §8 step 4, before `load_historical_validator_set` or `verify_*` is ever
reached — proven by an instrumented double that would fail the test if
either were called); `fast_path_prepare_replay_rejects_a_stored_vote_whose_locked_objects_digest_disagrees_with_the_prepared_lock_set`;
`fast_path_apply_rejects_a_certificate_whose_locked_objects_digest_does_not_match_the_freshly_rederived_lock_set`
(§2's two new integration-point checks); consensus codec suite mirroring
`0xD006`-`0xD00B` for all revised/new frames;
`submit_*_is_idempotent_for_a_differently_signed_encoding_of_the_identical_pair`
(the case the normalized-identity fix exists for) per class;
`submit_*_resolves_a_concurrent_identical_submission_without_a_duplicate_row`
(real-thread race, `BarrierGatedActivateStore`-style); `submit_*_fails_closed_when_the_stored_row_disagrees_with_its_own_key_digest`;
`submit_*_fails_closed_when_no_historical_validator_set_exists_for_the_claimed_epoch`;
`submit_*_fails_closed_when_the_historical_row_digest_disagrees_with_the_restart_verified_transition_chain`
(direct tamper injection at the historical row, proving §7's anchor check);
`submit_*_never_reaches_verification_on_the_already_recorded_path`
(panicking verifier double); `query_fastpath_equivocation_evidence_rejects_a_selector_mismatch`;
`equivocation_evidence_survives_close_reopen_and_reverifies`; a genuine
multi-statement case documenting the accepted multi-record consequence
(Unresolved risks).

**Vectors:** `0xD00C`-`0xD00F` and the revised `0xD006`/`0xD008` into
`scripts/fast-vote-vectors.mjs`; `0x6429` into `scripts/fast-path-vectors.mjs`.
Dual Rust/JS, no Rust encoder invoked from JS, wired into
`scripts/check-all.sh`.

**Gate:** `cargo fmt --all`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, `cargo test --workspace --all-targets
--all-features`, `./scripts/check-all.sh`, plus fresh security and
tech-lead review.

## Unresolved risks

1. **No enumeration/aggregation query — but the primitive already exists.**
   `query_fastpath_equivocation_evidence` is a point lookup. Listing "all
   evidence for validator V at epoch E" is not implemented by this DR, but
   is directly supported without any new store capability: the key
   `.../equivocation/<chain><evidence_epoch><validator>...` is a valid
   prefix for `runtime::StateKeyScanner::scan_keys` (`StateKeyScan`/
   `StateKeyPage`, bounded at `MAX_STATE_SCAN_KEYS = 1_024`, already
   implemented by both `MemoryStateStore` and `SqliteStateStore`). Phase 3's
   enumeration need only add a `StateKeyScanner`-bounded query function, not
   a new index.
2. **Multiple conflicting vote pairs produce multiple independent records**
   (one per conflicting pair — e.g. a validator with three mutually
   conflicting statements yields up to three pairwise records), not one
   aggregate. This is unaffected by how many objects any single pair
   overlaps on: class (b) builds and stores exactly **one** canonical
   record per vote pair regardless of how many `(ObjectId, version)` pairs
   the two preimages share — the builder names only the smallest such pair
   in the evidence header (§5 step 5), while every other shared pair stays
   visible in the attached, fully-retained preimages rather than being
   evidenced separately. Every record is independently, fully verifiable;
   the pairwise (not object-wise) multiplicity is not space-optimal.
   Accepted; Phase 3 may aggregate at consumption time.
3. **Hash-suite schedule at the evidence epoch**, and at whichever epoch a
   given `locked_objects_digest`/normalized-identity digest is computed
   under, is untested by this design; the implementation must add a test
   for a suite switch landing exactly at the relevant epoch, mirroring
   DR-0132's own open item.
4. **No external ingress**; only in-process, local-operator-invoked
   submission exists. A future relay/watcher is deployment tooling, not
   part of this DR.
5. **Phase 3 consumption shape is undesigned** — what slashing does with
   evidence, retention/archival policy, and economic parameters are all
   left open.
6. **A malicious signer can sign a false `locked_objects_digest`** — nothing
   in `cast_vote` (or anywhere else in this design) can force a validator to
   hash its *actual* locked object set rather than an arbitrary Digest32 it
   simply signs. Such a vote is a completely valid `FastVote` by every check
   this DR or DR-0129/DR-0130 define; if the matching preimage were ever
   attached to it, class (b)'s §8-step-4 hash check would correctly reject
   it (the false digest cannot match the real preimage's hash), so this is
   not by itself a hole in class (b)'s own proof — but it does mean a
   validator can sign a vote whose locked-object claim is simply
   unfalsifiable evidence-wise (no correct preimage exists to attach, and no
   one is forced to produce one). **This DR does not, and cannot, claim
   complete proof of what a validator actually locked — only that a
   `FastVote` faithfully carries whatever `locked_objects_digest` its
   signer chose to sign.** The compensating control is not evidentiary but
   architectural, and already exists independently of this DR: honest
   certificate *formation* (`try_form_certificate`'s target-triple match,
   §2) and honest certificate *application* (apply's independent
   `fresh_locked_objects_digest` re-derivation, §2, added by this DR) both
   require the *locally, independently re-derived* digest from the node's
   own real admission output — a vote carrying a false digest can be
   validly signed and even relayed, but can never contribute to a
   certificate that a different, honest node's own re-derivation accepts,
   because that node computes the digest itself rather than trusting the
   vote's claim. A false digest therefore cannot make a bad state apply; it
   can only, at most, prevent that one vote from ever being usable in a
   real quorum — a liveness cost to the dishonest signer alone, not a
   safety gap for anyone else.

## Consequences / Deferred

- Implements Slice 3 in `crates/consensus/src/fast_vote.rs` (in-place
  revision), `crates/consensus/src/equivocation.rs`, and
  `crates/node-core/src/equivocation.rs`, with the supporting consensus,
  fast-path, query, export, vector, and roadmap changes listed in the Status
  and completion evidence above.
- `locked_objects_digest` **is** needed, reversing the original design's
  finding — see §1 class (b) and the Revision note above.
- Reused, not reinvented (once implemented): `FastPathCertifier::verify_vote`/
  `EpochTransitionCertifier::verify_vote`, `encode_fast_vote_payload`/
  `encode_epoch_transition_vote_payload`, `objects::encode_object_ref`/
  `decode_object_ref`, `fast_path::FastPathEd25519Verifier`,
  `fastpath_validator_set_key`/`fastpath_epoch_transition_key`,
  `HashSuiteResolver::hash_for_purpose`, `epoch_transition::activate`'s real
  `DurableCommitOutcome`/`DurableCommitRejection` mapping, and
  `fast_path::tests::ValidatorFiles`/`four_validators()`.
- No bonding, slashing, penalty, reward, or distribution mechanism of any
  kind is implemented by this DR.
- DR-0134 declares Slice 4's authorization classes and still-closed external
  ingress boundary; Phase 2 closure remains conditional on its companion code
  and reviews landing.
- `EpochTransitionVote`/`EpochTransitionCertificate` (`0xD009`-`0xD00B`),
  the `FastPathEpochRecord`/`FastPathLockRecord` fencing model, and the
  epoch-transition activation/reclamation design are all unchanged by this
  DR. `FastVote`/`FastCertificate` (`0xD006`, `0xD008`) are changed in place
  as specified in §2 — DR-0129/DR-0130 are updated with narrow pointers to
  this fact, not rewritten.
- Bond-linked slashing and deterministic fee-escrow distribution remain
  Phase 3, unaffected by this DR.
