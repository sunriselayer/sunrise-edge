# DR-0178: Closed conditional-readiness authority and retention

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted exact readiness-only implementation contract after independent
design review of [DR-0177](0177-conditional-readiness-and-ordered-seal.md).
The authorized Codex substitute returned APPROVE on the closed specification;
Opus was unavailable. This record does not
authorize Seal, activation or active serving. Implementation and validation
status belong only in [TODO.md](../../../TODO.md).

## Configuration and key authority

The pinned GenesisManifest does not contain a hash-suite schedule. Its genesis
digest is not authentication of an operator's future schedule. Readiness binds
the separate, complete locally trusted resolver schedule. A peer, candidate or
certificate cannot supply configuration authority. Every producer and verifier
recomputes this commitment from its own resolver; different future schedules
cannot combine votes, even when their outgoing suites agree.

Expose a read-only `HashSuiteResolver::schedules()` slice. Require 1..64 entries
and validate with the existing `HashSuiteScheduleConfig`: activation begins at
zero, epochs strictly increase, and suite IDs are nonzero and unique. Reuse
`protocol_upgrades::encode_hash_suite_schedule` (outer 0xC003/v1, entries
0xC002/v1). Hash those bytes with NodeEvent at outgoing epoch e. The semantic
subject and slot identity also use NodeEvent at e. The canonical successor set
is the existing ValidatorSet for checked adjacent epoch e+1; its digest uses
ValidatorSet at e+1, including that epoch's certificate hash algorithm. An
exposed certificate digest uses Certificate at e. Later Seal and activation
must match this configuration commitment; this feature does not authorize them.

Require 1..256 distinct registered IDs and public keys, Ed25519 only, positive
weights and checked total power. Every exact 32-byte successor key must pass
the existing `validate_ed25519_owner_address(CanonicalPrimeOrder)` primitive:
canonical recompression, non-identity and prime-order subgroup. This is new-set
admissibility, not a change to historical ZIP-215 signature verification. The
already pinned [curve25519-dalek primitives](https://docs.rs/curve25519-dalek/4.1.3/curve25519_dalek/edwards/struct.EdwardsPoint.html)
support the distinction; do not replace signature verification with a new
cryptographic implementation.

A readiness-only concrete key adapter owns an Ed25519 SigningKey and a
registered ValidatorId. It derives the actual VerificationKey from that same
private key. Core compares ID, scheme and actual key with the successor entry
before signing, and verifies the resulting signature under the registered key
before retention. Do not broaden ConsensusSigner or accept a caller-asserted
public-key/private-signer pair as key possession. Its narrow signing operation
does not confer ordinary/live signing authority.

## Public frames and purpose

The following new closed frames use encoding version 1. Reject unexpected
fields and invalid lengths before copies; exact decode/re-encode equality is
required. The namespace sweep found no existing allocation of these IDs, the
message label or the protected table. Existing schedule and ValidatorSet
encoders reuse 0xC001/0xC002 with different owning layouts/purposes; this record
does not change them or claim global collision freedom.

| Frame | Fields in canonical order |
| --- | --- |
| 0xD040 subject | 1 encoded chain, 2 protocol u32, 3 outgoing epoch u64, 4 genesis Digest32, 5 domain bytes, 6 outgoing-set Digest32, 7 semantic-cut Digest32, 8 checked next epoch u64, 9 next-set Digest32, 10 complete-schedule Digest32 |
| 0xD041 signed payload | 1 exact subject frame, 2 registered signer ID bytes, 3 scheme u16 |
| 0xD042 vote | 1 exact payload frame, 2 exact 64-byte signature |
| 0xD043 certificate | 1 subject frame, 2 existing canonical successor-set frame, 3 count u16, fields 4 onward strictly signer-sorted votes |

Signature framing is the existing 0x2001 frame, outgoing epoch and distinct
`conditional-readiness-v1` label. It signs the full canonical D041 payload,
including signer identity/scheme. Maximums are: 128-byte chain, 64 KiB successor
set, 16 KiB subject, 4 KiB vote, 1 MiB certificate and 256 votes. Certificate
assembly rejects duplicate signers rather than counting their weight twice.
Verify every signature and all subject/set/schedule identities against local
configuration; require strictly greater than two-thirds of the checked
successor power. A syntactically valid certificate is not proof of local
business completeness or permission to activate.

The public subject excludes package/raw-plan variants, local tokens/fences and
future Seal. Equivalent verifying proof subsets share the same subject. A
corrected eligible set may produce another identity before Seal. There is no
epoch singleton, global candidate cap or global sign-once assertion.

## Private producer

Independently replay the saved authenticated cut into the existing opaque
VerifiedImportPlan. No constructor accepts decoded rows, supplied equality
reports or a completed flag. Require the exact CompleteInactive binding and
terminal progress, and compare the complete destination inventory and referenced
immutable bodies with the private plan under a fresh local snapshot token.

Derive eligibility from that same reconstructed post-drain state through the
existing bond/resource predicate. Bracket eligibility and retained-slot reads
with the same token, not a replacement newer observation. Before a signature is
exposed, protected retention atomically rechecks that token, local authority,
binding and progress. A race may compute an unexposed signature but cannot
return it or admit work. Immutable body content remains outside the SQL token;
the full private closure comparison is mandatory, not replaced by the token.

Retained A/B/C and incoming E each use separate inactive staging. Neither
FreshImport nor Importing signs. CompleteInactive still refuses fresh business,
ordinary/cached live votes, ordered advancement, bootstrap and activation.
Exact original business replay remains receipt-first and execution-free.

Initial E bonding is a real prerequisite: the old Deposit only handles an
existing Exited bond, and genesis initializes committee bonds Active. No
positive acceptance may seed an E bond or manufacture an Exited predecessor.
Implement and independently verify first registration before claiming the
genuine A/B/C/E readiness gate; this record is not that registration authority.

## Protected exact-slot storage contract

Introduce an optional `ReadinessRetentionRepository: InactiveImportRepository`
with required methods, not default support or a common-store bypass:

- `read_ready_slot_at(operation, domain, binding, progress, fresh_token, slot)`
  returns Absent, Present with the exact typed record, or a known Tombstoned
  observation. Stale token/schema/fence/lifecycle failures return typed errors.
- `retain_ready_slot(operation, domain, binding, progress, fresh_token,
  expected_observation, record)` returns the existing DurableCommitOutcome.
  Exact Present comparison is nonmutating; an absent-slot insertion and local
  mutation-sequence advance commit together.

Both methods atomically require CompleteInactive, exact immutable binding and
completed progress, the current token's namespace/domain/fence/sequence and
operation domain/fence/deadline. They inspect one slot, not all past candidates.
The storage-only seam cannot authenticate a vote or create a core capability.

| Protected frame | Fields in canonical order |
| --- | --- |
| 0x64D0 slot | 1 semantic subject Digest32, 2 signer ID bytes |
| 0x64D2 creation observation | 1 exact local namespace bytes, 2 domain bytes, 3 positive writer fence u64, 4 mutation sequence u64 |
| 0x64D1 record | 1 slot frame, 2 exact ImportBinding frame, 3 complete ImportProgress frame, 4 creation-observation frame, 5 exact bounded vote bytes |

The slot is at most 256 bytes, namespace at most 256 bytes, vote at most 4 KiB,
and entire record at most 16 KiB. Decode closed fields and re-encode exactly.
Core verifies the vote signature and its linkage to the slot, subject and signer;
storage treats vote bytes only as bounded content. A new insertion requires
record.creation_token == fresh_token and records pre-insertion sequence s;
insertion advances the covered sequence to s+1. Exact retained replay uses a
fresh token but keeps that original creation observation. Never compare the
old creation token to the current token as a retry prerequisite.
Present-record verification requires creation namespace/domain equal to the
current destination, a positive creation fence no greater than the current
monotonic fence, and creation sequence strictly below the current covered
sequence. These are local linkage checks, not proof against a consistent
whole-database rollback or a recovered unknown old observation.

Memory owns a separate protected map. Shared SQL owns
`durable_conditional_readiness`, keyed by the exact canonical slot, with
status 1 Present or 2 Tombstoned and bounded record bytes. Read status/type/
length before fetching a record. Validate exact schema identity on create/open.
The key and every lookup are scoped by the engine's exact namespace/domain;
independent fresh destinations must not collide in a global semantic-slot map.
Missing protected metadata is corruption, never absence or a lazy repair.
Use new shared SQL metadata v4 and native SQLite schema v3. Initialized older
files are unsupported; no automatic migration, reset or repair. PostgreSQL's
ordinary-only profile uses its next schema identity with fresh selected PG
acceptance; no PG import capability is introduced. SQLite opt-in import facade
implements the seam; ordinary/DO/PG hosts gain no readiness interface by default.

Malformed or conflicting present records, known tombstones, stale observations
or binding mismatches refuse without overwrite. No reset/delete/pruning API,
tombstone management, State-prefix exemption or activation conversion exists.
The protected table is outside the business inventory by its exact schema owner.

## Reply loss and validation

No newly computed signature is exposed on an indeterminate acknowledgement.
Fresh fenced full re-verification and exact-slot reconciliation must observe
the exact landed record before returning it. If the write did not land, the
call refuses; a subsequent independently verified call may retry. Present
valid replay returns exact original bytes without a new signature.

Absence is no cached record, not a virgin key or preservation of an unknown
historical observation. Fresh complete re-verification may recreate identical
deterministic public vote bytes. Certificates still count one signer once.
Ordinary CAS cannot detect a mutually consistent whole-database rollback
without an independent anchor; no extra anchoring guarantee is claimed. None
of this relaxes unique ordered/post-Seal transition vote history.

Required evidence includes independent stable/adversarial vectors, all
registered-key/scheme/weight/adjacency/schedule failures before signing, genuine
post-drain A/B/C/E SQLite staging exceeding one import batch, real initial E
deposit, equivalent proof carriers and corrected eligible sets, full original
history/body equality and execution-free replay. Prove restart/non-signing
retained replay, landed/unlanded reply loss, absent-cache recreation, corrupt
present/mandatory metadata, known tombstones and stale token/fence refusal.
Full npm ci/check-all, exact-head independent review, required CI and selected
PG acceptance for schema changes remain mandatory. These are capability gates,
not Delivery 3 completion, an independent security audit or network startup.
