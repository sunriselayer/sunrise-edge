# DR-0129: owned-object FastVote/FastCertificate canonical library (phase 0)

## Status

Accepted for the scope below, compiled, tested, and vector-checked in this
session. See "Verification" for the exact commands run and their results.

## Context

TODO.md's delivery roadmap names "FastVote and multi-validator integration"
as the next deliverable after the generic-contract and asset-creation gates.
The design brief (TODO.md's `# 24 Fast Path`, `# 25 Vote`, `# 26 Certificate`
sections) and `docs/architecture/core-protocol.md` section 11/12 describe an
owned-object fast path distinct from the shared-object BFT consensus that
`crates/consensus` already implements (`ChainedHotStuff`, `ConsensusVote`,
`QuorumCertificate`, type IDs `0xD001`-`0xD005`). Those two designs are easy
to conflate because they live in the same crate and share vocabulary
("vote", "certificate", "quorum"); this decision record exists specifically
to keep them distinct:

* **Owned-object fast path (this DR).** A validator signs a `FastVote`
  attesting that it would (or did) apply one specific transaction with one
  specific execution-effects hash, over objects it can lock exclusively by
  version because they are owned (not shared/conflicting). A
  `FastCertificate` is a quorum of such votes for the same pair. There is no
  proposal, view, height, leader, or persisted chain state — certification is
  a stateless per-transaction aggregation, not a BFT state machine.
* **Shared-object consensus ingress and validator-set changes (deferred).**
  Wiring `ReceiveVote`/`ReceiveCertificate`/`ReceiveConsensusMessage`/
  `ApplyValidatorSetChange` into `node-core`'s authenticated event dispatch,
  HotStuff proposal/view/commit activation, and any governance-driven
  validator-set change remain out of scope. `ChainedHotStuff`,
  `ConsensusVote`, and `QuorumCertificate` are unchanged by this DR.
* **Static permissioned epoch.** The validator set used to build a
  `FastPathCertifier` is an immutable `validator_set::ValidatorSet` snapshot
  for one epoch, matching the genesis permissioned model (TODO.md `# 30`).
  Validator-set rotation, bonding, and slashing are unchanged and out of
  scope.

## Scope: phase 0 only

This decision deliberately stops at a reusable, inert consensus library. It
does not add a `node-core` dependency or API, persistent locks, effects
application, certificate publication, or network ingress. Those operations
must be designed together so authenticated execution, object authority,
fees, crash recovery, and idempotent publication cannot be bypassed by an
intermediate API.

### `FastVote`/`FastCertificate` canonical types, codec, and aggregation (`crates/consensus`)

New module `crates/consensus/src/fast_vote.rs`, re-exported from the crate
root, using the next unallocated type IDs in the crate's `0xD0xx` namespace
(`0xD001`-`0xD005` already belong to `ChainedHotStuff`'s proposal/vote/
certificate/parameters types and are untouched):

| Type ID | Frame |
| --- | --- |
| `0xD006` | `FastVote` signable payload |
| `0xD007` | `FastVote` (payload + signature) |
| `0xD008` | `FastCertificate` |

Signature domain: `SignatureMessageType::new("fast-path-vote-v1")`, a new,
distinct message type from `ChainedHotStuff`'s `"shared-consensus-proposal-v1"`/
`"shared-consensus-vote-v1"`, so a `FastVote` signature can never be replayed
as a shared-consensus vote or vice versa (exercised directly by a co-located
test that real-signs the identical canonical payload under `ChainedHotStuff`'s
own vote domain and confirms `verify_vote` rejects it).

`FastVote` binds `chain_id`, `protocol_version`, `epoch`, `tx_hash`,
`execution_effects_hash`, `validator`, and `signature_scheme`. `FastCertificate`
binds the same header fields plus a canonically validator-ID-ordered,
deduplicated `Vec<FastVote>`.

`FastPathCertifier` is a stateless, `Clone`, epoch-scoped signer/verifier
bound to one `(chain_id, protocol_version, epoch, ValidatorSet)`:

* `cast_vote` signs one `FastVote` for a caller-supplied `(tx_hash,
  execution_effects_hash)`.
* `verify_vote` validates one vote's context, registered scheme, and
  signature.
* `try_form_certificate` deterministically forms the **minimal** canonically
  ordered quorum: candidate votes are deduplicated by validator, verified,
  then walked in ascending `ValidatorId` order accumulating voting power
  until the strict `ValidatorSet::quorum_threshold` is met, at which point
  exactly that prefix becomes the certificate. Because the walk order is
  always canonical (never the caller's arrival order), two callers who
  observe the same valid vote set in different orders produce byte-identical
  certificates. The result is the shortest prefix of the canonical validator
  order that reaches quorum; with unequal voting power it is not necessarily
  the globally smallest-cardinality quorum subset.

  `try_form_certificate` applies exactly one narrow, explicit, documented
  exclusion policy and otherwise fails closed.
  A candidate vote addressed to a different `(tx_hash,
  execution_effects_hash)` pair or a different `(chain_id, protocol_version,
  epoch)` is unrelated relay noise and is excluded without being verified at
  all. A vote that *is* addressed to this exact pair/context but fails
  `verify_vote` with `UnknownValidator`, `SignatureSchemeMismatch`,
  `InvalidSignatureLength`, `InvalidSignature`, or `ContextMismatch` is
  itself malformed or cryptographically invalid — not a sign of
  infrastructure failure — and is excluded under this same policy. Any other
  `verify_vote` error, in particular `ConsensusError::Authenticator` (the
  caller's own `ConsensusVerifier` adapter failing, as opposed to a
  signature it actually checked and rejected), is returned immediately as an
  `Err` from `try_form_certificate` rather than silently excluded. Both
  branches — an infrastructure error propagating, and a genuinely invalid
  signature being excluded so quorum still forms from the remaining votes —
  are covered by co-located tests. If one validator supplies multiple valid
  signatures for the same payload, the lexicographically smallest signature
  is retained, preserving arrival-order independence for signature schemes
  with multiple valid representations.
* `verify_certificate` checks context, strict canonical vote order
  (rejecting both out-of-order and duplicate-validator vote sequences), per-vote
  signatures, and quorum power. It does **not** require minimality: an
  "alternate" valid quorum-carrying vote subset for the same header also
  verifies, by design.

`encode_fast_vote`/`decode_fast_vote`/`encode_fast_certificate`/
`decode_fast_certificate` follow this workspace's strict canonical-decode
convention: exact field sets, bounded nested collections
(`MAX_FAST_CERTIFICATE_VOTES = 10_000`, matching `validator_set`'s own
`MAX_VALIDATORS`), and byte-exact re-encoding of the decoded value.

`ConsensusError` gained two additive variants, `CanonicalDecoding` and
`ProtocolType`, needed only by the new decode path; every existing variant,
every `ChainedHotStuff`/`ConsensusVote`/`QuorumCertificate` encoding, and the
existing `consensus_parameter_encoding_is_stable` vector are unchanged.

### Test coverage

`crates/consensus/src/fast_vote.rs` has 32 co-located unit tests using a real
Ed25519 signer/verifier (`ed25519-zebra`, the same pinned dependency
`crypto::Ed25519Verifier` uses), covering: real sign/verify round trip; wrong
chain/protocol-version/epoch/validator-set-member/signature-scheme/signature
rejection; below-quorum non-formation; deterministic minimal-quorum
certificate formation independent of vote arrival order, including duplicate
valid signature representations; an alternate valid quorum subset also
verifying; non-canonical and duplicate certificate vote-order rejection at
both decode and verification; precise rejection of a wrong-length validator
identifier; strict decode rejection of wrong type id, wrong version, an extra
field, a missing field, a declared vote count that disagrees with the fields
present, and a declared count over `MAX_FAST_CERTIFICATE_VOTES`;
cross-family signature-domain separation from `ChainedHotStuff`; and the two
`try_form_certificate` fail-closed/exclusion-policy cases described above.

Three pinned literal Rust hex vectors cover type IDs `0xD006`-`0xD008`
(`fast_vote_payload_encoding_vector_0xd006_is_stable`,
`fast_vote_encoding_vector_0xd007_is_stable`,
`fast_certificate_encoding_vector_0xd008_is_stable`), and
`scripts/fast-vote-vectors.mjs` independently reconstructs the same three
frames byte-for-byte from scratch (no Rust encoder invoked) and asserts
identical hex, following the existing `scripts/*-vectors.mjs` convention;
it is wired into `scripts/check-all.sh`.

## Deferred, unresolved, not designed by this DR

* Validator-side execution and per-object locking for owned objects.
* Atomic certificate publication (durable records, idempotent replay).
* `node-core` (or any other) wiring of `cast_fast_vote`/`apply_fast_certificate`
  or equivalents — no such functions were introduced by this phase-0
  revision; DR-0130 later introduced the local Phase 1 equivalents.
* Any HTTP/CLI ingress for votes or certificates.
* HotStuff wiring, validator-set changes, slashing, fee distribution.
* Multi-validator paid Standard Asset end-to-end evidence.

None of the above was implemented by DR-0129's phase-0 code. DR-0130 now
implements the local validator-side execution, locking, durable certificate
publication, and multi-validator paid Standard Asset evidence as Phase 1;
external ingress, validator lifecycle, slashing, and fee distribution remain
open in `TODO.md`.

## Phase roadmap

This DR is phase 0 of a four-phase FastVote delivery plan tracked in
`TODO.md`'s delivery roadmap (item 5) and
`docs/architecture/core-protocol.md` section 11:

* **Phase 0 (this DR).** Canonical `FastVote`/`FastCertificate` types, wire
  codec, and signature/quorum aggregation library only. Done.
* **Phase 1.** One coherent certified-execution slice: signed paid intent
  authentication, exact replay reconciliation, nonce/policy/object/ABI
  validation, deterministic paid execution, a canonical commitment over the
  complete staged commit, durable exclusive sender-authorized owned-object
  version locks, byte-stable `FastVote`, quorum certificate verification, and
  atomic certificate apply. Implemented under
  [DR-0130](0130-owned-object-certified-execution.md); it was deliberately
  not part of this phase-0 DR.
* **Phase 2.** Validator lifecycle: epoch/validator-set transitions,
  retired/wrong-epoch rejection, relay/event-family authorization, explicit
  equivocation evidence, multi-validator fault/restart tests. Not yet
  designed.
* **Phase 3.** Economics/security completion: bond-linked slashing execution
  and deterministic transaction-fee escrow distribution to the final
  certificate signer set. Not yet designed.

FastVote is complete only after phase 3. A testnet may launch after phase 1,
but that launch is not itself FastVote completion.

**2026-09-25 clarification:** the preceding phase-0 planning sentence is not
authority to activate protocol v3 on an externally reachable multi-validator
network. The later hard activation constraints in `TODO.md` and
`docs/architecture/core-protocol.md` still apply. Phase 1 alone supports a
closed local developer rehearsal; an earlier limited multi-validator testnet
would require an explicit, independently reviewed non-production activation
profile.

## Verification

Run in this session, on the code in this revision:

```bash
cargo fmt --all
cargo test -p consensus
node scripts/fast-vote-vectors.mjs
cargo clippy -p consensus --all-targets --all-features
```

All 4 passed. `cargo test -p consensus` includes the 32 tests described
above (plus this crate's pre-existing `ChainedHotStuff`/canonical-encoding
adapters/cloudflare-workers && ./scripts/check-all.sh`) also passed. The merge
gate additionally requires a fresh focused security review and tech-lead
approval of the final diff; any subsequent code change invalidates those
reviews and requires them to be refreshed.

## Consequences

* `crates/consensus` now has two independent, non-interfering message
  families: shared-object `ChainedHotStuff` (unchanged) and owned-object
  `FastPathCertifier` (new). Neither's canonical bytes or signature domain
  can be confused with the other's.
* `node-core` is **unchanged** by this DR: no new dependency, no new module,
  and no new public API.
* This is a self-contained types/codec/aggregation library with no callers
  anywhere in the workspace yet, consistent with the existing hard
  activation constraint that no externally reachable event family beyond
  `SubmitTransaction` may go live before its own authenticated/authorized
  ingress is implemented and reviewed. The next slice (validator-side
  execution, locking, atomic publication, and ingress) requires a separate
  decision.
* **[DR-0133](0133-fastvote-equivocation-evidence.md) (2026-09-22, design
  only, not implemented) extends `FastVote`/`FastCertificate`'s (`0xD006`,
  `0xD008`) canonical v1 payload in place**, adding a `locked_objects_digest`
  field needed to evidence a validator locking the same object version
  across two different transactions. This repository is unreleased: there is
  no `0xD006`v2 or compatibility decoder: the version-1 wire layout simply
  changes, exactly as DR-0131 later redefined `0x641B` in place. Pre-DR-0133
  encoded bytes, including this DR's own pinned vectors, no longer decode
  once that revision is implemented.
