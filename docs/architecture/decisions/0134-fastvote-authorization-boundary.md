# DR-0134: FastVote authorization boundary (phase 2, slice 4)

## Status

Accepted and implemented, 2026-09-22. The companion code, tests, complete
repository gate, Bugbot review, focused security review, and fresh tech-lead
review landed in PR #180. Slice 4 closes FastVote Phase 2 while preserving the
closed external boundary.

FastVote remains incomplete until Phase 3 implements bond-linked slashing and
deterministic fee-escrow distribution to the final certificate signer set.
Nothing here authorizes testnet or production activation of a new ingress.

## Context

DR-0131 fixed the general mutation fence and required Slice 4 to classify the
Phase 2 operations. DR-0132 implemented epoch transition but left its C7
ingress correction to this slice: static `NodeConfig.epoch` is not authority
after a transition. DR-0133 implemented local equivocation-evidence recording.
All three deliberately added no externally reachable FastVote surface.

The phrases "local-operator-authorized" and "validator-authenticated" are not
competing variants. They describe two different boundaries: who may invoke an
in-process node operation, and which cryptographic proof authorizes its
protocol effect.

## Decision

### Authorization matrix

Every operation below is local-operator-invoked and externally closed. A local
operator invocation alone never supplies validator authority.

| Operation | Invocation authority | Validator proof required for its signing or mutating branch | External ingress |
| --- | --- | --- | --- |
| `fast_path::prepare` | Local operator | Current-set signer; the paid intent is independently sender-authenticated. | Closed |
| `fast_path::apply` | Local operator | Current-set quorum `FastCertificate`, bound to the local prepared record and independently re-derived execution. | Closed |
| `epoch_transition::propose_and_vote` | Local operator | Outgoing-set signer. The operator-supplied next set has no authority by itself. | Closed |
| `epoch_transition::activate` | Local operator | Outgoing-set quorum `EpochTransitionCertificate` over the locally re-derived activation set. | Closed |
| `equivocation::submit_fast_vote_equivocation_evidence` | Local operator | Historical-evidence proof: both conflicting votes verify against the chain-anchored validator set for their epoch. | Closed |
| `equivocation::submit_fast_vote_object_conflict_evidence` | Local operator | Historical-evidence proof: both votes verify against the chain-anchored validator set, and each preimage hashes to its vote's signed `locked_objects_digest`. | Closed |
| `equivocation::submit_epoch_transition_equivocation_evidence` | Local operator | Historical-evidence proof: both conflicting transition votes verify against the chain-anchored outgoing set. | Closed |

`propose_and_vote` persists nothing, but it belongs in this matrix because it
emits a validator-authenticated protocol statement. The evidence submitters do
not need to be validators: historical validator signatures prove the evidence;
the trusted local operator chooses whether to invoke the recording operation.

An exact replay branch may return a previously verified receipt, activation,
or evidence row without re-verifying newly supplied proof, provided it performs
no mutation and strictly matches the durable identity. The proof requirement
above governs the branch that first signs or changes state.

Direct paid execution, local execution, local publication, and authenticated
`SubmitTransaction` retain their existing sender/publisher authentication.
Phase 2 adds epoch and lock fencing to those families; it does not turn them
into validator-authorized operations. Genesis installation is signed bootstrap,
not a Phase 2 operation, and queries are read-only.

### Closed external boundary

Slice 4 adds no canonical frame, type ID, signature domain, `NodeEventKind`,
HTTP route, CLI command, Rust-client transport method, relay, or watcher. It
does not repurpose `ReceiveVote`, `ReceiveCertificate`,
`ReceiveConsensusMessage`, or `ApplyValidatorSetChange`; native HTTP continues
to reject every non-`SubmitTransaction` event family through DR-0099's
exhaustive fail-closed boundary.

No existing canonical ID or byte encoding changes in this slice. In
particular, the checked-in fast-vote and fast-path vector outputs remain
byte-for-byte unchanged.

No synthetic `LocalOperatorAuthorization` token is introduced. Without an
operator identity and authenticator, a publicly constructible marker would be
ceremony rather than authority. Local-operator trust remains an embedding and
deployment boundary; validator authorization remains cryptographically
enforced inside the seven operations above.

### Committed epoch at existing ingress (DR-0132 C7)

The affected native surfaces must derive the live epoch from the durable
`FastPathEpochRecord`, via `query::query_committed_epoch_state`, after resolving
trusted storage authority. They are authenticated `SubmitTransaction` context
validation; `GET /v1/context`; `GET /v1/senders/{sender}/next-nonce`; public
paid execution's expected context, base-profile-4 execution policy, and paid
fee policy; and the paid-policy query. Static `NodeConfig.epoch` remains
bootstrap/composition input and is not live post-transition authority. The
profile-4 and fee-policy rows must match the committed context exactly; these
surfaces must not reuse their epoch-`e` rows after activation to `e+1`.

For `SubmitTransaction`, deriving live epoch does not move cryptographic
admission behind storage. The route first authenticates the bounded canonical
transaction, sender binding, signature, and outer/inner signed-epoch
consistency using trusted chain/protocol/profile configuration. It allocates
operational identity and reads the epoch singleton only after that succeeds,
then requires the authenticated epoch to equal the committed current epoch
before application planning or transition. Request epoch is therefore never
live authority, while invalid signatures cannot force the epoch read.

This does not reinterpret local publication's `policy.context.epoch()`.
DR-0131 defines that field as a historical code/policy-version selector, not a
claim about the live epoch; local publication preserves that selector while
retaining its current-epoch CAS fence and epoch-disjoint sender-nonce lock.
Nor does activation invent profile-2 or profile-3 local-execution rows at
`e+1`. Those local profiles are not dynamically upgraded: their old-epoch
intents remain unavailable because the core current-epoch fence rejects them.

The preliminary epoch read is not a mutation fence. Every mutation retains the
existing same-commit `FastPathEpochRecord` CAS assertion. If activation races
between ingress resolution and commit, the old-epoch mutation fails closed and
the caller retries against the new committed epoch. The live epoch must not be
cached as authorization.

## Completion criteria

Slice 4, and therefore Phase 2, closes only when all of the following are true:

1. Code contains one closed `FastVotePhase2Operation` inventory with exactly
   the seven operations in the matrix. A wildcard-free exhaustive match maps
   every operation to its exact invocation, validator-proof, and ingress
   policy, and an exact matrix test asserts all seven rows. This classification
   is typed metadata, not an operator credential or new externally callable
   API.
2. Authenticated `SubmitTransaction`, `/v1/context`, next-nonce, public paid
   execution's expected context/base-profile-4 policy/fee policy, and the
   paid-policy query use the committed epoch as specified above, while every
   mutation retains its CAS fence. Local publication preserves its historical
   selector, and no profile-2 or profile-3 `e+1` row is synthesized. Invalid
   transaction and paid-execution bytes or signatures reject before identity,
   clock, or storage; only an authenticated signed epoch reaches the
   committed-epoch equality check. Paid execution then performs exact receipt
   reconciliation before current policy, nonce, code, or object reads.
3. A real `e -> e+1` test proves context, next-nonce, paid-policy,
   authenticated submission, and public paid execution use `e+1`; the paid
   path uses the activated base-profile-4 and fee-policy rows, and stale-`e`
   input is rejected. An absent or mismatched `e+1` profile-4 or fee-policy row
   makes the applicable paid-policy query and public paid execution unavailable
   without fallback to epoch `e`. This test does not require profile-2 or
   profile-3 local execution to acquire an invented `e+1` policy.
4. A transition racing ingress resolution cannot admit an old-epoch mutation.
5. Every non-`SubmitTransaction` `NodeEventKind` remains rejected on every
   native router family, and no FastVote-specific route, CLI, or client surface
   exists.
6. The existing unknown-signer, insufficient-quorum, wrong-epoch, and invalid
   historical-evidence tests continue to prove the matrix's validator side.
7. No canonical ID or byte encoding changes, and the exact outputs of
   `scripts/fast-vote-vectors.mjs` and `scripts/fast-path-vectors.mjs` remain
   unchanged.
8. The complete repository gate and fresh focused security and tech-lead
   reviews pass on the integrated code and documentation.

## Consequences and deferred work

- Phase 2 completion declares validator lifecycle, fencing, transition,
  evidence, and authorization boundaries implemented. It does not expose a
  transport for them.
- External FastVote relay/event-family admission requires a separate decision,
  family-specific authentication and authorization, bounded wire contract,
  adversarial tests, and focused delta audit.
- Bonding, slashing, evidence consumption/retention policy, and deterministic
  signer fee/reward distribution remain Phase 3.
- Testnet or production launch remains a separate deployment decision and must
  not be inferred from Phase 2 completion.
