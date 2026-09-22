# DR-0134: FastVote authorization boundary (phase 2, slice 4)

## Status

Accepted, 2026-09-22. This decision closes the design of FastVote Phase 2
Slice 4. Slice 4 and Phase 2 are implemented only when the companion code,
tests, complete repository gate, and fresh security and tech-lead reviews land
with this decision. This documentation change alone does not make that claim.

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

No synthetic `LocalOperatorAuthorization` token is introduced. Without an
operator identity and authenticator, a publicly constructible marker would be
ceremony rather than authority. Local-operator trust remains an embedding and
deployment boundary; validator authorization remains cryptographically
enforced inside the seven operations above.

### Committed epoch at existing ingress (DR-0132 C7)

Every existing native surface that validates, selects, or reports a live epoch
must derive it from the durable `FastPathEpochRecord`, via
`query::query_committed_epoch_state`, after resolving trusted storage authority.
Static `NodeConfig.epoch` remains bootstrap/composition input and is not live
post-transition authority.

This applies at least to authenticated `SubmitTransaction` context validation,
`GET /v1/context`, `GET /v1/senders/{sender}/next-nonce`, paid-execution expected
context, and the paid-fee-policy query. An epoch-scoped policy must be loaded or
deterministically derived for that committed context and strictly checked
against durable state; an adapter must not silently reuse a prior epoch's
in-memory policy. An opt-in local profile with no policy at the committed epoch
is unavailable, not silently reinterpreted.

The preliminary epoch read is not a mutation fence. Every mutation retains the
existing same-commit `FastPathEpochRecord` CAS assertion. If activation races
between ingress resolution and commit, the old-epoch mutation fails closed and
the caller retries against the new committed epoch. The live epoch must not be
cached as authorization.

## Completion criteria

Slice 4, and therefore Phase 2, closes only when all of the following are true:

1. Existing structured native ingress and epoch-sensitive queries use the
   committed epoch as specified above, while mutation-time CAS fencing remains.
2. A real `e -> e+1` test proves context, next-nonce, paid-policy, and
   authenticated submission behavior follows `e+1`, while stale `e` input
   fails closed.
3. A transition racing ingress resolution cannot admit an old-epoch mutation.
4. Every non-`SubmitTransaction` `NodeEventKind` remains rejected on every
   native router family, and no FastVote-specific route, CLI, or client surface
   exists.
5. The existing unknown-signer, insufficient-quorum, wrong-epoch, and invalid
   historical-evidence tests continue to prove the matrix's validator side.
6. The complete repository gate and fresh focused security and tech-lead
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
