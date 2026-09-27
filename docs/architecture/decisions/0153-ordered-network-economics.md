# DR-0153: Ordered network economics

## Status

Accepted implementation direction, 2026-09-27. Implementation and verification
status belong in `TODO.md`. This decision does not authorize public ingress,
network activation, deployment or real custody.

## Context

DR-0151 delivery 2 joins the existing bond, evidence, slashing and fee-claim
state machines to an independently authenticated network. Their local row,
object and nonce CAS assertions do not decide the order across validator
stores. A claim against a shared escrow cannot safely reuse the owned-object
FastVote lifecycle as though the escrow belonged to one claimant.

One rejected alternative was a single quorum vote per resource generation,
covering its previous and next digests. Those digests bind a transition, but
do not recover a fragmented vote between competing legitimate claimants.
Derive, collect one quorum and apply are three workflow steps, not three
consensus voting phases. Permanent generation locks would introduce a shared
resource liveness failure, rather than implement the required ordered path.

## Decision

### Reuse the shared consensus engine

Use the existing epoch-scoped `consensus::ChainedHotStuff` for economic
operations only. Keep ordinary paid Publish, Instantiate and Call on their
owned-object FastVote path. Neither a relay nor the order of client HTTP
requests becomes a sequencer or an authority.

The closed first profile uses the existing genesis consensus parameters and
an anchor derived canonically from the independently pinned signed genesis,
logical domain and epoch/set identity. It supports the existing fee-claim,
bond lifecycle, evidence admission and evidence-driven slash envelopes. It
does not reinterpret bond amount as voting power or introduce an asset ID,
Coin body decoder or Standard Asset-specific admission branch.

Keep the existing signed intent/proposal/vote/certificate bytes unchanged.
New persistence/transport frames get distinct, searched-for identifiers,
closed tags, explicit context, strict canonical decoders and bounded vectors.

### Closed three-chain scheduling profile

Each proposal contains at most one economic operation. Heights congruent to
1 modulo 3 may carry that operation or be empty; the other two heights are
empty descendants. This bounded profile makes one coherent economic commit
per three-chain window possible without speculative application of several
dependent signed claims. Empty proposals still require the selected leader's
signature and a real quorum; they do not manufacture finality.

Persist the complete consensus state, vote/leader-proposal identity and exact
candidate bytes before returning signed messages. Restart must preserve the
last vote, high/locked certificates and all retained safety information. A
failed or ambiguous commit must not expose a new signed vote. An externally
delivered tick may advance the pacemaker only according to trusted clock and
the existing engine rules; it cannot authorize a proposal, quorum or mutation.
Progress depends on eligible leaders, quorum availability and request/event
delivery, not on a permanent daemon or background scheduler in protocol core.

### Shared ordering and owned reservations are different

Do not reserve an escrow/bond generation or protocol-custody object permanently
for the first proposal. Those mutations occur only in the ordered execution
path. Competing claimants must remain orderable through normal consensus view
and branch selection, including empty progress proposals.

Economic legs can also consume address-owned input objects and sender nonces.
Admission reserves precisely those inputs using the same durable lock keys
as FastVote, atomically with its candidate/vote record. This prevents a fast
transaction from racing an ordered leg. It does not lock unrelated objects or
put all user calls through global consensus. Only the original admitted
request may use or release its reservation, or the separately authorized
epoch transition may make an old-epoch lock stale. Abandoned address-owned
reservations retain the existing self-wedge limitation; they must not wedge
another claimant's shared escrow. There is no timeout-based safety unlock.

### One atomic business/order commit

Execute the exact authenticated operation only after the shared engine emits
its committed block, against the already-applied shared prefix. Reuse the
existing generic public-contract execution, custody postconditions, historical
eligibility and value-conservation checks. A private staging-store adapter
captures the existing handler's transaction without publishing it. Combine
that transaction with the order/consensus state, operation audit record and
required lock cleanup in one fenced durable invocation.

Neither local `StateRevision` nor writer-generation values belong in signed
network proposals: they are local CAS tokens, not protocol state digests.
The canonical candidate binds the exact operation envelope, kind, context,
request identity and creation-checkpoint operand. That operand is a committed
execution input, not proof that a checkpoint or state root was published.

A stale or semantically refused ordered candidate receives a deterministic
retained rejection with no application/custody movement and no sender-nonce
advancement. Storage unavailability, corrupt/missing prerequisites, fencing
or indeterminate commit are not semantic rejection evidence. They stop the
local apply and require reconciliation/catch-up; never advance the applied
prefix past an operation whose outcome is unknown.

Keep the original shared request-id namespace. Exact replay reconciles its
retained candidate/order/receipt before fresh policy, code, object or nonce
reads. Different bytes, kinds or checkpoint operands under an existing
request ID fail closed without changing receipts or state.

### Network surface and recovery

Mount only explicit ordered proposal/certificate/query routes alongside the
certified-only FastVote surface. Never add a direct economics mutation
fallback or enable the generic event/legacy paid mutation routers.
Authenticate canonical messages and embedded intents against independently
pinned authority before clock, identity allocation or runtime I/O.

The SDK/CLI drives selected leaders, verifies votes and forms real certificates
against the local genesis pin, synchronizes exact artifacts before sending,
reserves outputs before mutation and reports each replica separately. TLS
endpoint validation is separate from protocol-context validation. A returned
unsigned HTTP acknowledgement alone is not network finality or durability.

Recovery replays declared exact authenticated proposals/certificates and their
candidate bytes in dependency order without signing or voting. It must retain
and independently verify the economic prefix and original receipts, including
after process/store close and reopen. Missing fast-path prerequisites require
their own certified recovery; no opaque state import or invented success is
allowed. This is declared catch-up, not completeness/state-root proof or
permission for a new validator to join.

## Acceptance boundaries

Exercise real independent validator stores and compiled CLI operations for
claims, bonds, all evidence families and slash, conflicting claims, quorum
loss/leader changes, forged or reordered artifacts, same-boot/restart replay,
missed-prepare recovery, owned-path conflicts, writer fencing and commit-loss
reconciliation. Compare canonical outcomes and business state, and separately
verify the retained bond/claim histories and actual value movement.

Require parent integration review, the complete repository gate, fresh
exact-final-head Opus approval and passing required CI before a normal merge.
Independent security review and activation remain separate gates. Delivery 3
still owns membership/epoch activation and verified complete state handoff;
this fixed-epoch implementation must not claim those features complete.

## Primary reference

The existing engine's chained voting/locking/commit model is grounded in
[HotStuff: BFT Consensus in the Lens of Blockchain](https://arxiv.org/abs/1803.05069),
especially its distinction between a quorum certificate and three-chain
commit. This decision composes that engine; it does not invent a one-phase
replacement or claim an independent consensus security audit.
