# DR-0292: Original bond trusted local currentness

Date: 2026-11-10 (Asia/Singapore)

Status: Selected trust boundary; opt-in local observation transport implemented;
approver and signing enforcement pending.

## Context

[DR-0289] and [DR-0291] select the original-genesis bond operation, separate
inner and outer content approvers, and protected key workers. Its source Coin
remains a caller snapshot. Matching a public query response byte for byte does
not establish the chain's current state.

## Decision

For the initial original-bond release, trust one designated local original
`sqlite_source_host` as the source of a **same-process observation at a local
token**. The designated node identity, chain, domain, validator, and genesis
digest must be pinned outside an untrusted request. This is a local-node trust
choice, not a chain-state proof: report `chain_state_proof=false`.

After the host's single writer-fence claim, the read-only currentness
operation uses that host's existing `Arc<SqliteDurableStore>` and original
ordered policy, never a second database opener or a startup context. For each
request it creates a fresh context at the claimed fence. It brackets all
deciding reads with `read_stable_advisory`, requiring equal full portable
tokens (namespace, domain, writer fence, mutation sequence). It reads the
committed epoch record with `query_committed_epoch_state`, requiring epoch
zero and the expected validator-set digest. Under the same token it reuses
the original host's active validator-set, root, fee, and committee checks
rather than relying only on startup validation. It reads the locally
advertised applied committed tip through `query_ordered_history_summary`
and the exact source Coin through `query_object`. Only a current inline
object whose ID, version, digest, creating chain ID and protocol version,
and canonical body match the reviewed Coin may be reported. Missing,
tombstoned, blob-only, malformed, changed-fence, and
changed-token observations refuse. The ordered tip is local progress, not
proof that the node has the network's latest head.

The resulting token is a locator for subsequent independent rechecks, never
caller authority or a mutation fence. A later write can race signature
creation or delivery. This boundary makes no atomic-currentness claim at
signature delivery or execution; the ordered handler's own source/effects
checks remain separate.

Both content approvers, the broker, and the relevant key worker must
independently requery the pinned node at their approval, signing, or
signature-release points. The observation is bound to the existing typed
approval content and carried from the inner request into the outer request.
A changed observation or restarted node refuses and requires new approval;
the protocol signing frames remain unchanged.

## Implementation boundary

The opt-in `--bond-currentness-config` private file selects one socket path,
one to eight distinct allowed peer UIDs different from the host UID, connection and request caps,
and a total deadline. The original host binds the socket after its one fence
claim and before readiness. It authenticates the Unix peer before reading a
bounded request, performs one read-only query at a time, joins any in-flight
query at stop, and removes its exact owned socket before the host terminal
record. The response carries the full local token, applied ordered tip, exact
Coin reference and `chain_state_proof=false`. Exhaustion or listener failure
stops the host rather than silently continuing HTTP service.

The existing loopback HTTP route and outbound diagnostics socket are not this
admission boundary. There is no bond CLI, broker, content-approver or protected
key-worker connection to the listener yet. The present bond preview and
protected signing fixture therefore retain their unverified-source status.
This record does not approve, sign, register, or execute a bond and closes no
M2 or release requirement. Actual node/approver enrollment, real keys, host
users, and security policy are outside this decision.

[DR-0289]: 0289-bond-outer-key-custody-and-split-approval.md
[DR-0291]: 0291-original-bond-inner-standard-asset-profile.md
