# DR-0122: local independent instances and typed execution

Decision: 2026-09-07 (Asia/Singapore).

This defines the local execution composition, not network admission or
completion of the generic-contract gate. Implementation status and verification
evidence belong in [`TODO.md`](../../../TODO.md).

## Explicit executable authority

The non-executing publication profile in [DR-0121](0121-durable-local-code-publication.md)
does not become executable by reinterpretation. A separate, explicitly installed
publication policy admits typed-host profile 2. Its semantics commitment binds
the supported engine/fuel version, host ABI/rules and fixed stack limits. An
engine upgrade changes protocol semantics, even when WASM source is unchanged.
Historical profile-1 bytes and policies keep their original interpretation.

The executable ABI is a distinct `0x5406/v1` wrapper over the existing CallAbi,
an optional exact initializer and a sorted unique list of locally defined
transferable constructors. The complete wrapper, including overhead, must fit
64 KiB; a maximal inner CallAbi cannot additionally consume that overhead.
Initializers use the existing bounded call-entrypoint name rules, require no
input objects/type arguments, and cannot be entered through ordinary or nested
calls. A library can declare no initializer. The transferable list is bounded
at 64 and cannot name another package's constructor.

`ExecuteLocalContract` authenticates the exact call sender, request ID, nonce,
mode, chain/protocol/epoch, exact code/instance target, ordered access, arguments,
gas limit and committed local execution-policy digest. The policy explicitly
authorizes zero fees with fixed resource bounds. Older `CallContractIntent`
signatures remain nonadmissible; no unsigned fee consent is inferred or added.
The locally configured expected context is authoritative, not a request or HTTP
response. The signature key equals the call sender and every frame's caller.

## Instances do not introduce a shared mutable storage root

Logical identity is `(chain, creator, creation seed)`, independent of hash-suite
rotation, protocol version and code revision. The immutable instance record
binds its original verification context, exact published code and designated
initializer. Creation requires the authenticated sender to be the creator and
requires true absence, not a live row or a tombstone. Ordinary calls pin the
exact record digest and authorization revision. They do not update that record;
application state remains separately declared object heads.

Every public object has a host-stamped immutable authority sidecar binding its
object ID, exact instance/context, exact defining code and canonical scoped
nominal type. The instance is an isolation boundary, not a second type
namespace. Creating, mutating or consuming internal state requires defining-code
authority in addition to instance, owner and declared-handle rights. Possession
of bytes or an owner's signature cannot grant arbitrary code those rights.

The instance and sidecar namespaces `se/instances/` and `se/object-authority/`
are reserved against generic state plans, including their mutations. The legacy
`env` path cannot mutate, transfer or consume a sidecar-governed object. Any
permitted legacy sidecar-absence observation must be part of its atomic read
assertions. The public path rejects objects without exact live-head and sidecar
provenance. Neither path can downgrade an object by ignoring authority metadata.

Public creation IDs use a distinct typed canonical derivation containing the
signed event digest, exact instance/context, defining code and global creation
ordinal, hashed through the central resolver. They do not reuse the legacy raw
SHA-256 helper. This is cryptographic domain separation, not a claim that hash
collisions are mathematically impossible. Ordinals include intermediate objects
created then consumed: surviving outputs must retain their original ordinal.
Creation rejects collisions with any existing head or authority row, including
tombstones. Consumed authority rows remain immutable provenance; a tombstoned
head can never be resolved as a live handle or resurrected from its sidecar.

## Typed host and library call boundary

Profile 2 imports only the exact `sunrise` ABI. It does not expose legacy `env`
operations accepting arbitrary type hashes, schema versions or privileged owner
kinds. This profile rejects Shared, System and Immutable inputs; initial owners
and transfer recipients are canonical prime-order Ed25519 addresses.

The host owns a bounded invocation arena and frame-local handle tables.
Canonical tags and bodies are checked against the executing code's signed
constructors/layouts, not caller-supplied layouts. Transfer requires an owned
Write/Consume-capable handle in the exact instance, defining-code authority and
the signed transferable declaration. It permanently downgrades all aliases to
Read for the invocation, including self-transfer. Consumption invalidates every
alias. A newly created sender-owned object receives Consume-capable rights;
creation for another owner returns only a read handle.

A nested call selects a direct, exactly published dependency and its typed ABI.
It receives only a unique subset of the parent frame's handles, with no rights
escalation, and executes in the **same root instance** while retaining its own
defining-code authority. Calls are effectful and void: they do not return values
or newly created handles. `get_caller` returns the transaction sender, not the
calling package; libraries cannot use it to authenticate their calling code.
`get_instance` returns the complete canonical immutable instance record.

This is library composition, not entry into another independent instance.
Cross-instance calls require a separate exact signed target/revision and bounded
delegated authority. A dependency declaration or same-typed handle cannot imply
that authorization. Standard Asset interoperability must not silently treat the
library-only boundary as the missing cross-instance capability.

One Store, global fuel counter and arena cover the entire invocation. Fresh
module instances for nested calls cannot preserve guest memory/globals across
calls. Aggregate memory allocation remains charged for the Store lifetime,
including after a frame returns. Depth, call count, guest value/call stacks,
handles, creations, arguments and outputs are bounded; host copies and decoding
consume fuel. A nested trap is fatal, never an ignorable error code. Events use
canonical scoped tags and defining-code body layouts and are included in the
existing canonical ExecutionEffects committed by the receipt.

## Atomic admission and failure semantics

Authenticate first, then reconcile the signed request's exact durable receipt
before reading code, policy, instance or objects. Fresh admission reserves the
existing shared sender nonce, verifies committed policy and the complete durable
publication closure, checks instance/sidecar/object provenance, and carries all
observed revisions/heads into one fenced invocation. Final effects are checked
again before persistence; successful VM return alone is not commit authority.

Successful initialization commits the record, initial objects/sidecars, nonce
and receipt atomically. A call commits individual object changes with its nonce
and receipt; it does not serialize all state on an instance-wide write. The
outbox is explicitly absent because this local composition emits no peer event.

Pre-execution rejection and request-ID conflicts change nothing. An execution
trap discards all provisional application/instance effects and events, but
atomically records a normalized Rejected outcome and consumed nonce under the
explicit zero-fee policy. Exact replay returns the original bytes without
executing code again. Indeterminate commits require replay of identical signed
bytes, not a new request or assumed success.

Code, policy and publication receipts remain verifiable while referenced.
Retained code/receipts/consumed sidecars grow with admitted work; bounded
per-invocation execution is not a bounded total-storage claim. Archival/pruning
requires a separately specified policy and cannot silently delete provenance.

## Product and migration boundary

Local execution requires explicit devnet opt-in, including required publication
policies and matching native router/pre-parser capabilities. Default execution
routes remain closed. Rust CLI software signing verifies endpoint TLS separately
from expected protocol context and exact returned commitments; Ledger remains
unsupported before any device/network action. Canonical file exports must not
overwrite existing files. A response is checked against the signed request and
result selector/status; HTTP 200 is not proof of execution success.

The legacy trusted catalog, Standard Asset implementation and native fee
settlement are not migrated by this decision. They remain separate from public
execution, except for the mandatory isolation guard protecting public objects.
Replacing those trusted-only paths with the public facilities and explicitly
signed fee settlement is still required by [the target design](../../design.md).
This local flow does not establish asset equivalence, public testnet readiness,
permissionless network execution, distributed publication or production readiness.
