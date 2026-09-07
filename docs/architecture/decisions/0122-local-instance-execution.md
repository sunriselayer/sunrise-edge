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

### Canonical frames

All integers are little-endian. Decoders reject unknown fields/versions,
trailing bytes and unsupported closed values; no omitted-field defaults apply.

| Frame | Ordered fields |
| --- | --- |
| `0x5406/v1` executable ABI | 1: existing CallAbi; 2: initializer UTF-8 (empty means none); 3: u16 count followed by sorted u16 transferable constructor IDs |
| `0x630A/v2` publication policy | Original v1 fields 1–5 with executable semantics; 6: u32 profile 2; separate `v2/policies/` key |
| `0x630B/v2` executable semantics | 1: `local-devnet-typed-host-execution`; 2: profile 2; 3: rules 1; 4: `wasmi-1.1.0`; 5: fuel model 1; 6–8: stack initial/max bytes and recursion bound; 9: typed host ABI 1; 10: aggregate memory bytes |
| `0x6404/v1` instance | 1: original PublicationContext; 2: creator bytes32; 3: seed bytes32; 4: exact code reference; 5: authorization revision 1; 6: initializer |
| `0x6405/v1` execution intent | 1: mode u16 (Instantiate 1, Call 2); 2: execution-policy Digest32; 3: existing CallIntent |
| `0x6406/v1` signed execution | 1: execution intent; 2: Ed25519 signature bytes64 |
| `0x6407/v1` object authority | 1: object ID bytes32; 2: original instance context; 3: exact InstanceTarget; 4: exact defining code; 5: canonical ScopedTypeTag |
| `0x6408/v1` result | 1: request ID bytes32; 2: instance record; 3: executed mode; 4: existing ExecutionEffects |
| `0x6409/v1` execution policy | 1: context; 2: profile 2; 3: zero-fee mode 0; 4–14: bounds/rules below; 15: complete executable-semantics frame; 16: library-binding fuel charge |
| `0x640A/v1` creation derivation | 1: call context; 2: original instance context; 3: exact InstanceTarget; 4: defining code; 5: signed event Digest32; 6: global u32 creation ordinal |

Execution-policy fields 4–14 respectively bind gas 1,000,000; frame depth 8;
total calls 64; aggregate memory 64 MiB; encoded output 16 MiB; creations 128;
handles 256; base host gas 10; per-byte host gas 1; rules version 1; events 1024.
Library view/binding costs an additional fixed 2048 fuel per call over an
already verified, at-most-33-node closure. Code/layout storage is immutable and
shared: re-rooting a library view does not copy WASM or revalidate the graph.
Wasmi stack configuration is 128 initial bytes, 8192 maximum bytes and recursion
128; these are not value-slot counts. Host-nested frame depth is separately
bounded. The sole encoded failure reason is `local contract trapped`.

Instance records hash under their original Object context; execution policy
under ProtocolConfig; complete signed requests under NodeEvent. Creation hashes
its typed frame under the current Object context. Central framing retains chain,
protocol and hash-suite separation. Existing Object/Transaction/receipt codecs
are reused without changing their canonical bytes.

`scripts/local-execution-vectors.mjs` reconstructs these bytes independently of
Rust, including both success/rejection results, signing bytes and creation ID.
Rust pins the same lengths, hashes and Ed25519 signature. Encoding tests are not
evidence of durable admission or execution of the vector's unverified code ref.

## Instances do not introduce a shared mutable storage root

Logical identity is `(chain, creator, creation seed)`, independent of hash-suite
rotation, protocol version and code revision. The immutable instance record
binds its original verification context, exact published code and designated
initializer. Creation requires the authenticated sender to be the creator and
requires true absence, not a live row or a tombstone. Ordinary calls pin the
exact record digest and authorization revision. They do not update that record;
application state remains separately declared object heads.

Fresh execution requires the instance and complete code closure to use the
active protocol version. Earlier epochs within that trusted resolver remain
valid. Historical protocol-version records can still be verified and queried,
and exact receipts replay before this admission check; executing them under a
different protocol version requires a separate explicit migration capability.

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
Cumulative handle allocation includes root selectors, child aliases and created
handles; consumption and frame return do not refund the 256-handle budget.
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
