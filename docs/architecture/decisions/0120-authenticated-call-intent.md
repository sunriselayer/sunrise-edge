# DR-0120: authenticated generic call intent

Accepted: 2026-09-07 (Asia/Singapore).

## Signed intent is not an executable transaction

`execution::call` strictly decodes and authenticates a bounded call intent,
then binds it to the exact signed publication interface. It performs no I/O
and grants no execution capability. It is not accepted by the legacy
transaction executor, node ingress, storage commit, or trusted module catalog.

The signing domain is `CallContractIntent`, fixed Ed25519, using the existing
central signature frame. The verifier receives a trusted expected chain,
protocol version and epoch; it must not derive that expectation from the
request. It rejects a different context before key/signature verification and
requires a canonical non-identity prime-order sender key. A successful witness
has private fields and immutable access only. A false signature result rejects.

Every intent field below is signed, including request ID. No relay may change
the replay key, substitute a target, reorder accesses or attach unsigned
resource/fee authority. Nonce and request ID are authenticated values, not
evidence of freshness. Durable replay reconciliation remains separate.

## Exact wire frames

All new frames use CanonicalStruct version 1, little-endian integers, exact
required fields, fixed raw array lengths, and rejection of unknown fields,
versions, malformed nested values and trailing bytes.

| Frame | Ordered fields |
| --- | --- |
| `0x5204` concrete type arguments | 1: u16 count; 2 onward: existing `0x5202` argument frames |
| `0x6401` instance target | 1: creator bytes32; 2: seed bytes32; 3: nonzero u64 authorization revision; 4: canonical Digest32 record commitment |
| `0x6402` call intent | 1: context (`0x6301`); 2: request ID bytes32; 3: sender bytes32; 4: nonce u64; 5: exact code reference (`0x6302`); 6: instance target; 7: entrypoint UTF-8; 8: concrete type arguments; 9: existing ordered AccessManifest; 10: argument bytes; 11: nonzero gas-limit u64 |
| `0x6403` signed intent | 1: call intent; 2: Ed25519 signature bytes64 |

The existing `UnverifiedDependencyRef`/`0x6302` representation already names
an exact package origin, code revision, original publication context and
artifact digest. Calls reuse it as a reference to their root code, not as an
object reference or legacy ModuleId. The artifact commitment transitively
binds WASM, ABI, semantics and exact dependency references. Code's original
protocol/epoch may differ from the current call context; chain must agree.

Instance logical identity is `(chain, creator, creation seed)`, distinct from
package lineage and object identity. Its authorization revision and record
digest are pinned by the caller, not silently resolved to latest. Digest
algorithm rotation does not redefine logical identity. These fields are only
an unverified target: they neither allocate an instance nor authenticate its
creator, record, active code revision, or capabilities. Future durable instance
records must retain their commitment's original context, enforce authenticated
creation and absence atomically, and match every asserted target component.
No second type namespace or shared mutable storage root is introduced.

## Bounds and binding

The outer intent is capped at 128 KiB before decode; the signed wrapper is
capped at 128 KiB + 128 bytes. Instance target frames are capped at 256 bytes.
Arguments are capped at 64 KiB before copying. Entrypoints are nonempty,
at most 64 UTF-8 bytes, and not `memory`. Access preserves signed order, is
limited to 32 entries and rejects duplicate ObjectIds even if versions differ.

The type argument forest allows eight roots and shares a 64-node/32-KiB
budget across all roots. Each argument counts as one node, each nominal tag
also counts as one, and nominal depth starts at one with maximum four.
Every nested nominal origin must name the call chain. The forest reuses the
existing argument and tag encodings without inventing a synthetic nominal
root. Standalone lists do not relax bound-signature substitution limits.

After signature authentication, `bind_authenticated_call` requires exact
origin, revision, original context and full artifact digest equality with the
verified candidate interface. It substitutes the signed type arguments,
decodes arguments with that interface's signed layout, and checks exact
access count/modes. A different layout, candidate, copied ABI, or entrypoint
cannot replace the signed target. Successful structural binding still does
not establish durable publication, owner authorization, instance scope,
defining-code rights, or authenticated object state.

This intent profile deliberately authorizes **no fees**. It cannot be admitted
as a fee-paying transaction. A fee-bearing signed profile must explicitly bind
fee consent and committed settlement policy; unsigned fee additions or silent
conversion from this signature are forbidden. Replacing an unreleased intent
profile must not introduce a live compatibility fallback.

## Integration obligations and evidence

Before public execution: reconcile durable replay before code/policy/object
I/O; resolve committed publication and dependency records; authenticate exact
instance/revision and owner/type capabilities; enforce committed resources and
fee consent; and atomically commit all read assertions, effects, nonce,
receipt and outbox under fencing. No such consumer is activated by this record.

Existing Transaction/Object/receipt/nonce/submit bytes and legacy execution
remain unchanged. Rust tests cover strict decoding, forged signatures and
targets, signed-field mutation, ABI binding, and shared type forest budgets.
`scripts/call-intent-vectors.mjs` independently reconstructs the new frames and
Ed25519 signature using Node's crypto implementation; the same fixed digests
and signature are pinned in Rust tests and the script runs in check-all.
